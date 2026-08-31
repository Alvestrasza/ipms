import csv
import io
import time
import uuid
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess

from .certificates import (
    CertificateProbeError,
    create_certificate_trust_token,
    load_certificate_trust_token,
    request_bmc_certificate_probe,
)
from .models import (
    BmcCommunicationLog,
    BmcEventLogEntry,
    ConnectorEndpoint,
    ConnectorSecret,
    DiscoveryJob,
    PhysicalSystem,
)
from .permissions import CanManageConnectors
from .secrets import store_connector_secret
from .serializers import (
    BmcCertificateProbeSerializer,
    BmcCommunicationLogSerializer,
    BmcEventLogEntrySerializer,
    BmcConnectorEnrollmentSerializer,
    ConnectorCredentialSerializer,
    ConnectorEndpointSerializer,
    DiscoveryJobSerializer,
    PhysicalSystemSerializer,
)


def _active_connector(request, pk):
    return get_object_or_404(
        ConnectorEndpoint,
        id=pk,
        tenant=request.tenant,
        connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
        removed_at__isnull=True,
    )


def _queue_discovery(endpoint: ConnectorEndpoint, actor: str) -> DiscoveryJob:
    active_job = DiscoveryJob.objects.filter(
        connector=endpoint,
        status__in=(DiscoveryJob.Status.QUEUED, DiscoveryJob.Status.RUNNING),
    ).first()
    if active_job:
        return active_job
    return DiscoveryJob.objects.create(
        tenant=endpoint.tenant,
        connector=endpoint,
        connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
        requested_by=actor,
    )


class ConnectorEndpointListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = ConnectorEndpointSerializer

    def get_queryset(self):
        return ConnectorEndpoint.objects.filter(
            tenant=self.request.tenant,
            removed_at__isnull=True,
        )


class BmcCertificateProbeView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    def post(self, request):
        serializer = BmcCertificateProbeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        started = time.monotonic()
        try:
            observation = request_bmc_certificate_probe(
                data["base_url"],
                timeout=settings.BMC_CONNECT_TIMEOUT_SECONDS,
                port=settings.CERTIFICATE_PROBE_PORT,
                token=settings.CERTIFICATE_PROBE_TOKEN,
            )
        except CertificateProbeError as exc:
            BmcCommunicationLog.objects.create(
                tenant=request.tenant,
                bmc_name=data["display_name"],
                bmc_family=data["bmc_family"],
                severity=BmcCommunicationLog.Severity.ERROR,
                event_type="tls.certificate_probe",
                method="TLS",
                resource_path="/",
                duration_ms=round((time.monotonic() - started) * 1000),
                error_code=exc.code,
            )
            raise ValidationError({"certificate": [exc.code]}) from exc

        BmcCommunicationLog.objects.create(
            tenant=request.tenant,
            bmc_name=data["display_name"],
            bmc_family=data["bmc_family"],
            severity=(
                BmcCommunicationLog.Severity.INFO
                if observation.trusted_by_system
                else BmcCommunicationLog.Severity.WARNING
            ),
            event_type="tls.certificate_probe",
            method="TLS",
            resource_path="/",
            duration_ms=round((time.monotonic() - started) * 1000),
        )
        token = create_certificate_trust_token(
            tenant_id=str(request.tenant.id),
            base_url=data["base_url"],
            observation=observation,
        )
        return Response(
            {
                "certificate": observation.public_document(),
                "requires_explicit_trust": not observation.trusted_by_system,
                "certificate_trust_token": token,
            }
        )


class BmcConnectorEnrollmentView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    def post(self, request):
        serializer = BmcConnectorEnrollmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            trust = load_certificate_trust_token(data["certificate_trust_token"])
        except CertificateProbeError as exc:
            raise ValidationError({"certificate_trust_token": [exc.code]}) from exc
        if (
            trust.get("tenant_id") != str(request.tenant.id)
            or trust.get("base_url") != data["base_url"]
        ):
            raise ValidationError(
                {"certificate_trust_token": ["certificate_trust_scope_mismatch"]}
            )
        if not trust.get("trusted_by_system") and not data["confirm_certificate_trust"]:
            raise ValidationError(
                {"confirm_certificate_trust": ["explicit_certificate_trust_required"]}
            )
        try:
            observation = request_bmc_certificate_probe(
                data["base_url"],
                timeout=settings.BMC_CONNECT_TIMEOUT_SECONDS,
                port=settings.CERTIFICATE_PROBE_PORT,
                token=settings.CERTIFICATE_PROBE_TOKEN,
            )
        except CertificateProbeError as exc:
            raise ValidationError({"certificate": [exc.code]}) from exc
        if observation.fingerprint_sha256 != trust.get("fingerprint_sha256"):
            raise ValidationError({"certificate": ["certificate_changed_during_enrollment"]})
        if ConnectorEndpoint.objects.filter(
            tenant=request.tenant,
            base_url=data["base_url"],
            removed_at__isnull=True,
        ).exists():
            raise ValidationError({"address": ["This BMC endpoint is already enrolled."]})

        with transaction.atomic():
            endpoint = ConnectorEndpoint.objects.create(
                tenant=request.tenant,
                connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
                bmc_family=data["bmc_family"],
                display_name=data["display_name"],
                base_url=data["base_url"],
                tls_certificate_sha256=observation.fingerprint_sha256,
            )
            store_connector_secret(
                tenant=request.tenant,
                secret_id=endpoint.credential_reference,
                username=data["username"],
                password=data["password"],
            )
            job = _queue_discovery(endpoint, request.user.get_username())
            AuditEvent.objects.create(
                tenant=request.tenant,
                actor=request.user.get_username(),
                action="connector.enroll",
                object_type="connector_endpoint",
                object_id=str(endpoint.id),
                outcome=AuditEvent.Outcome.SUCCEEDED,
                correlation_id=job.correlation_id,
                details={
                    "connector_type": endpoint.connector_type,
                    "bmc_family": endpoint.bmc_family,
                    "job_id": str(job.id),
                },
            )
        return Response(
            {
                "connector": ConnectorEndpointSerializer(endpoint).data,
                "discovery_job": DiscoveryJobSerializer(job).data,
            },
            status=status.HTTP_201_CREATED,
        )


class ConnectorCredentialView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    @transaction.atomic
    def post(self, request, pk):
        endpoint = _active_connector(request, pk)
        serializer = ConnectorCredentialSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        store_connector_secret(
            tenant=request.tenant,
            secret_id=endpoint.credential_reference,
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        endpoint.health = ConnectorEndpoint.Health.UNKNOWN
        endpoint.last_error_code = ""
        endpoint.last_error_detail = {}
        endpoint.save(
            update_fields=(
                "health",
                "last_error_code",
                "last_error_detail",
                "updated_at",
            )
        )
        job = _queue_discovery(endpoint, request.user.get_username())
        AuditEvent.objects.create(
            tenant=request.tenant,
            actor=request.user.get_username(),
            action="connector.credentials.rotate",
            object_type="connector_endpoint",
            object_id=str(endpoint.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            correlation_id=job.correlation_id,
            details={"connector_type": endpoint.connector_type, "job_id": str(job.id)},
        )
        BmcCommunicationLog.objects.create(
            tenant=request.tenant,
            connector=endpoint,
            bmc_name=endpoint.display_name,
            bmc_family=endpoint.bmc_family,
            severity=BmcCommunicationLog.Severity.INFO,
            event_type="credential.rotated",
            correlation_id=job.correlation_id,
        )
        return Response(
            {"discovery_job": DiscoveryJobSerializer(job).data},
            status=status.HTTP_202_ACCEPTED,
        )


class ConnectorDetailView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    @transaction.atomic
    def delete(self, request, pk):
        endpoint = _active_connector(request, pk)
        endpoint = ConnectorEndpoint.objects.select_for_update().get(id=endpoint.id)
        BmcCommunicationLog.objects.create(
            tenant=request.tenant,
            connector=endpoint,
            bmc_name=endpoint.display_name,
            bmc_family=endpoint.bmc_family,
            severity=BmcCommunicationLog.Severity.INFO,
            event_type="connector.removed",
        )
        ConnectorSecret.objects.filter(
            id=endpoint.credential_reference,
            tenant=request.tenant,
        ).delete()
        DiscoveryJob.objects.filter(
            connector=endpoint,
            status=DiscoveryJob.Status.QUEUED,
        ).update(
            status=DiscoveryJob.Status.FAILED,
            error_code="connector_removed",
            completed_at=timezone.now(),
        )
        endpoint.enabled = False
        endpoint.removed_at = timezone.now()
        endpoint.removed_by = request.user.get_username()
        endpoint.save(
            update_fields=("enabled", "removed_at", "removed_by", "updated_at")
        )
        AuditEvent.objects.create(
            tenant=request.tenant,
            actor=request.user.get_username(),
            action="connector.remove",
            object_type="connector_endpoint",
            object_id=str(endpoint.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            details={
                "connector_type": endpoint.connector_type,
                "credential_destroyed": True,
            },
        )
        return Response(status=status.HTTP_204_NO_CONTENT)


class ConnectorDiscoveryView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    def post(self, request, pk):
        endpoint = _active_connector(request, pk)
        if not endpoint.enabled:
            raise ValidationError({"connector": ["connector_disabled"]})
        job = _queue_discovery(endpoint, request.user.get_username())
        AuditEvent.objects.create(
            tenant=request.tenant,
            actor=request.user.get_username(),
            action="connector.discovery.queued",
            object_type="connector_endpoint",
            object_id=str(endpoint.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            correlation_id=job.correlation_id,
            details={"connector_type": endpoint.connector_type, "job_id": str(job.id)},
        )
        return Response(
            {"discovery_job": DiscoveryJobSerializer(job).data},
            status=status.HTTP_202_ACCEPTED,
        )


class PhysicalSystemListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = PhysicalSystemSerializer

    def get_queryset(self):
        return PhysicalSystem.objects.filter(
            tenant=self.request.tenant,
            connector__removed_at__isnull=True,
        )


def _filtered_bmc_logs(request):
    queryset = BmcCommunicationLog.objects.filter(tenant=request.tenant)
    severities = []
    for raw in request.query_params.getlist("severity"):
        severities.extend(value for value in raw.split(",") if value)
    allowed = {choice for choice, _ in BmcCommunicationLog.Severity.choices}
    if severities:
        if any(value not in allowed for value in severities):
            raise ValidationError({"severity": ["invalid_severity"]})
        queryset = queryset.filter(severity__in=severities)
    connector = request.query_params.get("connector", "")
    if connector:
        try:
            connector_id = uuid.UUID(connector)
        except ValueError as exc:
            raise ValidationError({"connector": ["invalid_connector"]}) from exc
        queryset = queryset.filter(connector_id=connector_id)
    for parameter, lookup in (("from", "occurred_at__gte"), ("to", "occurred_at__lte")):
        raw = request.query_params.get(parameter, "")
        if raw:
            parsed = parse_datetime(raw)
            if parsed is None:
                raise ValidationError({parameter: ["invalid_datetime"]})
            if timezone.is_naive(parsed):
                parsed = timezone.make_aware(parsed, datetime_timezone.utc)
            queryset = queryset.filter(**{lookup: parsed})
    query = request.query_params.get("q", "").strip()
    if query:
        queryset = queryset.filter(
            Q(bmc_name__icontains=query)
            | Q(event_type__icontains=query)
            | Q(resource_path__icontains=query)
            | Q(error_code__icontains=query)
            | Q(redfish_error_code__icontains=query)
            | Q(redfish_message_id__icontains=query)
        )
    return queryset


class BmcCommunicationLogListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = BmcCommunicationLogSerializer

    def get_queryset(self):
        return _filtered_bmc_logs(self.request)[:500]


def _filtered_bmc_event_logs(request):
    queryset = BmcEventLogEntry.objects.filter(tenant=request.tenant)
    severities = []
    for raw in request.query_params.getlist("severity"):
        severities.extend(value for value in raw.split(",") if value)
    allowed_severities = {choice for choice, _ in BmcEventLogEntry.Severity.choices}
    if severities:
        if any(value not in allowed_severities for value in severities):
            raise ValidationError({"severity": ["invalid_severity"]})
        queryset = queryset.filter(severity__in=severities)
    log_types = []
    for raw in request.query_params.getlist("log_type"):
        log_types.extend(value for value in raw.split(",") if value)
    allowed_log_types = {choice for choice, _ in BmcEventLogEntry.LogType.choices}
    if log_types:
        if any(value not in allowed_log_types for value in log_types):
            raise ValidationError({"log_type": ["invalid_log_type"]})
        queryset = queryset.filter(log_type__in=log_types)
    connector = request.query_params.get("connector", "")
    if connector:
        try:
            connector_id = uuid.UUID(connector)
        except ValueError as exc:
            raise ValidationError({"connector": ["invalid_connector"]}) from exc
        queryset = queryset.filter(connector_id=connector_id)
    for parameter, lookup in (
        ("from", "source_created_at__gte"),
        ("to", "source_created_at__lte"),
    ):
        raw = request.query_params.get(parameter, "")
        if raw:
            parsed = parse_datetime(raw)
            if parsed is None:
                raise ValidationError({parameter: ["invalid_datetime"]})
            if timezone.is_naive(parsed):
                parsed = timezone.make_aware(parsed, datetime_timezone.utc)
            queryset = queryset.filter(**{lookup: parsed})
    query = request.query_params.get("q", "").strip()
    if query:
        queryset = queryset.filter(
            Q(bmc_name__icontains=query)
            | Q(message__icontains=query)
            | Q(source_record_id__icontains=query)
            | Q(record_format__icontains=query)
        )
    return queryset


class BmcEventLogEntryListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = BmcEventLogEntrySerializer

    def get_queryset(self):
        return _filtered_bmc_event_logs(self.request)[:500]


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    return f"'{text}" if text.startswith(("=", "+", "-", "@")) else text


class BmcCommunicationLogExportView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)

    def get(self, request):
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(
            (
                "occurred_at",
                "severity",
                "bmc",
                "bmc_family",
                "event_type",
                "method",
                "resource_path",
                "http_status",
                "duration_ms",
                "error_code",
                "redfish_error_code",
                "redfish_message_id",
                "correlation_id",
            )
        )
        for entry in _filtered_bmc_logs(request)[:10000]:
            writer.writerow(
                _csv_safe(value)
                for value in (
                    entry.occurred_at.isoformat(),
                    entry.severity,
                    entry.bmc_name,
                    entry.bmc_family,
                    entry.event_type,
                    entry.method,
                    entry.resource_path,
                    entry.http_status,
                    entry.duration_ms,
                    entry.error_code,
                    entry.redfish_error_code,
                    entry.redfish_message_id,
                    entry.correlation_id,
                )
            )
        response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = 'attachment; filename="ipms-bmc-logs.csv"'
        response["Cache-Control"] = "private, no-store"
        return response


class BmcEventLogEntryExportView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)

    def get(self, request):
        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow(
            (
                "source_created_at",
                "severity",
                "bmc",
                "log_type",
                "source_record_id",
                "message",
                "repeat_count",
                "repaired",
                "event_class",
                "event_code",
                "event_number",
                "record_format",
            )
        )
        for entry in _filtered_bmc_event_logs(request)[:10000]:
            writer.writerow(
                _csv_safe(value)
                for value in (
                    entry.source_created_at.isoformat()
                    if entry.source_created_at
                    else "",
                    entry.severity,
                    entry.bmc_name,
                    entry.log_type,
                    entry.source_record_id,
                    entry.message,
                    entry.repeat_count,
                    entry.repaired,
                    entry.event_class,
                    entry.event_code,
                    entry.event_number,
                    entry.record_format,
                )
            )
        response = HttpResponse(output.getvalue(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = (
            'attachment; filename="ipms-bmc-event-logs.csv"'
        )
        response["Cache-Control"] = "private, no-store"
        return response


class DiscoveryJobListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = DiscoveryJobSerializer

    def get_queryset(self):
        return DiscoveryJob.objects.filter(tenant=self.request.tenant)


class DiscoveryJobDetailView(RetrieveAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = DiscoveryJobSerializer

    def get_queryset(self):
        return DiscoveryJob.objects.filter(tenant=self.request.tenant)
