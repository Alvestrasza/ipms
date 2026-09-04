import csv
import io
import time
import uuid
from datetime import timezone as datetime_timezone

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Q
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
    HyperVVirtualMachine,
    WindowsServer,
    WindowsServerRole,
    WindowsServerTelemetry,
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
    WindowsServerDetailSerializer,
    WindowsServerSerializer,
    WindowsServerTelemetrySerializer,
    HyperVVirtualMachineSerializer,
    neutralize_public_protocol_text,
    public_bmc_family,
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


class WindowsServerListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = WindowsServerSerializer

    def get_queryset(self):
        queryset = WindowsServer.objects.filter(tenant=self.request.tenant)
        server_type = self.request.query_params.get("server_type", "")
        if server_type in WindowsServer.ServerType.values:
            queryset = queryset.filter(server_type=server_type)
        operating_system_role = self.request.query_params.get(
            "operating_system_role", ""
        )
        if operating_system_role == WindowsServer.OperatingSystemRole.SERVER:
            queryset = queryset.filter(
                operating_system_role__in=(
                    WindowsServer.OperatingSystemRole.SERVER,
                    WindowsServer.OperatingSystemRole.DOMAIN_CONTROLLER,
                )
            )
        elif operating_system_role in WindowsServer.OperatingSystemRole.values:
            queryset = queryset.filter(operating_system_role=operating_system_role)
        elif operating_system_role:
            raise ValidationError({"operating_system_role": ["invalid_role"]})
        operating_system_family = self.request.query_params.get(
            "operating_system_family", ""
        )
        if operating_system_family:
            if (
                operating_system_family != operating_system_family.strip()
                or len(operating_system_family) > 64
            ):
                raise ValidationError(
                    {"operating_system_family": ["invalid_family"]}
                )
            queryset = queryset.filter(
                operating_system_family=operating_system_family
            )
        role = self.request.query_params.get("role", "")
        if role:
            if role != role.strip() or len(role) > 255:
                raise ValidationError({"role": ["invalid_role"]})
            queryset = queryset.filter(installed_roles__name=role).distinct()
        return queryset.select_related("connector")


class WindowsServerRoleListView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)

    def get(self, request):
        rows = (
            WindowsServerRole.objects.filter(
                server__tenant=request.tenant,
                server__operating_system_role__in=(
                    WindowsServer.OperatingSystemRole.SERVER,
                    WindowsServer.OperatingSystemRole.DOMAIN_CONTROLLER,
                ),
            )
            .values("name", "display_name", "server__server_type")
            .annotate(server_count=Count("server_id", distinct=True))
            .order_by()
        )
        roles: dict[str, dict] = {}
        for row in rows:
            name = row["name"]
            role = roles.setdefault(
                name,
                {
                    "name": name,
                    "physical_count": 0,
                    "virtual_count": 0,
                    "display_names": {},
                },
            )
            server_type = row["server__server_type"]
            if server_type == WindowsServer.ServerType.PHYSICAL:
                role["physical_count"] += row["server_count"]
            elif server_type == WindowsServer.ServerType.VIRTUAL:
                role["virtual_count"] += row["server_count"]
            display_name = row["display_name"]
            role["display_names"][display_name] = (
                role["display_names"].get(display_name, 0) + row["server_count"]
            )

        response = []
        for role in roles.values():
            display_name = sorted(
                role.pop("display_names").items(),
                key=lambda item: (-item[1], item[0].casefold(), item[0]),
            )[0][0]
            response.append({**role, "display_name": display_name})
        response.sort(
            key=lambda item: (
                item["display_name"].casefold(),
                item["display_name"],
                item["name"],
            )
        )
        return Response(response)


class WindowsClientFamilyListView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)

    def get(self, request):
        rows = (
            WindowsServer.objects.filter(
                tenant=request.tenant,
                operating_system_role=WindowsServer.OperatingSystemRole.CLIENT,
            )
            .exclude(operating_system_family="")
            .values("operating_system_family", "server_type")
            .annotate(system_count=Count("id"))
            .order_by("operating_system_family", "server_type")
        )
        families: dict[str, dict] = {}
        for row in rows:
            family_name = row["operating_system_family"]
            family = families.setdefault(
                family_name,
                {
                    "name": family_name,
                    "physical_count": 0,
                    "virtual_count": 0,
                },
            )
            if row["server_type"] == WindowsServer.ServerType.PHYSICAL:
                family["physical_count"] += row["system_count"]
            elif row["server_type"] == WindowsServer.ServerType.VIRTUAL:
                family["virtual_count"] += row["system_count"]
        return Response(list(families.values()))


class HyperVVirtualMachineListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = HyperVVirtualMachineSerializer

    def get_queryset(self):
        queryset = HyperVVirtualMachine.objects.filter(
            tenant=self.request.tenant,
            host__tenant=self.request.tenant,
        )
        host = self.request.query_params.get("host", "")
        if host:
            try:
                host_id = uuid.UUID(host)
            except ValueError as exc:
                raise ValidationError({"host": ["invalid_host"]}) from exc
            queryset = queryset.filter(host_id=host_id)
        state = self.request.query_params.get("state", "")
        if state:
            if state not in HyperVVirtualMachine.State.values:
                raise ValidationError({"state": ["invalid_state"]})
            queryset = queryset.filter(state=state)
        return queryset.select_related("host")


class WindowsServerDetailView(RetrieveAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = WindowsServerDetailSerializer

    def get_queryset(self):
        return WindowsServer.objects.filter(
            tenant=self.request.tenant,
        ).select_related("connector", "latest_telemetry")


class WindowsServerTelemetryView(RetrieveAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = WindowsServerTelemetrySerializer
    lookup_field = "server_id"
    lookup_url_kwarg = "pk"

    def get_queryset(self):
        return WindowsServerTelemetry.objects.filter(
            tenant=self.request.tenant,
            server__tenant=self.request.tenant,
        ).select_related("server")


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
                "api_error_code",
                "api_message_id",
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
                    public_bmc_family(entry.bmc_family),
                    neutralize_public_protocol_text(entry.event_type),
                    entry.method,
                    neutralize_public_protocol_text(entry.resource_path),
                    entry.http_status,
                    entry.duration_ms,
                    neutralize_public_protocol_text(entry.error_code),
                    neutralize_public_protocol_text(entry.redfish_error_code),
                    neutralize_public_protocol_text(entry.redfish_message_id),
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
                    neutralize_public_protocol_text(entry.source_record_id),
                    neutralize_public_protocol_text(entry.message),
                    entry.repeat_count,
                    entry.repaired,
                    entry.event_class,
                    entry.event_code,
                    entry.event_number,
                    neutralize_public_protocol_text(entry.record_format),
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
