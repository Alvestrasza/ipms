import ipaddress
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.certificates import (
    CertificateProbeError,
    request_bmc_certificate_probe,
    request_windows_http_probe,
)
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess

from .deployment_secrets import store_deployment_secret
from .deployment_approval import (
    WindowsDeploymentApprovalError,
    create_windows_deployment_approval,
    load_windows_deployment_approval,
)
from .lifecycle import ACTIVE_STATUSES, create_lifecycle_job
from .models import AgentEnrollment, AgentLifecycleJob, WindowsAgentDeployment
from .permissions import CanDeployAgents
from .serializers import (
    AgentLifecycleJobSerializer,
    AgentLifecycleRequestSerializer,
    WindowsAgentDeploymentPreflightSerializer,
    WindowsAgentDeploymentRequestSerializer,
    WindowsAgentDeploymentSerializer,
)
from .services import create_enrollment_token


def _actor(request) -> str:
    return request.user.get_username()[:255]


def _https_origin(address: str, port: int) -> str:
    try:
        host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    except ValueError:
        host = address
    return f"https://{host}:{port}/"


def _http_origin(address: str, port: int) -> str:
    try:
        host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    except ValueError:
        host = address
    return f"http://{host}:{port}/wsman"


class WindowsAgentDeploymentPreflightView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanDeployAgents)

    def post(self, request):
        serializer = WindowsAgentDeploymentPreflightSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        address = data["address"]
        https_port = data["https_port"]
        try:
            observation = request_bmc_certificate_probe(
                _https_origin(address, https_port),
                timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                port=settings.CERTIFICATE_PROBE_PORT,
                token=settings.CERTIFICATE_PROBE_TOKEN,
            )
        except CertificateProbeError as exc:
            fallback_errors = {
                "certificate_unavailable",
                "connection_failed",
                "connection_timeout",
            }
            if not data["allow_http_fallback"] or exc.code not in fallback_errors:
                raise PublicApiError(exc.code) from exc
            fallback_port = 5985
            try:
                request_windows_http_probe(
                    _http_origin(address, fallback_port),
                    timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                    port=settings.CERTIFICATE_PROBE_PORT,
                    token=settings.CERTIFICATE_PROBE_TOKEN,
                )
            except CertificateProbeError as fallback_exc:
                raise PublicApiError(fallback_exc.code) from fallback_exc
            approval = create_windows_deployment_approval(
                tenant_id=str(request.tenant.id),
                address=address,
                port=fallback_port,
                transport=WindowsAgentDeployment.Transport.HTTP,
            )
            return Response(
                {
                    "transport": WindowsAgentDeployment.Transport.HTTP,
                    "port": fallback_port,
                    "approval_token": approval,
                    "requires_explicit_confirmation": True,
                    "https_error_code": exc.code,
                }
            )

        approval = create_windows_deployment_approval(
            tenant_id=str(request.tenant.id),
            address=address,
            port=https_port,
            transport=WindowsAgentDeployment.Transport.HTTPS,
            fingerprint_sha256=observation.fingerprint_sha256,
            trusted_by_system=observation.trusted_by_system,
        )
        return Response(
            {
                "transport": WindowsAgentDeployment.Transport.HTTPS,
                "port": https_port,
                "approval_token": approval,
                "requires_explicit_confirmation": True,
                "requires_explicit_trust": not observation.trusted_by_system,
                "certificate": observation.public_document(),
            }
        )


class WindowsAgentDeploymentListCreateView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanDeployAgents)

    def get(self, request):
        deployments = WindowsAgentDeployment.objects.filter(
            tenant=request.tenant,
        )[:50]
        return Response(WindowsAgentDeploymentSerializer(deployments, many=True).data)

    def post(self, request):
        serializer = WindowsAgentDeploymentRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            approval = load_windows_deployment_approval(data["approval_token"])
        except WindowsDeploymentApprovalError as exc:
            raise PublicApiError(str(exc)) from exc
        if (
            approval.get("tenant_id") != str(request.tenant.id)
            or approval.get("address") != data["address"]
            or approval.get("port") != data["port"]
            or approval.get("transport") != data["transport"]
        ):
            raise PublicApiError("windows_deployment_approval_scope_mismatch")
        if not data["confirm_connection"]:
            raise PublicApiError("windows_deployment_confirmation_required")

        fingerprint = ""
        trust_mode = WindowsAgentDeployment.CertificateTrustMode.NONE
        if data["transport"] == WindowsAgentDeployment.Transport.HTTPS:
            try:
                observation = request_bmc_certificate_probe(
                    _https_origin(data["address"], data["port"]),
                    timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                    port=settings.CERTIFICATE_PROBE_PORT,
                    token=settings.CERTIFICATE_PROBE_TOKEN,
                )
            except CertificateProbeError as exc:
                raise PublicApiError(exc.code) from exc
            fingerprint = str(approval.get("fingerprint_sha256", ""))
            if observation.fingerprint_sha256 != fingerprint:
                raise PublicApiError("windows_certificate_changed")
            trusted_by_system = bool(approval.get("trusted_by_system"))
            if trusted_by_system and not observation.trusted_by_system:
                raise PublicApiError("windows_certificate_trust_changed")
            trust_mode = (
                WindowsAgentDeployment.CertificateTrustMode.SYSTEM
                if trusted_by_system
                else WindowsAgentDeployment.CertificateTrustMode.PINNED
            )
        else:
            try:
                request_windows_http_probe(
                    _http_origin(data["address"], data["port"]),
                    timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                    port=settings.CERTIFICATE_PROBE_PORT,
                    token=settings.CERTIFICATE_PROBE_TOKEN,
                )
            except CertificateProbeError as exc:
                raise PublicApiError(exc.code) from exc
        if WindowsAgentDeployment.objects.filter(
            tenant=request.tenant,
            target_address=data["address"],
            target_port=data["port"],
            status__in=(
                WindowsAgentDeployment.Status.QUEUED,
                WindowsAgentDeployment.Status.RUNNING,
            ),
        ).exists():
            raise PublicApiError("deployment_already_pending")

        actor = _actor(request)
        try:
            with transaction.atomic():
                lifecycle_bootstrap_enrollment = None
                existing_enrollment_id = data.get("existing_enrollment_id")
                if existing_enrollment_id is not None:
                    lifecycle_bootstrap_enrollment = get_object_or_404(
                        AgentEnrollment.objects.select_for_update(),
                        id=existing_enrollment_id,
                        tenant=request.tenant,
                        status=AgentEnrollment.Status.ACTIVE,
                    )
                    from ipms.apps.discovery.models import WindowsServer

                    existing_server = WindowsServer.objects.filter(
                        tenant=request.tenant,
                        inventory_source=WindowsServer.InventorySource.AGENT,
                        source_id=lifecycle_bootstrap_enrollment.device_uri,
                    ).first()
                    existing_version = _version_tuple(
                        existing_server.agent_version if existing_server else ""
                    )
                    if existing_version is not None and existing_version >= (0, 1, 32):
                        raise PublicApiError("agent_lifecycle_bootstrap_not_required")
                    if AgentLifecycleJob.objects.filter(
                        enrollment=lifecycle_bootstrap_enrollment,
                        status__in=ACTIVE_STATUSES,
                    ).exists():
                        raise PublicApiError("agent_lifecycle_job_rejected")
                    if WindowsAgentDeployment.objects.filter(
                        lifecycle_bootstrap_enrollment=(
                            lifecycle_bootstrap_enrollment
                        ),
                        status__in=(
                            WindowsAgentDeployment.Status.QUEUED,
                            WindowsAgentDeployment.Status.RUNNING,
                        ),
                    ).exists():
                        raise PublicApiError("deployment_already_pending")
                enrollment, bootstrap_token, _ = create_enrollment_token(
                    tenant=request.tenant,
                    display_name=data["display_name"],
                    actor=actor,
                )
                deployment = WindowsAgentDeployment.objects.create(
                    tenant=request.tenant,
                    enrollment=enrollment,
                    lifecycle_bootstrap_enrollment=lifecycle_bootstrap_enrollment,
                    display_name=data["display_name"],
                    target_address=data["address"],
                    target_port=data["port"],
                    transport=data["transport"],
                    certificate_trust_mode=trust_mode,
                    requested_by=actor,
                    certificate_fingerprint_sha256=fingerprint,
                )
                store_deployment_secret(
                    deployment,
                    username=data["username"],
                    password=data["password"],
                    bootstrap_token=bootstrap_token,
                )
                AuditEvent.objects.create(
                    tenant=request.tenant,
                    actor=actor,
                    action="agent.windows_deployment.queue",
                    object_type="windows_agent_deployment",
                    object_id=str(deployment.id),
                    outcome=AuditEvent.Outcome.SUCCEEDED,
                    details={
                        "target_address": data["address"],
                        "target_port": data["port"],
                        "transport": data["transport"],
                        "certificate_trust_mode": trust_mode,
                        "administrator_confirmed": True,
                        "lifecycle_bootstrap": lifecycle_bootstrap_enrollment
                        is not None,
                    },
                )
        except (DjangoValidationError, ObjectDoesNotExist) as exc:
            raise PublicApiError("agent_pki_unavailable") from exc
        return Response(
            WindowsAgentDeploymentSerializer(deployment).data,
            status=status.HTTP_201_CREATED,
        )


class WindowsAgentDeploymentDetailView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanDeployAgents)

    def get(self, request, pk):
        deployment = get_object_or_404(
            WindowsAgentDeployment,
            id=pk,
            tenant=request.tenant,
        )
        return Response(WindowsAgentDeploymentSerializer(deployment).data)


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


class AgentAdministrationListView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanDeployAgents)

    def get(self, request):
        from ipms.apps.discovery.models import WindowsServer

        servers = {
            server.source_id: server
            for server in WindowsServer.objects.filter(
                tenant=request.tenant,
                inventory_source=WindowsServer.InventorySource.AGENT,
            )
        }
        target_version = settings.AGENT_WINDOWS_VERSION
        target_tuple = _version_tuple(target_version)
        now = timezone.now()
        enrollments = AgentEnrollment.objects.filter(
            tenant=request.tenant,
        ).prefetch_related(
            Prefetch(
                "lifecycle_jobs",
                queryset=AgentLifecycleJob.objects.filter(status__in=ACTIVE_STATUSES),
                to_attr="active_lifecycle_jobs",
            )
        )
        documents = []
        for enrollment in enrollments:
            server = servers.get(enrollment.device_uri)
            last_seen = server.last_seen_at if server else enrollment.last_seen_at
            if enrollment.status == AgentEnrollment.Status.REVOKED:
                state = "revoked"
            elif last_seen is None:
                state = "not-seen"
            elif last_seen >= now - timedelta(seconds=45):
                state = "online"
            elif last_seen >= now - timedelta(minutes=5):
                state = "stale"
            else:
                state = "offline"
            current_version = server.agent_version if server else ""
            current_tuple = _version_tuple(current_version)
            lifecycle_capable = (
                enrollment.status == AgentEnrollment.Status.ACTIVE
                and current_tuple is not None
                and current_tuple >= (0, 1, 32)
            )
            compliance = "unknown"
            if current_tuple is not None and target_tuple is not None:
                compliance = "current" if current_tuple >= target_tuple else "outdated"
            active_job = next(
                (job for job in enrollment.active_lifecycle_jobs),
                None,
            )
            documents.append(
                {
                    "enrollment_id": str(enrollment.id),
                    "device_uri": enrollment.device_uri,
                    "fqdn": (server.fqdn or server.hostname) if server else enrollment.display_name,
                    "operating_system": server.operating_system if server else "",
                    "os_version": server.os_version if server else "",
                    "agent_version": current_version,
                    "target_version": target_version,
                    "status": state,
                    "compliance": compliance,
                    "lifecycle_capable": lifecycle_capable,
                    "last_seen_at": last_seen,
                    "active_job": AgentLifecycleJobSerializer(active_job).data if active_job else None,
                }
            )
        return Response(documents)


class AgentLifecycleView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanDeployAgents)

    def post(self, request, pk):
        serializer = AgentLifecycleRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        enrollment = get_object_or_404(
            AgentEnrollment,
            id=pk,
            tenant=request.tenant,
        )
        from ipms.apps.discovery.models import WindowsServer

        server = WindowsServer.objects.filter(
            tenant=request.tenant,
            inventory_source=WindowsServer.InventorySource.AGENT,
            source_id=enrollment.device_uri,
        ).first()
        current_version = _version_tuple(server.agent_version if server else "")
        if current_version is None or current_version < (0, 1, 32):
            raise PublicApiError("agent_lifecycle_bootstrap_required")
        action = serializer.validated_data["action"]
        target_version = _version_tuple(settings.AGENT_WINDOWS_VERSION)
        if (
            action == AgentLifecycleJob.Action.UPDATE
            and target_version is not None
            and current_version >= target_version
        ):
            raise PublicApiError("agent_already_current")
        actor = _actor(request)
        try:
            with transaction.atomic():
                job = create_lifecycle_job(
                    enrollment=enrollment,
                    action=action,
                    actor=actor,
                )
                AuditEvent.objects.create(
                    tenant=request.tenant,
                    actor=actor,
                    action=f"agent.lifecycle.{action}.queue",
                    object_type="agent_lifecycle_job",
                    object_id=str(job.id),
                    outcome=AuditEvent.Outcome.SUCCEEDED,
                    details={
                        "device_uri": enrollment.device_uri,
                        "target_version": job.target_version,
                    },
                )
        except (DjangoValidationError, IntegrityError) as exc:
            raise PublicApiError("agent_lifecycle_job_rejected") from exc
        return Response(
            AgentLifecycleJobSerializer(job).data,
            status=status.HTTP_201_CREATED,
        )
