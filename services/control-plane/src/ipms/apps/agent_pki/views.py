import ipaddress

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, ValidationError as DjangoValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404
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
from .models import WindowsAgentDeployment
from .permissions import CanDeployAgents
from .serializers import (
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
                enrollment, bootstrap_token, _ = create_enrollment_token(
                    tenant=request.tenant,
                    display_name=data["display_name"],
                    actor=actor,
                )
                deployment = WindowsAgentDeployment.objects.create(
                    tenant=request.tenant,
                    enrollment=enrollment,
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
