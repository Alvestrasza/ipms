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
)
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess

from .deployment_secrets import store_deployment_secret
from .models import WindowsAgentDeployment
from .permissions import CanDeployAgents
from .serializers import (
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
        base_url = _https_origin(data["address"], data["port"])
        try:
            observation = request_bmc_certificate_probe(
                base_url,
                timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                port=settings.CERTIFICATE_PROBE_PORT,
                token=settings.CERTIFICATE_PROBE_TOKEN,
            )
        except CertificateProbeError as exc:
            raise PublicApiError(exc.code) from exc
        if not observation.trusted_by_system:
            raise PublicApiError("windows_certificate_untrusted")
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
                    requested_by=actor,
                    certificate_fingerprint_sha256=(
                        observation.fingerprint_sha256
                    ),
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
