# File Name: platform_views.py
# Version: v0.2.76 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Platform tenant metadata administration without customer operational access.
"""Platform metadata administration without customer operational access."""

from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.audit.models import AuditEvent
from ipms.apps.agent_pki.models import AgentPkiPolicy, AgentPkiRecoveryMaterial
from ipms.apps.agent_pki.onboarding import (
    tenant_agent_onboarding_status,
    verify_gateway_isolation,
)
from ipms.apps.agent_pki.services import (
    confirm_managed_pki_recovery,
    download_managed_pki_recovery,
    prepare_managed_pki,
)
from ipms.apps.core.exceptions import PublicApiError
from .models import Tenant, TenantMembership
from .identity import create_local_user
from .permissions import IsPlatformAdministrator
from .serializers import (
    InitialTenantAdministratorSerializer,
    AgentPkiInitializeSerializer,
    AgentPkiRecoveryConfirmSerializer,
    PlatformTenantCreateSerializer,
    PlatformTenantUpdateSerializer,
)


def independent_administrator_history(tenant):
    return TenantMembership.objects.filter(
        tenant=tenant,
        role=TenantMembership.Role.TENANT_ADMIN,
        user__is_staff=False,
        user__is_superuser=False,
        user__ipms_platform_administrator__isnull=True,
    ).exists()


def platform_tenant_payload(tenant):
    return {
        "id": str(tenant.id),
        "slug": tenant.slug,
        "display_name": tenant.display_name,
        "purpose": tenant.purpose,
        "status": tenant.status,
        "created_at": tenant.created_at.isoformat(),
        "updated_at": tenant.updated_at.isoformat(),
        "needs_administrator": tenant.initial_administrator_created_at is None
        and not independent_administrator_history(tenant),
    }


def audit_platform(request, tenant, action, **details):
    AuditEvent.objects.create(
        tenant=tenant,
        actor=request.user.get_username(),
        action=f"platform.tenant.{action}",
        object_type="tenant",
        object_id=str(tenant.id),
        outcome=AuditEvent.Outcome.SUCCEEDED,
        correlation_id=getattr(request, "correlation_id", None),
        details={"actor_user_id": str(request.user.pk), **details},
    )


@method_decorator(sensitive_post_parameters(), name="dispatch")
class PlatformTenantView(APIView):
    permission_classes = (IsAuthenticated, IsPlatformAdministrator)


class PlatformTenantListCreateView(PlatformTenantView):
    def get(self, request):
        return Response(
            {
                "results": [
                    platform_tenant_payload(tenant) for tenant in Tenant.objects.all()
                ]
            }
        )

    def post(self, request):
        serializer = PlatformTenantCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            with transaction.atomic():
                if Tenant.objects.filter(slug__iexact=data["slug"]).exists():
                    raise PublicApiError("tenant_slug_unavailable", status_code=409)
                tenant = Tenant.objects.create(**data)
                audit_platform(request, tenant, "create", status=tenant.status)
        except IntegrityError:
            raise PublicApiError("tenant_slug_unavailable", status_code=409) from None
        return Response(platform_tenant_payload(tenant), status=201)


class PlatformTenantDetailView(PlatformTenantView):
    def patch(self, request, pk):
        serializer = PlatformTenantUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            tenant = get_object_or_404(
                Tenant.objects.select_for_update(no_key=True), pk=pk
            )
            if tenant.status == Tenant.Status.DECOMMISSIONED:
                raise PublicApiError("tenant_unavailable", status_code=409)
            previous_status = tenant.status
            for field, value in serializer.validated_data.items():
                setattr(tenant, field, value)
            tenant.save(update_fields=(*serializer.validated_data.keys(), "updated_at"))
            if tenant.status != previous_status:
                from .operations import apply_tenant_status_change

                apply_tenant_status_change(
                    tenant, previous_status, request.user.get_username()
                )
            audit_platform(
                request,
                tenant,
                "update",
                previous_status=previous_status,
                status=tenant.status,
            )
        return Response(platform_tenant_payload(tenant))


class InitialTenantAdministratorView(PlatformTenantView):
    @sensitive_variables()
    def post(self, request, pk):
        serializer = InitialTenantAdministratorSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            with transaction.atomic():
                tenant = get_object_or_404(
                    Tenant.objects.select_for_update(no_key=True), pk=pk
                )
                if tenant.status == Tenant.Status.DECOMMISSIONED:
                    raise PublicApiError("tenant_unavailable", status_code=409)
                if (
                    tenant.initial_administrator_created_at is not None
                    or independent_administrator_history(tenant)
                ):
                    raise PublicApiError(
                        "tenant_administrator_already_initialized", status_code=409
                    )
                users = get_user_model()
                if users.objects.filter(username__iexact=data["username"]).exists():
                    raise PublicApiError("username_unavailable", status_code=409)
                user = create_local_user(
                    username=data["username"],
                    password=data["initial_password"],
                    first_name=data.get("first_name", ""),
                    last_name=data.get("last_name", ""),
                    email=data.get("email", ""),
                    is_active=True,
                    is_staff=False,
                    is_superuser=False,
                )
                TenantMembership.objects.create(
                    tenant=tenant, user=user, role=TenantMembership.Role.TENANT_ADMIN
                )
                tenant.initial_administrator_created_at = timezone.now()
                tenant.save(
                    update_fields=("initial_administrator_created_at", "updated_at")
                )
                audit_platform(
                    request,
                    tenant,
                    "initial_administrator.create",
                    user_id=str(user.pk),
                )
        except IntegrityError:
            raise PublicApiError("username_unavailable", status_code=409) from None
        return Response({"tenant": platform_tenant_payload(tenant)}, status=201)


class PlatformTenantAgentOnboardingView(PlatformTenantView):
    def get(self, request, pk):
        tenant = get_object_or_404(Tenant, pk=pk)
        return Response(tenant_agent_onboarding_status(tenant=tenant))

    @sensitive_variables("data")
    def post(self, request, pk):
        serializer = AgentPkiInitializeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        with transaction.atomic():
            tenant = get_object_or_404(
                Tenant.objects.select_for_update(no_key=True), pk=pk
            )
            if tenant.status != Tenant.Status.ACTIVE:
                raise PublicApiError("tenant_inactive", status_code=409)
            if (
                tenant.initial_administrator_created_at is None
                and not independent_administrator_history(tenant)
            ):
                raise PublicApiError("tenant_administrator_required", status_code=409)
            if AgentPkiPolicy.objects.filter(tenant=tenant).exists():
                raise PublicApiError("agent_pki_already_configured", status_code=409)
            if AgentPkiPolicy.objects.filter(
                gateway_dns_name__iexact=data["gateway_dns_name"]
            ).exists():
                raise PublicApiError("gateway_dns_name_unavailable", status_code=409)
            prepare_managed_pki(
                tenant=tenant,
                gateway_dns_name=data["gateway_dns_name"],
                gateway_port=settings.AGENT_GATEWAY_PORT,
                recovery_passphrase=data["recovery_passphrase"].encode("utf-8"),
                actor=request.user.get_username(),
            )
        return Response(tenant_agent_onboarding_status(tenant=tenant), status=201)


class PlatformTenantAgentRecoveryView(PlatformTenantView):
    def get(self, request, pk):
        tenant = get_object_or_404(Tenant, pk=pk)
        try:
            recovery, digest = download_managed_pki_recovery(
                tenant=tenant,
                actor=request.user.get_username(),
            )
        except AgentPkiRecoveryMaterial.DoesNotExist:
            raise PublicApiError("agent_pki_recovery_unavailable", status_code=409) from None
        response = HttpResponse(recovery, content_type="application/x-pem-file")
        response["Content-Disposition"] = (
            f'attachment; filename="ipms-{tenant.slug}-agent-root-recovery.pem"'
        )
        response["Cache-Control"] = "no-store"
        response["Pragma"] = "no-cache"
        response["X-Content-Type-Options"] = "nosniff"
        response["X-IPMS-Recovery-SHA256"] = digest
        return response

    def post(self, request, pk):
        serializer = AgentPkiRecoveryConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tenant = get_object_or_404(Tenant, pk=pk)
        try:
            confirm_managed_pki_recovery(
                tenant=tenant,
                bundle_sha256=serializer.validated_data["bundle_sha256"],
                actor=request.user.get_username(),
            )
        except AgentPkiRecoveryMaterial.DoesNotExist:
            raise PublicApiError("agent_pki_recovery_unavailable", status_code=409) from None
        except ValidationError:
            raise PublicApiError("agent_pki_recovery_not_confirmed", status_code=409) from None
        return Response(tenant_agent_onboarding_status(tenant=tenant))


class PlatformTenantAgentGatewayVerifyView(PlatformTenantView):
    def post(self, request, pk):
        tenant = get_object_or_404(Tenant, pk=pk)
        if not AgentPkiPolicy.objects.filter(tenant=tenant).exists():
            raise PublicApiError("agent_pki_not_configured", status_code=409)
        verification = verify_gateway_isolation(requested_tenant=tenant)
        return Response(
            {
                "verification": verification,
                "onboarding": tenant_agent_onboarding_status(tenant=tenant),
            }
        )
