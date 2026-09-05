"""Platform metadata administration without customer operational access."""

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from .models import Tenant, TenantMembership
from .permissions import IsPlatformAdministrator
from .serializers import (
    InitialTenantAdministratorSerializer,
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
        details=details,
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
                user = users.objects.create_user(
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
