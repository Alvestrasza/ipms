import json
from ipaddress import ip_address

from django.contrib.auth import authenticate, get_user_model, login, logout
from django.db import IntegrityError, transaction
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.http import HttpRequest, JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError

from .access import tenants_for_user
from .models import Tenant, TenantMembership
from .permissions import HasSelectedTenantAccess, HasTenantPermission
from .rbac import (
    Permission,
    effective_memberships,
    effective_tenant_permissions,
    effective_tenant_role,
    effective_platform_permissions,
    has_tenant_permission,
    is_platform_administrator,
)
from .serializers import (
    TenantMembershipUpdateSerializer,
    TenantUserCreateSerializer,
    tenant_user_payload,
)

MAX_LOGIN_BODY_BYTES = 8_192


def _source_ip(request: HttpRequest) -> str | None:
    value = request.META.get("REMOTE_ADDR", "")
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def _audit_authentication(
    request: HttpRequest,
    *,
    actor: str,
    action: str,
    outcome: str,
) -> None:
    AuditEvent.objects.create(
        actor=actor[:255] or "anonymous",
        action=action,
        outcome=outcome,
        correlation_id=request.correlation_id,
        source_ip=_source_ip(request),
    )


def _login_error(request: HttpRequest, *, status: int) -> JsonResponse:
    return JsonResponse(
        {
            "error": {
                "code": "authentication_failed" if status == 401 else "invalid_request",
                "message": "Sign-in failed.",
                "correlation_id": str(request.correlation_id),
            }
        },
        status=status,
    )


def _tenant_payload(user) -> list[dict[str, object]]:
    return [
        {
            "id": str(tenant.id),
            "slug": tenant.slug,
            "display_name": tenant.display_name,
            "role": effective_tenant_role(user, tenant),
            "permissions": sorted(effective_tenant_permissions(user, tenant)),
        }
        for tenant in tenants_for_user(user)
    ]


def _session_payload(request: HttpRequest) -> dict:
    if not request.user.is_authenticated:
        return {
            "authenticated": False,
            "csrf_token": get_token(request),
        }
    return {
        "authenticated": True,
        "csrf_token": get_token(request),
        "user": {
            "username": request.user.get_username(),
            "display_name": request.user.get_full_name() or request.user.get_username(),
            "is_platform_admin": is_platform_administrator(request.user),
        },
        "tenants": _tenant_payload(request.user),
        "platform_permissions": sorted(effective_platform_permissions(request.user)),
    }


@require_GET
@ensure_csrf_cookie
def session_view(request: HttpRequest) -> JsonResponse:
    return JsonResponse(_session_payload(request))


@require_POST
@csrf_protect
def login_view(request: HttpRequest) -> JsonResponse:
    if len(request.body) > MAX_LOGIN_BODY_BYTES:
        return _login_error(request, status=400)

    try:
        payload = json.loads(request.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}

    if not isinstance(payload, dict):
        payload = {}

    username = payload.get("username", "")
    password = payload.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        username = ""
        password = ""
    if len(username) > 254 or len(password) > 1_024:
        username = ""
        password = ""

    user = authenticate(request, username=username, password=password)
    if user is None:
        _audit_authentication(
            request,
            actor=username,
            action="auth.login",
            outcome=AuditEvent.Outcome.DENIED,
        )
        return _login_error(request, status=401)

    login(request, user)
    _audit_authentication(
        request,
        actor=user.get_username(),
        action="auth.login",
        outcome=AuditEvent.Outcome.SUCCEEDED,
    )
    return JsonResponse(_session_payload(request))


@require_POST
@csrf_protect
def logout_view(request: HttpRequest) -> JsonResponse:
    actor = (
        request.user.get_username() if request.user.is_authenticated else "anonymous"
    )
    if request.user.is_authenticated:
        _audit_authentication(
            request,
            actor=actor,
            action="auth.logout",
            outcome=AuditEvent.Outcome.SUCCEEDED,
        )
    logout(request)
    return JsonResponse(_session_payload(request))


class CanViewUsers(HasTenantPermission):
    message = "User viewing permission is required."
    required_permission = Permission.USERS_VIEW


class CanManageUsers(HasTenantPermission):
    message = "User management permission is required."
    required_permission = Permission.USERS_MANAGE


def _membership_queryset(request):
    return (
        TenantMembership.objects.filter(
            tenant=request.tenant,
            user__is_staff=False,
            user__is_superuser=False,
            user__ipms_platform_administrator__isnull=True,
        )
        .select_related("user")
        .prefetch_related("user__ipms_external_identities")
    )


def _audit_user_change(request, *, action: str, membership, outcome: str, details=None):
    AuditEvent.objects.create(
        tenant=request.tenant,
        actor=request.user.get_username()[:255],
        action=action,
        object_type="tenant_membership",
        object_id=str(membership.id),
        outcome=outcome,
        correlation_id=request.correlation_id,
        source_ip=_source_ip(request),
        details=details or {},
    )


def _lock_membership_tenant(request):
    tenant = Tenant.objects.select_for_update(no_key=True).get(pk=request.tenant.pk)
    if not has_tenant_permission(request.user, tenant, Permission.USERS_MANAGE):
        raise PublicApiError("forbidden", status_code=403)
    return tenant


@method_decorator(sensitive_post_parameters(), name="dispatch")
class TenantUserListCreateView(APIView):
    permission_classes = (
        IsAuthenticated,
        HasSelectedTenantAccess,
        CanViewUsers,
    )

    def get(self, request):
        return Response(
            [tenant_user_payload(item) for item in _membership_queryset(request)]
        )

    @sensitive_variables()
    def post(self, request):
        if Permission.USERS_MANAGE not in effective_tenant_permissions(
            request.user, request.tenant
        ):
            self.permission_denied(request, message=CanManageUsers.message)
        serializer = TenantUserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        user_model = get_user_model()
        if user_model.objects.filter(username__iexact=data["username"]).exists():
            raise PublicApiError("username_unavailable", status_code=409)
        try:
            with transaction.atomic():
                _lock_membership_tenant(request)
                user = user_model.objects.create_user(
                    username=data["username"],
                    password=data["initial_password"],
                    first_name=data.get("first_name", ""),
                    last_name=data.get("last_name", ""),
                    email=data.get("email", ""),
                )
                membership = TenantMembership.objects.create(
                    tenant=request.tenant,
                    user=user,
                    role=data["role"],
                    expires_at=data.get("expires_at"),
                )
                _audit_user_change(
                    request,
                    action="identity.user.create",
                    membership=membership,
                    outcome=AuditEvent.Outcome.SUCCEEDED,
                    details={"role": membership.role},
                )
        except IntegrityError as exc:
            raise PublicApiError("username_unavailable", status_code=409) from exc
        membership = _membership_queryset(request).get(id=membership.id)
        return Response(tenant_user_payload(membership), status=status.HTTP_201_CREATED)


class TenantUserDetailView(APIView):
    permission_classes = (
        IsAuthenticated,
        HasSelectedTenantAccess,
        CanManageUsers,
    )

    def patch(self, request, pk):
        serializer = TenantMembershipUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        changes = serializer.validated_data
        with transaction.atomic():
            _lock_membership_tenant(request)
            try:
                membership = (
                    _membership_queryset(request)
                    .select_for_update(of=("self",))
                    .get(id=pk)
                )
            except TenantMembership.DoesNotExist:
                raise PublicApiError("user_not_found", status_code=404) from None
            resulting_role = changes.get("role", membership.role)
            resulting_active = changes.get("is_active", membership.is_active)
            resulting_expiry = changes.get("expires_at", membership.expires_at)
            removes_tenant_admin = (
                membership.role == TenantMembership.Role.TENANT_ADMIN
                and (
                    resulting_role != TenantMembership.Role.TENANT_ADMIN
                    or not resulting_active
                    or resulting_expiry is not None
                )
            )
            if removes_tenant_admin:
                other_admin_exists = effective_memberships(
                    TenantMembership.objects.filter(
                        tenant=request.tenant,
                        role=TenantMembership.Role.TENANT_ADMIN,
                    ).exclude(id=membership.id)
                ).exists()
                if not other_admin_exists:
                    raise PublicApiError("last_tenant_admin", status_code=409)
                if membership.user_id == request.user.id:
                    raise PublicApiError("self_role_change_denied", status_code=409)
            previous = {
                "role": membership.role,
                "is_active": membership.is_active,
                "expires_at": (
                    membership.expires_at.isoformat() if membership.expires_at else None
                ),
            }
            for field, value in changes.items():
                setattr(membership, field, value)
            membership.save(update_fields=(*changes.keys(), "updated_at"))
            _audit_user_change(
                request,
                action="identity.membership.update",
                membership=membership,
                outcome=AuditEvent.Outcome.SUCCEEDED,
                details={
                    "previous": previous,
                    "current": {
                        "role": membership.role,
                        "is_active": membership.is_active,
                        "expires_at": (
                            membership.expires_at.isoformat()
                            if membership.expires_at
                            else None
                        ),
                    },
                },
            )
        membership = _membership_queryset(request).get(id=membership.id)
        return Response(tenant_user_payload(membership))
