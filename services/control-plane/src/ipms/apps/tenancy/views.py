import json
from ipaddress import ip_address

from django.contrib.auth import authenticate, login, logout
from django.http import HttpRequest, JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from django.views.decorators.http import require_GET, require_POST

from ipms.apps.audit.models import AuditEvent

from .access import tenants_for_user
from .models import TenantMembership


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


def _tenant_payload(user) -> list[dict[str, str]]:
    roles = {
        membership.tenant_id: membership.role
        for membership in TenantMembership.objects.filter(
            user=user,
            is_active=True,
        )
    }
    return [
        {
            "id": str(tenant.id),
            "slug": tenant.slug,
            "display_name": tenant.display_name,
            "role": "platform_admin" if user.is_staff else roles[tenant.id],
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
            "display_name": request.user.get_full_name()
            or request.user.get_username(),
            "is_platform_admin": request.user.is_staff,
        },
        "tenants": _tenant_payload(request.user),
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
    actor = request.user.get_username() if request.user.is_authenticated else "anonymous"
    if request.user.is_authenticated:
        _audit_authentication(
            request,
            actor=actor,
            action="auth.logout",
            outcome=AuditEvent.Outcome.SUCCEEDED,
        )
    logout(request)
    return JsonResponse(_session_payload(request))
