import uuid

from django.http import HttpRequest
from rest_framework.exceptions import NotFound, ParseError

from .models import Tenant, TenantMembership


TENANT_HEADER = "X-IPMS-Tenant-ID"


def tenants_for_user(user) -> list[Tenant]:
    if not user.is_authenticated:
        return []
    queryset = Tenant.objects.filter(status=Tenant.Status.ACTIVE)
    if user.is_staff:
        return list(queryset)
    return list(
        queryset.filter(
            memberships__user=user,
            memberships__is_active=True,
        ).distinct()
    )


def selected_tenant_for_request(request: HttpRequest) -> Tenant:
    raw_tenant_id = request.headers.get(TENANT_HEADER, "").strip()
    if not raw_tenant_id:
        raise ParseError(f"The {TENANT_HEADER} header is required.")

    try:
        tenant_id = uuid.UUID(raw_tenant_id)
    except ValueError as exc:
        raise ParseError(f"The {TENANT_HEADER} header is invalid.") from exc

    accessible_tenants = Tenant.objects.filter(
        id=tenant_id,
        status=Tenant.Status.ACTIVE,
    )
    if not request.user.is_staff:
        accessible_tenants = accessible_tenants.filter(
            memberships__user=request.user,
            memberships__is_active=True,
        )

    try:
        return accessible_tenants.get()
    except Tenant.DoesNotExist as exc:
        # Do not reveal whether an inaccessible tenant exists.
        raise NotFound("The selected tenant was not found.") from exc
