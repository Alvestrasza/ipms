from __future__ import annotations

from django.db.models import Q, QuerySet
from django.utils import timezone

from .models import Tenant, TenantMembership


class Permission:
    INVENTORY_VIEW = "inventory.view"
    CONNECTORS_MANAGE = "connectors.manage"
    AGENTS_VIEW = "agents.view"
    AGENTS_MANAGE = "agents.manage"
    SERVICE_ACCOUNTS_MANAGE = "service_accounts.manage"
    VIRTUAL_MACHINES_OPERATE = "virtual_machines.operate"
    VIRTUAL_MACHINES_CONSOLE_CONTROL = "virtual_machines.console.control"
    OPERATIONS_APPROVE = "operations.approve"
    AUDIT_VIEW = "audit.view"
    USERS_VIEW = "users.view"
    USERS_MANAGE = "users.manage"


ALL_PERMISSIONS = frozenset(
    value
    for name, value in vars(Permission).items()
    if name.isupper() and isinstance(value, str)
)

ROLE_PERMISSIONS = {
    TenantMembership.Role.TENANT_ADMIN: ALL_PERMISSIONS,
    TenantMembership.Role.OPERATOR: frozenset(
        {
            Permission.INVENTORY_VIEW,
            Permission.CONNECTORS_MANAGE,
            Permission.AGENTS_VIEW,
            Permission.AGENTS_MANAGE,
            Permission.VIRTUAL_MACHINES_OPERATE,
            Permission.VIRTUAL_MACHINES_CONSOLE_CONTROL,
        }
    ),
    TenantMembership.Role.APPROVER: frozenset(
        {
            Permission.INVENTORY_VIEW,
            Permission.OPERATIONS_APPROVE,
            Permission.AUDIT_VIEW,
        }
    ),
    TenantMembership.Role.AUDITOR: frozenset(
        {
            Permission.INVENTORY_VIEW,
            Permission.AGENTS_VIEW,
            Permission.AUDIT_VIEW,
            Permission.USERS_VIEW,
        }
    ),
    TenantMembership.Role.READER: frozenset({Permission.INVENTORY_VIEW}),
}


def effective_memberships(
    queryset: QuerySet[TenantMembership] | None = None,
) -> QuerySet[TenantMembership]:
    memberships = queryset if queryset is not None else TenantMembership.objects.all()
    return memberships.filter(is_active=True).filter(
        Q(expires_at__isnull=True) | Q(expires_at__gt=timezone.now())
    )


def is_platform_administrator(user) -> bool:
    return bool(user.is_authenticated and user.is_staff)


def effective_tenant_role(user, tenant: Tenant) -> str | None:
    if is_platform_administrator(user):
        return "platform_admin"
    membership = effective_memberships(
        TenantMembership.objects.filter(user=user, tenant=tenant)
    ).first()
    return membership.role if membership else None


def effective_tenant_permissions(user, tenant: Tenant) -> frozenset[str]:
    if is_platform_administrator(user):
        return ALL_PERMISSIONS
    role = effective_tenant_role(user, tenant)
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_tenant_permission(user, tenant: Tenant, permission: str) -> bool:
    return permission in effective_tenant_permissions(user, tenant)
