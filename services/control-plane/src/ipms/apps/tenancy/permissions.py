from rest_framework.permissions import BasePermission

from .access import selected_tenant_for_request
from .rbac import has_tenant_permission, is_platform_administrator


class IsPlatformAdministrator(BasePermission):
    def has_permission(self, request, view):
        return is_platform_administrator(request.user)


class HasSelectedTenantAccess(BasePermission):
    def has_permission(self, request, view) -> bool:
        request.tenant = selected_tenant_for_request(request)
        return True


class HasTenantPermission(BasePermission):
    required_permission = ""

    def has_permission(self, request, view) -> bool:
        return bool(
            self.required_permission
            and has_tenant_permission(
                request.user,
                request.tenant,
                self.required_permission,
            )
        )
