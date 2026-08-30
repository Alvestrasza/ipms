from rest_framework.permissions import BasePermission

from .access import selected_tenant_for_request


class HasSelectedTenantAccess(BasePermission):
    def has_permission(self, request, view) -> bool:
        request.tenant = selected_tenant_for_request(request)
        return True
