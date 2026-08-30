from rest_framework.permissions import BasePermission

from ipms.apps.tenancy.models import TenantMembership


class CanManageConnectors(BasePermission):
    message = "Connector management requires tenant administrator access."

    def has_permission(self, request, view) -> bool:
        if request.user.is_staff:
            return True
        return TenantMembership.objects.filter(
            tenant=request.tenant,
            user=request.user,
            is_active=True,
            role=TenantMembership.Role.TENANT_ADMIN,
        ).exists()
