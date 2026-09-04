from ipms.apps.tenancy.permissions import HasTenantPermission
from ipms.apps.tenancy.rbac import Permission


class CanDeployAgents(HasTenantPermission):
    message = "Agent management permission is required."
    required_permission = Permission.AGENTS_MANAGE
