from ipms.apps.tenancy.permissions import HasTenantPermission
from ipms.apps.tenancy.rbac import Permission


class CanManageConnectors(HasTenantPermission):
    message = "Connector management permission is required."
    required_permission = Permission.CONNECTORS_MANAGE


class CanManageInfrastructure(HasTenantPermission):
    message = "Virtual machine operation permission is required."
    required_permission = Permission.VIRTUAL_MACHINES_OPERATE
