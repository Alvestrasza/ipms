export type TenantRole =
  | "platform_admin"
  | "tenant_admin"
  | "operator"
  | "approver"
  | "auditor"
  | "reader";

export type PermissionCode =
  | "inventory.view"
  | "connectors.manage"
  | "agents.view"
  | "agents.manage"
  | "virtual_machines.operate"
  | "virtual_machines.console.control"
  | "operations.approve"
  | "audit.view"
  | "users.view"
  | "users.manage";

export type TenantSummary = {
  id: string;
  slug: string;
  display_name: string;
  role: TenantRole;
  permissions?: PermissionCode[];
};

export type AuthenticatedSession = {
  authenticated: true;
  csrf_token: string;
  user: {
    username: string;
    display_name: string;
    is_platform_admin: boolean;
  };
  tenants: TenantSummary[];
};

export type AnonymousSession = {
  authenticated: false;
  csrf_token: string;
};

export type IpmsSession = AuthenticatedSession | AnonymousSession;

export function hasPermission(
  tenant: TenantSummary,
  permission: PermissionCode,
): boolean {
  if (tenant.permissions) return tenant.permissions.includes(permission);
  return ["platform_admin", "tenant_admin"].includes(tenant.role);
}
