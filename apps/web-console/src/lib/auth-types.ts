/**
 * File Name: auth-types.ts
 * Version: v0.1.0
 * Created: 2026-08-30 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Define tenant sessions and server-issued portal permission codes.
 */
export type TenantRole =
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
  | "service_accounts.manage"
  | "security.baselines.manage"
  | "security.scans.run"
  | "virtual_machines.operate"
  | "virtual_machines.console.control"
  | "virtual_machines.configure"
  | "virtual_machines.checkpoints.manage"
  | "virtual_machines.migrate"
  | "virtual_machines.cluster.manage"
  | "operations.approve"
  | "audit.view"
  | "users.view"
  | "users.manage";

export type TenantSummary = {
  id: string;
  slug: string;
  display_name: string;
  role: TenantRole;
  permissions: PermissionCode[];
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
  platform_permissions: "tenants.manage"[];
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
  return tenant.permissions?.includes(permission) === true;
}

export function hasPlatformPermission(
  session: AuthenticatedSession,
  permission: "tenants.manage",
): boolean {
  return (
    session.user.is_platform_admin &&
    session.platform_permissions?.includes(permission) === true
  );
}

export function portalScope(
  session: IpmsSession | null,
): "anonymous" | "platform" | "tenant" | "no-tenant" {
  if (!session?.authenticated) return "anonymous";
  if (session.user.is_platform_admin) return "platform";
  return session.tenants.length ? "tenant" : "no-tenant";
}
