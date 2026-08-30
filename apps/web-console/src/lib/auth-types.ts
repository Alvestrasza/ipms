export type TenantRole =
  | "platform_admin"
  | "tenant_admin"
  | "operator"
  | "reader";

export type TenantSummary = {
  id: string;
  slug: string;
  display_name: string;
  role: TenantRole;
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
