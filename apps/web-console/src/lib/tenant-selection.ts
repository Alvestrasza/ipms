import type { AuthenticatedSession, TenantSummary } from "./auth-types";

export const TENANT_COOKIE = "ipms_tenant";

type CookieReader = {
  get(name: string): { value: string } | undefined;
};

export function selectedTenant(
  session: AuthenticatedSession,
  cookieStore: CookieReader,
): TenantSummary | null {
  const selectedId = cookieStore.get(TENANT_COOKIE)?.value;
  return (
    session.tenants.find((tenant) => tenant.id === selectedId) ??
    session.tenants[0] ??
    null
  );
}
