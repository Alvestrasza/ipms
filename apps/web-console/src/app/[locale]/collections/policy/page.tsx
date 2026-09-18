/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render ordered multi-domain Policy Collection management.
 */
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { PolicyCollections } from "@/components/policy-collections";
import { getCollectionCopy } from "@/i18n/collection-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getPolicyCollections } from "@/lib/server-collections";
import { getDomainSecuritySettings } from "@/lib/server-domain-security";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getSecurityOverrides } from "@/lib/server-security-overrides";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata() {
  return { title: getCollectionCopy(await resolveLocale()).policyTitle };
}
export default async function PolicyCollectionsPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "security.collections.view"))
    redirect(`/${locale}/access-unavailable`);
  const [collections, domains, overrides] = await Promise.all([
    getPolicyCollections(tenant.id),
    getDomainSecuritySettings(tenant.id),
    getSecurityOverrides(tenant.id),
  ]);
  if (
    !collections.sessionValid ||
    !domains.sessionValid ||
    overrides.status === 401
  )
    redirect(`/${locale}/login`);
  if (collections.forbidden || domains.forbidden || overrides.status === 403)
    redirect(`/${locale}/access-unavailable`);
  const copy = getCollectionCopy(locale);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="collections-policy"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">
            {copy.navigation} / {copy.policyNavigation}
          </p>
          <h1>{copy.policyTitle}</h1>
          <p>{copy.policyDescription}</p>
        </div>
      </section>
      {collections.data && domains.data && overrides.data ? (
        <PolicyCollections
          initial={collections.data}
          domains={domains.data}
          overrides={overrides.data}
          tenantId={tenant.id}
          csrfToken={session.csrf_token}
          canManage={hasPermission(tenant, "security.collections.manage")}
          copy={copy}
        />
      ) : (
        <p role="alert">{copy.unavailable}</p>
      )}
    </ConsoleShell>
  );
}
