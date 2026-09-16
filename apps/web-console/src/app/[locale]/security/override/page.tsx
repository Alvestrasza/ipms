/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Authorize tenant original-setting overrides and their managed deployment.
 */
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { SecurityOverrides } from "@/components/security-overrides";
import { getSecurityOverrideCopy } from "@/i18n/security-override-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getDomainSecuritySettings } from "@/lib/server-domain-security";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getSecurityOverrides } from "@/lib/server-security-overrides";
import { selectedTenant } from "@/lib/tenant-selection";
export async function generateMetadata() {
  return { title: getSecurityOverrideCopy(await resolveLocale()).title };
}
export default async function OverridePage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "security.baselines.manage"))
    redirect(`/${locale}/access-unavailable`);
  const [overrides, domains] = await Promise.all([
    getSecurityOverrides(tenant.id),
    getDomainSecuritySettings(tenant.id),
  ]);
  if (overrides.status === 401 || !domains.sessionValid)
    redirect(`/${locale}/login`);
  if (overrides.status === 403) redirect(`/${locale}/access-unavailable`);
  const copy = getSecurityOverrideCopy(locale);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-override"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">Security</p>
          <h1>{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
      </section>
      <SecurityOverrides
        key={tenant.id}
        initial={overrides.data}
        domains={domains.data}
        tenantId={tenant.id}
        csrfToken={session.csrf_token}
        locale={locale}
        canImport={hasPermission(tenant, "security.gpo_imports.run")}
      />
    </ConsoleShell>
  );
}
