/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Author bounded tenant custom GPO definitions.
 */
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { SecurityOverrides } from "@/components/security-overrides";
import { getSecurityCustomGpoCopy } from "@/i18n/security-custom-gpo-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getDomainSecuritySettings } from "@/lib/server-domain-security";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getSecurityCustomGpos } from "@/lib/server-security-overrides";
import { selectedTenant } from "@/lib/tenant-selection";

export default async function CustomGpoPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "security.baselines.manage"))
    redirect(`/${locale}/access-unavailable`);
  const [customGpos, domains] = await Promise.all([
    getSecurityCustomGpos(tenant.id),
    getDomainSecuritySettings(tenant.id),
  ]);
  if (customGpos.status === 401 || !domains.sessionValid)
    redirect(`/${locale}/login`);
  if (customGpos.status === 403) redirect(`/${locale}/access-unavailable`);
  const copy = getSecurityCustomGpoCopy(locale);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-custom-gpo"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">Security / Windows GPOs</p>
          <h1>{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
        {hasPermission(tenant, "security.gpo_imports.run") ? (
          <Link
            className="outline-button"
            href={`/${locale}/security/windows-gpos` as Route}
          >
            {copy.openDeployment}
          </Link>
        ) : null}
      </section>
      <SecurityOverrides
        key={tenant.id}
        mode="custom"
        initial={customGpos.data}
        domains={domains.data}
        tenantId={tenant.id}
        csrfToken={session.csrf_token}
        locale={locale}
      />
    </ConsoleShell>
  );
}
