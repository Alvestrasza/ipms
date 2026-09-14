/**
 * File Name: page.tsx
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Authorize tenant baseline visibility administration before loading settings.
 */
import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { SecurityBaselineAdministration } from "@/components/security-baseline-administration";
import { getSecurityCopy } from "@/i18n/security-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getSecurityBaselineSettings } from "@/lib/server-security";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getSecurityCopy(await resolveLocale()).admin.title };
}

export default async function SecurityBaselineAdministrationPage() {
  const locale = await resolveLocale();
  const copy = getSecurityCopy(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  if (!hasPermission(tenant, "security.baselines.manage"))
    redirect(`/${locale}/security/baseline`);

  const settings = await getSecurityBaselineSettings(tenant.id);
  if (!settings.sessionValid) redirect(`/${locale}/login`);
  if (settings.forbidden) redirect(`/${locale}/access-unavailable`);

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="admin-security-baselines"
    >
      <section
        className="page-heading"
        aria-labelledby="baseline-administration-heading"
      >
        <div>
          <p className="eyebrow">{copy.admin.eyebrow}</p>
          <h1 id="baseline-administration-heading">{copy.admin.title}</h1>
          <p>{copy.admin.description}</p>
        </div>
        <span className="read-only-badge">{tenant.display_name}</span>
      </section>
      <SecurityBaselineAdministration
        key={tenant.id}
        initialSettings={settings.data}
        csrfToken={session.csrf_token}
        tenantId={tenant.id}
        locale={locale}
        copy={copy}
      />
    </ConsoleShell>
  );
}
