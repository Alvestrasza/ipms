/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Authorize domain planning in the selected tenant before reading settings.
 */
import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { DomainSecurityAdministration } from "@/components/domain-security-administration";
import styles from "@/components/domain-security-administration.module.css";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getDomainSecuritySettings } from "@/lib/server-domain-security";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getDomainSecurityCopy(await resolveLocale()).title };
}

export default async function DomainSecurityAdministrationPage() {
  const locale = await resolveLocale();
  const copy = getDomainSecurityCopy(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  if (!hasPermission(tenant, "security.domains.manage"))
    redirect(`/${locale}/security/baseline`);
  const result = await getDomainSecuritySettings(tenant.id);
  if (!result.sessionValid) redirect(`/${locale}/login`);
  if (result.forbidden) redirect(`/${locale}/access-unavailable`);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="admin-security-domains"
    >
      <section
        className="page-heading"
        aria-labelledby="domain-security-heading"
      >
        <div className={styles.headingText}>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1 id="domain-security-heading">{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
        <span className="read-only-badge">{tenant.display_name}</span>
      </section>
      <DomainSecurityAdministration
        key={tenant.id}
        initialCatalog={result.data}
        tenantId={tenant.id}
        csrfToken={session.csrf_token}
        locale={locale}
        copy={copy}
      />
    </ConsoleShell>
  );
}
