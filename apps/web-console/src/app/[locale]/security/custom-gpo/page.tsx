/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Reserve the bounded tenant custom GPO management destination.
 */
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { resolveLocale } from "@/i18n/server";
import { getWindowsGpoCopy } from "@/i18n/windows-gpo-copy";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";

export default async function CustomGpoPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "security.baselines.manage"))
    redirect(`/${locale}/access-unavailable`);
  const copy = getWindowsGpoCopy(locale);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-custom-gpo"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">Security / {copy.navigation}</p>
          <h1>{copy.customTitle}</h1>
          <p>{copy.customDescription}</p>
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
    </ConsoleShell>
  );
}
