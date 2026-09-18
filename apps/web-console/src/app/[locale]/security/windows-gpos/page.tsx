/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render the single authorized Windows GPO deployment workspace.
 */
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { WindowsGpoWorkspace } from "@/components/windows-gpo-workspace";
import { resolveLocale } from "@/i18n/server";
import { getWindowsGpoCopy } from "@/i18n/windows-gpo-copy";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getDomainSecuritySettings } from "@/lib/server-domain-security";
import { requireTenantScope } from "@/lib/server-portal-scope";
import {
  getSecurityCustomGpos,
  getSecurityOverrides,
} from "@/lib/server-security-overrides";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata() {
  return { title: getWindowsGpoCopy(await resolveLocale()).title };
}

export default async function WindowsGpoPage({
  searchParams,
}: {
  searchParams: Promise<{
    source?: string | string[];
    baseline?: string | string[];
  }>;
}) {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "security.gpo_imports.run"))
    redirect(`/${locale}/access-unavailable`);
  const canManageOverrides = hasPermission(tenant, "security.baselines.manage");
  const [domains, overrides, customGpos] = await Promise.all([
    getDomainSecuritySettings(tenant.id),
    canManageOverrides
      ? getSecurityOverrides(tenant.id)
      : Promise.resolve({ data: [], status: 200 }),
    canManageOverrides
      ? getSecurityCustomGpos(tenant.id)
      : Promise.resolve({ data: [], status: 200 }),
  ]);
  if (
    !domains.sessionValid ||
    overrides.status === 401 ||
    customGpos.status === 401
  )
    redirect(`/${locale}/login`);
  if (
    domains.forbidden ||
    overrides.status === 403 ||
    customGpos.status === 403
  )
    redirect(`/${locale}/access-unavailable`);
  const query = await searchParams;
  const copy = getWindowsGpoCopy(locale);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-windows-gpos"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">Security / {copy.navigation}</p>
          <h1>{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
      </section>
      <WindowsGpoWorkspace
        catalog={domains.data}
        overrides={overrides.data}
        customGpos={customGpos.data}
        tenantId={tenant.id}
        csrfToken={session.csrf_token}
        locale={locale}
        preferredBaselineId={
          typeof query.baseline === "string" ? query.baseline : undefined
        }
        initialSource={
          query.source === "override" || query.source === "custom"
            ? query.source
            : "baseline"
        }
      />
    </ConsoleShell>
  );
}
