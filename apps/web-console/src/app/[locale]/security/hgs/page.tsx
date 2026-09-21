/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render HGS deployment planning only within an authorized tenant session.
 */
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { HgsWorkspace } from "@/components/hgs-workspace";
import { getHgsCopy } from "@/i18n/hgs-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getHgsOverview } from "@/lib/server-hgs";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata() {
  return { title: getHgsCopy(await resolveLocale()).title };
}

export default async function HgsPage() {
  const locale = await resolveLocale();
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (
    !tenant ||
    (!hasPermission(tenant, "hgs.view") &&
      !hasPermission(tenant, "inventory.view"))
  )
    redirect(`/${locale}/access-unavailable`);
  const c = getHgsCopy(locale);
  const hgsTenant = tenant.purpose === "hgs";
  if (hgsTenant && !hasPermission(tenant, "hgs.view"))
    redirect(`/${locale}/access-unavailable`);
  const overview = hgsTenant ? await getHgsOverview(tenant.id) : null;
  if (overview && !overview.sessionValid) redirect(`/${locale}/login`);
  if (overview?.forbidden) redirect(`/${locale}/access-unavailable`);
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-hgs"
    >
      <section className="page-heading">
        <div>
          <p className="eyebrow">{c.security} / HGS</p>
          <h1>{c.title}</h1>
          <p>{c.description}</p>
        </div>
      </section>
      {hgsTenant ? (
        <HgsWorkspace
          key={tenant.id}
          initial={overview?.data ?? null}
          tenantId={tenant.id}
          csrfToken={session.csrf_token}
          canManage={hasPermission(tenant, "hgs.manage")}
          locale={locale}
        />
      ) : (
        <section className="inventory-panel agent-admin-panel">
          <div className="panel__header">
            <h2>{c.singleAppliance}</h2>
          </div>
          <p className="preview-notice">{c.tenantRequired}</p>
        </section>
      )}
    </ConsoleShell>
  );
}
