/**
 * File Name: page.tsx
 * Version: v0.1.0
 * Created: 2026-09-13
 * Last Modified: 2026-09-13
 * Author: Alice Endelgard
 * Organization: Alvestrasza Corporation
 * Description: Configure tenant WSUS server associations in the administration area.
 */
import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { WsusConsole } from "@/components/wsus-console";
import { resolveLocale } from "@/i18n/server";
import { getWsusCopy } from "@/i18n/wsus-copy";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getWsusOverview } from "@/lib/server-wsus";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getWsusCopy(await resolveLocale()).adminTitle };
}

export default async function WsusAdministrationPage({
  searchParams,
}: {
  searchParams: Promise<{ source?: string | string[] }>;
}) {
  const locale = await resolveLocale();
  const copy = getWsusCopy(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  if (!hasPermission(tenant, "connectors.manage"))
    redirect(`/${locale}/updates/wsus`);
  const requestedSource = (await searchParams).source;
  const overview = await getWsusOverview(tenant.id, {
    includeComparison: false,
    sourceId: typeof requestedSource === "string" ? requestedSource : undefined,
  });
  if (!overview.sessionValid) redirect(`/${locale}/login`);
  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="admin-wsus">
      <section
        className="page-heading"
        aria-labelledby="wsus-administration-heading"
      >
        <div>
          <p className="eyebrow">{copy.adminEyebrow}</p>
          <h1 id="wsus-administration-heading">{copy.adminTitle}</h1>
          <p>{copy.adminDescription}</p>
        </div>
        <span className="read-only-badge">{tenant.display_name}</span>
      </section>
      <WsusConsole
        key={tenant.id}
        configurationOnly
        initialSources={overview.sources}
        initialSourceId={overview.selectedSourceId}
        initialComparison={null}
        initialObservedAt={Date.now()}
        available={overview.available}
        tenantId={tenant.id}
        csrfToken={session.csrf_token}
        canManage
        locale={locale}
        copy={copy}
      />
    </ConsoleShell>
  );
}
