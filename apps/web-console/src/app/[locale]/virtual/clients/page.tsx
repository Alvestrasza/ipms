import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { WindowsServerInventory } from "@/components/windows-server-inventory";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { getWindowsServers } from "@/lib/server-windows";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.windowsClients.virtualTitle };
}

export default async function VirtualWindowsClientsPage({
  searchParams,
}: {
  searchParams: Promise<{ family?: string | string[] }>;
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  const familyParameter = (await searchParams).family;
  const requestedFamily = Array.isArray(familyParameter)
    ? familyParameter[0]
    : familyParameter;
  if (
    requestedFamily &&
    (requestedFamily !== requestedFamily.trim() || requestedFamily.length > 64)
  ) {
    redirect(`/${locale}/virtual/clients`);
  }
  const family = requestedFamily || undefined;
  const inventory = await getWindowsServers(
    tenant.id,
    "virtual",
    undefined,
    "client",
    family,
  );
  if (!inventory.sessionValid) redirect(`/${locale}/login`);

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="virtual-clients"
      activeWindowsClientFamily={family}
    >
      <div
        className={`preview-notice ${inventory.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {inventory.available
          ? dictionary.windowsClients.liveData
          : dictionary.windowsClients.unavailableData}
      </div>
      <section
        className="page-heading"
        aria-labelledby="virtual-windows-clients-heading"
      >
        <div>
          <p className="eyebrow">{dictionary.windowsClients.virtualEyebrow}</p>
          <h1 id="virtual-windows-clients-heading">
            {dictionary.windowsClients.virtualHeading}
          </h1>
          <p>
            {dictionary.windowsClients.virtualDescriptionPrefix}{" "}
            {tenant.display_name}.
          </p>
        </div>
        <span className="read-only-badge">Agent</span>
      </section>
      <WindowsServerInventory
        servers={inventory.servers}
        serverType="virtual"
        roleLabel={
          family
            ? (dictionary.windowsClientFamilies[family] ?? family)
            : undefined
        }
        locale={locale}
        copy={dictionary.windowsClients}
      />
    </ConsoleShell>
  );
}
