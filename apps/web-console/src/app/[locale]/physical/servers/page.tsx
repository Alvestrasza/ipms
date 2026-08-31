import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { WindowsServerInventory } from "@/components/windows-server-inventory";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getWindowsServers } from "@/lib/server-windows";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.windowsServers.physicalTitle };
}

export default async function PhysicalWindowsServersPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);

  const inventory = await getWindowsServers(tenant.id, "physical");
  if (!inventory.sessionValid) redirect(`/${locale}/login`);

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="physical-servers"
    >
      <div
        className={`preview-notice ${inventory.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {inventory.available
          ? dictionary.windowsServers.liveData
          : dictionary.windowsServers.unavailableData}
      </div>
      <section
        className="page-heading"
        aria-labelledby="physical-windows-heading"
      >
        <div>
          <p className="eyebrow">{dictionary.windowsServers.eyebrow}</p>
          <h1 id="physical-windows-heading">
            {dictionary.windowsServers.physicalHeading}
          </h1>
          <p>
            {dictionary.windowsServers.physicalDescriptionPrefix}{" "}
            {tenant.display_name}.
          </p>
        </div>
        <span className="read-only-badge">{dictionary.overview.readOnly}</span>
      </section>
      <WindowsServerInventory
        servers={inventory.servers}
        serverType="physical"
        locale={locale}
        copy={dictionary.windowsServers}
      />
    </ConsoleShell>
  );
}
