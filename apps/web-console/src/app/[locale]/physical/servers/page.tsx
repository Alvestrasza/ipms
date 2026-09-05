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
  return { title: dictionary.windowsServers.physicalTitle };
}

export default async function PhysicalWindowsServersPage({
  searchParams,
}: {
  searchParams: Promise<{ role?: string | string[] }>;
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  const roleParameter = (await searchParams).role;
  const requestedRole = Array.isArray(roleParameter)
    ? roleParameter[0]
    : roleParameter;
  if (
    requestedRole &&
    (requestedRole !== requestedRole.trim() || requestedRole.length > 255)
  ) {
    redirect(`/${locale}/physical/servers`);
  }
  const role =
    requestedRole &&
    requestedRole === requestedRole.trim() &&
    requestedRole.length <= 255
      ? requestedRole
      : undefined;

  const inventory = await getWindowsServers(tenant.id, "physical", role);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="physical-servers"
      activeWindowsRole={role}
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
        roleLabel={role}
        locale={locale}
        copy={dictionary.windowsServers}
      />
    </ConsoleShell>
  );
}
