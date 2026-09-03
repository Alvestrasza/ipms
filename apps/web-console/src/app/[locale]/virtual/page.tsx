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
  return { title: dictionary.windowsServers.virtualTitle };
}

export default async function VirtualWindowsServersPage({
  searchParams,
}: {
  searchParams: Promise<{ role?: string | string[] }>;
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  const roleParameter = (await searchParams).role;
  const requestedRole = Array.isArray(roleParameter)
    ? roleParameter[0]
    : roleParameter;
  if (
    requestedRole &&
    (requestedRole !== requestedRole.trim() || requestedRole.length > 255)
  ) {
    redirect(`/${locale}/virtual`);
  }
  const role =
    requestedRole &&
    requestedRole === requestedRole.trim() &&
    requestedRole.length <= 255
      ? requestedRole
      : undefined;

  const inventory = await getWindowsServers(tenant.id, "virtual", role);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="virtual"
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
        aria-labelledby="virtual-windows-heading"
      >
        <div>
          <p className="eyebrow">{dictionary.windowsServers.virtualEyebrow}</p>
          <h1 id="virtual-windows-heading">
            {dictionary.windowsServers.virtualHeading}
          </h1>
          <p>
            {dictionary.windowsServers.virtualDescriptionPrefix}{" "}
            {tenant.display_name}.
          </p>
        </div>
        <span className="read-only-badge">Agent + Hyper-V</span>
      </section>
      <WindowsServerInventory
        servers={inventory.servers}
        serverType="virtual"
        roleLabel={role}
        locale={locale}
        copy={dictionary.windowsServers}
      />
    </ConsoleShell>
  );
}
