import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getLinuxSystems } from "@/lib/server-linux";
import { selectedTenant } from "@/lib/tenant-selection";
import { ConsoleShell } from "./console-shell";
import { LinuxSystemInventory } from "./linux-system-inventory";

export async function LinuxSystemsPage({
  systemType,
}: {
  systemType: "physical" | "virtual";
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  const inventory = await getLinuxSystems(tenant.id, systemType);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);
  const copy = dictionary.linuxSystems;
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection={
        systemType === "physical" ? "physical-linux" : "virtual-linux"
      }
    >
      <div
        className={`preview-notice ${inventory.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {inventory.available ? copy.liveData : copy.unavailableData}
      </div>
      <section className="page-heading">
        <div>
          <p className="eyebrow">Linux</p>
          <h1>
            {systemType === "physical"
              ? copy.physicalHeading
              : copy.virtualHeading}
          </h1>
          <p>
            {copy.description} {tenant.display_name}.
          </p>
        </div>
        <span className="read-only-badge">Agent</span>
      </section>
      <LinuxSystemInventory
        systems={inventory.systems}
        systemType={systemType}
        locale={locale}
        copy={copy}
      />
    </ConsoleShell>
  );
}
