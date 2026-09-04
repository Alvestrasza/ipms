import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { HyperVVirtualMachineInventory } from "@/components/hyperv-virtual-machine-inventory";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getHyperVVirtualMachines } from "@/lib/server-hyperv";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.hyperVInventory.title };
}

export default async function HyperVVirtualMachinesPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  const inventory = await getHyperVVirtualMachines(tenant.id);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);
  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="hyper-v-vms">
      <div
        className={`preview-notice ${inventory.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {inventory.available
          ? dictionary.hyperVInventory.liveData
          : dictionary.hyperVInventory.unavailableData}
      </div>
      <section className="page-heading" aria-labelledby="hyperv-vm-heading">
        <div>
          <p className="eyebrow">{dictionary.hyperVInventory.eyebrow}</p>
          <h1 id="hyperv-vm-heading">{dictionary.hyperVInventory.heading}</h1>
          <p>
            {dictionary.hyperVInventory.descriptionPrefix} {tenant.display_name}
            .
          </p>
        </div>
        <span className="read-only-badge">{dictionary.overview.readOnly}</span>
      </section>
      <HyperVVirtualMachineInventory
        copy={dictionary.hyperVInventory}
        virtualMachines={inventory.virtualMachines}
      />
    </ConsoleShell>
  );
}
