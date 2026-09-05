import { notFound, redirect } from "next/navigation";

import { HyperVConsoleWindow } from "@/components/hyperv-console-window";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import { getServerSession } from "@/lib/server-auth";
import { getHyperVVirtualMachines } from "@/lib/server-hyperv";

export default async function ConsolePage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ tenant?: string }>;
}) {
  const [locale, session, { id }, query] = await Promise.all([
    resolveLocale(),
    getServerSession(),
    params,
    searchParams,
  ]);
  if (!session?.authenticated) redirect(`/${locale}/login`);
  // Bind the detached window to its original tenant even when the main portal
  // changes the selected-tenant cookie. Membership is always revalidated.
  const tenant = session.tenants.find((item) => item.id === query.tenant);
  if (!tenant || !hasPermission(tenant, "virtual_machines.console.control"))
    notFound();
  const inventory = await getHyperVVirtualMachines(tenant.id);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);
  const vm = inventory.virtualMachines.find((item) => item.id === id);
  if (!vm) notFound();
  return (
    <HyperVConsoleWindow
      vm={vm}
      tenantId={tenant.id}
      csrfToken={session.csrf_token}
      serviceAccountsHref={`/${locale}/administration/service-accounts?tenant=${encodeURIComponent(tenant.id)}`}
      copy={getDictionary(locale).hyperVInventory.console}
    />
  );
}
