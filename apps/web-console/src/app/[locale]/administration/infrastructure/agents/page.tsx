import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { AgentAdministrationTable } from "@/components/agent-administration-table";
import { ConsoleShell } from "@/components/console-shell";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getManagedAgents } from "@/lib/server-agents";
import { getServerSession } from "@/lib/server-auth";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.agentAdministration.title };
}

export default async function AgentAdministrationPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  if (!session.user.is_platform_admin && tenant.role !== "tenant_admin") {
    redirect(`/${locale}`);
  }
  const inventory = await getManagedAgents(tenant.id);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="admin-agents"
    >
      <div
        className={`preview-notice ${inventory.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {inventory.available
          ? dictionary.agentAdministration.liveData
          : dictionary.agentAdministration.unavailableData}
      </div>
      <section
        className="page-heading"
        aria-labelledby="agent-administration-heading"
      >
        <div>
          <p className="eyebrow">{dictionary.agentAdministration.eyebrow}</p>
          <h1 id="agent-administration-heading">
            {dictionary.agentAdministration.heading}
          </h1>
          <p>{dictionary.agentAdministration.description}</p>
        </div>
        <span className="read-only-badge">{tenant.display_name}</span>
      </section>
      <AgentAdministrationTable
        agents={inventory.agents}
        csrfToken={session.csrf_token}
        tenantId={tenant.id}
        locale={locale}
        copy={dictionary.agentAdministration}
        deploymentCopy={dictionary.addSystem}
      />
    </ConsoleShell>
  );
}
