import { ArrowLeft, Cpu, MonitorCog, Server, ShieldCheck } from "lucide-react";
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getWindowsServer } from "@/lib/server-windows";
import { selectedTenant } from "@/lib/tenant-selection";

function formatMemory(bytes: number | null) {
  if (bytes === null) return "—";
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}

function formatDate(value: string | null, locale: "de" | "en") {
  if (!value) return "—";
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}

function display(value: string | null | undefined) {
  return value || "—";
}

export async function WindowsServerDetailPage({
  id,
  expectedType,
}: {
  id: string;
  expectedType: "physical" | "virtual";
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const copy = dictionary.windowsServerDetail;
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);

  const inventory = await getWindowsServer(tenant.id, id);
  if (!inventory.sessionValid) redirect(`/${locale}/login`);
  if (inventory.notFound) notFound();

  const backHref =
    expectedType === "physical"
      ? (`/${locale}/physical/servers` as Route)
      : (`/${locale}/virtual` as Route);
  const activeSection =
    expectedType === "physical" ? "physical-servers" : "virtual";

  if (!inventory.available || !inventory.server) {
    return (
      <ConsoleShell
        session={session}
        tenant={tenant}
        activeSection={activeSection}
      >
        <Link className="detail-back-link" href={backHref}>
          <ArrowLeft aria-hidden="true" size={16} />
          {expectedType === "physical" ? copy.backPhysical : copy.backVirtual}
        </Link>
        <section className="panel empty-state">
          <Server aria-hidden="true" size={28} />
          <strong>{copy.unavailable}</strong>
          <span>{dictionary.windowsServers.unavailableData}</span>
        </section>
      </ConsoleShell>
    );
  }

  const server = inventory.server;
  if (server.server_type !== expectedType) {
    const target =
      server.server_type === "virtual"
        ? `/${locale}/virtual/${server.id}`
        : server.server_type === "physical"
          ? `/${locale}/physical/servers/${server.id}`
          : null;
    if (target) redirect(target as Route);
    notFound();
  }

  const agentLabels = {
    "not-enrolled": dictionary.windowsServers.notEnrolled,
    online: dictionary.windowsServers.online,
    stale: dictionary.windowsServers.stale,
    offline: dictionary.windowsServers.offline,
    unknown: dictionary.windowsServers.unknown,
  };
  const typeLabels = {
    physical: copy.physical,
    virtual: copy.virtual,
    unknown: copy.unknown,
  };
  const sourceLabel =
    server.inventory_source === "agent"
      ? dictionary.windowsServers.sourceAgent
      : dictionary.windowsServers.sourceHyperV;

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection={activeSection}
    >
      <Link className="detail-back-link" href={backHref}>
        <ArrowLeft aria-hidden="true" size={16} />
        {expectedType === "physical" ? copy.backPhysical : copy.backVirtual}
      </Link>

      <section className="page-heading" aria-labelledby="system-detail-heading">
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1 id="system-detail-heading">{server.fqdn || server.hostname}</h1>
          <p>
            {copy.description} {tenant.display_name}.
          </p>
        </div>
        <div className="page-heading__meta">
          <StatusPill
            status={server.health}
            label={dictionary.status[server.health]}
          />
          <span className="read-only-badge">
            {dictionary.overview.readOnly}
          </span>
        </div>
      </section>

      <section
        className="panel bmc-identity"
        aria-labelledby="identity-heading"
      >
        <div className="bmc-identity__title">
          <span className="connector-mark">
            <Server aria-hidden="true" size={18} />
          </span>
          <div>
            <strong id="identity-heading">{copy.identity}</strong>
            <small>{copy.identityHint}</small>
          </div>
        </div>
        <dl className="bmc-identity__grid">
          <div>
            <dt>{copy.hostname}</dt>
            <dd>{server.hostname}</dd>
          </div>
          <div>
            <dt>{copy.fqdn}</dt>
            <dd>{display(server.fqdn)}</dd>
          </div>
          <div>
            <dt>{copy.domain}</dt>
            <dd>{display(server.domain_name)}</dd>
          </div>
          <div>
            <dt>{copy.classification}</dt>
            <dd>{typeLabels[server.server_type]}</dd>
          </div>
        </dl>
      </section>

      <section
        className="panel bmc-identity"
        aria-labelledby="platform-heading"
      >
        <div className="bmc-identity__title">
          <span className="connector-mark">
            <MonitorCog aria-hidden="true" size={18} />
          </span>
          <div>
            <strong id="platform-heading">{copy.platform}</strong>
            <small>{copy.platformHint}</small>
          </div>
        </div>
        <dl className="bmc-identity__grid">
          <div>
            <dt>{copy.operatingSystem}</dt>
            <dd>{display(server.operating_system)}</dd>
          </div>
          <div>
            <dt>{copy.osVersion}</dt>
            <dd>{display(server.os_version)}</dd>
          </div>
          <div>
            <dt>{copy.osBuild}</dt>
            <dd>{display(server.os_build)}</dd>
          </div>
          <div>
            <dt>{copy.architecture}</dt>
            <dd>{display(server.architecture)}</dd>
          </div>
          <div>
            <dt>{copy.manufacturer}</dt>
            <dd>{display(server.manufacturer)}</dd>
          </div>
          <div>
            <dt>{copy.model}</dt>
            <dd>{display(server.model)}</dd>
          </div>
          <div>
            <dt>{copy.cluster}</dt>
            <dd>{display(server.cluster_name)}</dd>
          </div>
          <div>
            <dt>{copy.hypervisorHost}</dt>
            <dd>{display(server.hypervisor_host)}</dd>
          </div>
        </dl>
      </section>

      <section
        className="panel bmc-identity"
        aria-labelledby="resources-heading"
      >
        <div className="bmc-identity__title">
          <span className="connector-mark">
            <Cpu aria-hidden="true" size={18} />
          </span>
          <div>
            <strong id="resources-heading">{copy.resources}</strong>
            <small>{copy.resourcesHint}</small>
          </div>
        </div>
        <dl className="bmc-identity__grid">
          <div>
            <dt>{copy.logicalProcessors}</dt>
            <dd>{server.logical_processors ?? "—"}</dd>
          </div>
          <div>
            <dt>{copy.memory}</dt>
            <dd>{formatMemory(server.memory_bytes)}</dd>
          </div>
        </dl>
      </section>

      <section
        className="panel bmc-identity"
        aria-labelledby="management-heading"
      >
        <div className="bmc-identity__title">
          <span className="connector-mark">
            <ShieldCheck aria-hidden="true" size={18} />
          </span>
          <div>
            <strong id="management-heading">{copy.management}</strong>
            <small>{copy.managementHint}</small>
          </div>
        </div>
        <dl className="bmc-identity__grid">
          <div>
            <dt>{copy.agentStatus}</dt>
            <dd>{agentLabels[server.agent_state]}</dd>
          </div>
          <div>
            <dt>{copy.agentVersion}</dt>
            <dd>{display(server.agent_version)}</dd>
          </div>
          <div>
            <dt>{copy.inventorySource}</dt>
            <dd>{sourceLabel}</dd>
          </div>
          <div>
            <dt>{copy.managementPacks}</dt>
            <dd>{server.management_packs.join(", ") || copy.noPacks}</dd>
          </div>
          <div>
            <dt>{copy.lastSeen}</dt>
            <dd>{formatDate(server.last_seen_at, locale)}</dd>
          </div>
          <div>
            <dt>{copy.discovered}</dt>
            <dd>{formatDate(server.discovered_at, locale)}</dd>
          </div>
        </dl>
      </section>
    </ConsoleShell>
  );
}
