import {
  Activity,
  Boxes,
  Clock3,
  RadioTower,
  RefreshCw,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { type DiscoveryJob, getDashboardData } from "@/lib/server-dashboard";
import { getPhysicalInfrastructure } from "@/lib/server-physical";
import { getWindowsServers } from "@/lib/server-windows";
import { selectedTenant } from "@/lib/tenant-selection";

const summaryIcons = [ServerCog, Boxes, RadioTower, ShieldCheck];
const connectorNames = {
  "hyper-v": "Hyper-V",
  "bmc-api": "BMC API",
};

function formatUtc(value: string | null, locale: "de" | "en", empty: string) {
  if (!value) return empty;
  return new Intl.DateTimeFormat(documentLocale(locale), {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(value));
}

function duration(job: DiscoveryJob) {
  if (!job.started_at || !job.completed_at) return "—";
  const seconds = Math.max(
    0,
    Math.round(
      (new Date(job.completed_at).getTime() -
        new Date(job.started_at).getTime()) /
        1000,
    ),
  );
  return `${seconds} s`;
}

function latestConnectorJob(
  jobs: DiscoveryJob[],
  connector: DiscoveryJob["connector_type"],
) {
  return jobs.find((job) => job.connector_type === connector);
}

function connectorStatus(job: DiscoveryJob | undefined) {
  if (!job) return "unknown" as const;
  if (job.status === "succeeded") return "healthy" as const;
  if (job.status === "failed") return "warning" as const;
  return job.status;
}

export default async function OverviewPage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);

  const [
    dashboard,
    infrastructure,
    physicalWindows,
    virtualWindows,
    physicalWindowsClients,
    virtualWindowsClients,
  ] = await Promise.all([
    getDashboardData(tenant.id),
    getPhysicalInfrastructure(tenant.id),
    getWindowsServers(tenant.id, "physical"),
    getWindowsServers(tenant.id, "virtual"),
    getWindowsServers(tenant.id, "physical", undefined, "client"),
    getWindowsServers(tenant.id, "virtual", undefined, "client"),
  ]);
  if (
    !dashboard.sessionValid ||
    !infrastructure.sessionValid ||
    !physicalWindows.sessionValid ||
    !virtualWindows.sessionValid ||
    !physicalWindowsClients.sessionValid ||
    !virtualWindowsClients.sessionValid
  )
    redirect(`/${locale}/login`);
  const systems = infrastructure.systems;
  const agentStateLabels = {
    "not-enrolled": dictionary.windowsServers.notEnrolled,
    online: dictionary.windowsServers.online,
    stale: dictionary.windowsServers.stale,
    offline: dictionary.windowsServers.offline,
    unknown: dictionary.windowsServers.unknown,
  };
  const managedSystems = [
    ...systems.map((system) => ({
      id: `bmc-${system.id}`,
      name: system.name,
      model: system.model,
      type: dictionary.overview.bmcManagedServer,
      state: system.power_state,
      health: system.health === "ok" ? ("healthy" as const) : system.health,
      href: `/${locale}/physical/bmc/${system.connector_id}` as Route,
    })),
    ...physicalWindows.servers.map((server) => ({
      id: `windows-${server.id}`,
      name: server.fqdn || server.hostname,
      model: server.model,
      type: dictionary.overview.physicalWindowsServer,
      state: agentStateLabels[server.agent_state],
      health: server.health,
      href: `/${locale}/physical/servers/${server.id}` as Route,
    })),
    ...virtualWindows.servers.map((server) => ({
      id: `windows-${server.id}`,
      name: server.fqdn || server.hostname,
      model: server.model,
      type: dictionary.overview.virtualWindowsServer,
      state: agentStateLabels[server.agent_state],
      health: server.health,
      href: `/${locale}/virtual/${server.id}` as Route,
    })),
    ...physicalWindowsClients.servers.map((client) => ({
      id: `windows-client-${client.id}`,
      name: client.fqdn || client.hostname,
      model: client.model,
      type: dictionary.overview.physicalWindowsClient,
      state: agentStateLabels[client.agent_state],
      health: client.health,
      href: `/${locale}/physical/servers/${client.id}` as Route,
    })),
    ...virtualWindowsClients.servers.map((client) => ({
      id: `windows-client-${client.id}`,
      name: client.fqdn || client.hostname,
      model: client.model,
      type: dictionary.overview.virtualWindowsClient,
      state: agentStateLabels[client.agent_state],
      health: client.health,
      href: `/${locale}/virtual/${client.id}` as Route,
    })),
  ];
  const health = {
    healthy: managedSystems.filter((system) => system.health === "healthy")
      .length,
    warning: managedSystems.filter((system) => system.health === "warning")
      .length,
    critical: managedSystems.filter((system) => system.health === "critical")
      .length,
    unknown: managedSystems.filter((system) => system.health === "unknown")
      .length,
  };
  const bmcCount = infrastructure.connectors.filter(
    (connector) => connector.connector_type === "bmc-api",
  ).length;
  const attention = managedSystems.filter(
    (system) => system.health !== "healthy",
  );
  const checkedAt = formatUtc(
    dashboard.checkedAt,
    locale,
    dictionary.overview.notStarted,
  );
  const summaryCards = [
    {
      label: dictionary.overview.physicalSystems,
      value: String(
        systems.length +
          physicalWindows.servers.length +
          physicalWindowsClients.servers.length,
      ),
      detail:
        infrastructure.available && physicalWindows.available
          ? dictionary.overview.inventoryCurrent
          : dictionary.overview.awaitingDiscovery,
    },
    {
      label: dictionary.overview.virtualMachines,
      value: String(
        virtualWindows.servers.length + virtualWindowsClients.servers.length,
      ),
      detail: virtualWindows.available
        ? dictionary.overview.inventoryCurrent
        : dictionary.overview.awaitingDiscovery,
    },
    {
      label: dictionary.overview.bareMetalControllers,
      value: String(bmcCount),
      detail: infrastructure.available
        ? dictionary.overview.enrolledBmcEndpoints
        : dictionary.overview.noConnector,
    },
    {
      label: dictionary.overview.restorePoints,
      value: "0",
      detail: dictionary.overview.noBackupData,
    },
  ];
  const connectors: DiscoveryJob["connector_type"][] = ["hyper-v", "bmc-api"];
  const connectorHealth = (type: DiscoveryJob["connector_type"]) => {
    const matches = infrastructure.connectors.filter(
      (connector) => connector.connector_type === type,
    );
    if (!matches.length)
      return connectorStatus(latestConnectorJob(dashboard.discoveryJobs, type));
    if (matches.some((connector) => connector.health === "critical"))
      return "critical" as const;
    if (matches.some((connector) => connector.health === "warning"))
      return "warning" as const;
    if (matches.every((connector) => connector.health === "healthy"))
      return "healthy" as const;
    return "unknown" as const;
  };

  return (
    <ConsoleShell session={session} tenant={tenant}>
      <section className="page-heading" aria-labelledby="overview-heading">
        <div>
          <p className="eyebrow">{dictionary.overview.managementOverview}</p>
          <h1 id="overview-heading">{dictionary.overview.heading}</h1>
          <p>
            {dictionary.overview.tenantStatusPrefix} {tenant.display_name}.
          </p>
        </div>
        <div className="page-heading__meta">
          <Clock3 aria-hidden="true" size={16} />
          {dictionary.overview.checkedPrefix} {checkedAt}
        </div>
      </section>

      <section
        className="summary-grid"
        aria-label={dictionary.overview.environmentSummary}
      >
        {summaryCards.map((card, index) => {
          const Icon = summaryIcons[index];
          return (
            <article className="summary-card" key={card.label}>
              <div className="summary-card__icon">
                <Icon aria-hidden="true" size={21} />
              </div>
              <div>
                <p>{card.label}</p>
                <strong>{card.value}</strong>
                <span className="summary-card__detail">{card.detail}</span>
              </div>
            </article>
          );
        })}
      </section>

      <div className="dashboard-grid">
        <section className="panel panel--wide" aria-labelledby="health-heading">
          <div className="panel__header">
            <div>
              <p className="eyebrow">{dictionary.overview.environmentHealth}</p>
              <h2 id="health-heading">{dictionary.overview.managedObjects}</h2>
            </div>
            <span className="panel__metric">
              <strong>{managedSystems.length}</strong>{" "}
              {dictionary.overview.managedObjects}
            </span>
          </div>
          <div
            className={
              managedSystems.length
                ? "health-bar"
                : "health-bar health-bar--empty"
            }
            role="img"
            aria-label={dictionary.overview.noObjects}
          >
            {managedSystems.length ? (
              <>
                <span
                  className="health-bar__healthy"
                  style={{
                    width: `${(health.healthy / managedSystems.length) * 100}%`,
                  }}
                />
                <span
                  className="health-bar__warning"
                  style={{
                    width: `${(health.warning / managedSystems.length) * 100}%`,
                  }}
                />
                <span
                  className="health-bar__critical"
                  style={{
                    width: `${(health.critical / managedSystems.length) * 100}%`,
                  }}
                />
                <span
                  className="health-bar__unknown"
                  style={{
                    width: `${(health.unknown / managedSystems.length) * 100}%`,
                  }}
                />
              </>
            ) : null}
          </div>
          <div className="health-legend">
            <span>
              <i className="legend-dot legend-dot--healthy" />
              {dictionary.overview.healthy} <strong>{health.healthy}</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--warning" />
              {dictionary.overview.warning} <strong>{health.warning}</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--critical" />
              {dictionary.overview.critical} <strong>{health.critical}</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--unknown" />
              {dictionary.overview.unknown} <strong>{health.unknown}</strong>
            </span>
          </div>
        </section>

        <section
          className="panel connector-card"
          aria-labelledby="connector-heading"
        >
          <div className="panel__header">
            <div>
              <p className="eyebrow">{dictionary.overview.connectorActivity}</p>
              <h2 id="connector-heading">
                {dictionary.overview.discoveryServices}
              </h2>
            </div>
            <Activity aria-hidden="true" size={20} />
          </div>
          {connectors.map((connector) => {
            const status = connectorHealth(connector);
            return (
              <div className="connector-row" key={connector}>
                <span>
                  <i
                    className={`connector-mark ${connector === "bmc-api" ? "connector-mark--ilo" : ""}`}
                  >
                    {connector === "hyper-v" ? "H" : "i"}
                  </i>
                  <strong>{connectorNames[connector]}</strong>
                </span>
                <StatusPill status={status} label={dictionary.status[status]} />
              </div>
            );
          })}
          <p className="connector-footnote">
            {dictionary.overview.connectorFootnote}
          </p>
        </section>
      </div>

      <section
        className="panel inventory-panel"
        aria-labelledby="attention-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{dictionary.overview.operationalFocus}</p>
            <h2 id="attention-heading">
              {dictionary.overview.attentionHeading}
            </h2>
          </div>
        </div>
        {attention.length ? (
          <div className="table-scroll">
            <table className="inventory-table">
              <thead>
                <tr>
                  <th>{dictionary.physical.name}</th>
                  <th>{dictionary.overview.systemType}</th>
                  <th>{dictionary.physical.model}</th>
                  <th>{dictionary.overview.state}</th>
                  <th>{dictionary.physical.health}</th>
                </tr>
              </thead>
              <tbody>
                {attention.map((system) => {
                  return (
                    <tr key={system.id}>
                      <td>
                        <Link href={system.href}>
                          <strong>{system.name}</strong>
                        </Link>
                      </td>
                      <td>{system.type}</td>
                      <td>{system.model || "—"}</td>
                      <td>{system.state || "—"}</td>
                      <td>
                        <StatusPill
                          status={system.health}
                          label={dictionary.status[system.health]}
                        />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <ServerCog aria-hidden="true" size={25} />
            <strong>
              {managedSystems.length
                ? dictionary.overview.noAttention
                : dictionary.overview.noInventory}
            </strong>
            <span>
              {managedSystems.length
                ? dictionary.overview.noAttentionHint
                : dictionary.overview.inventoryHint}
            </span>
          </div>
        )}
      </section>

      <section className="panel jobs-panel" aria-labelledby="jobs-heading">
        <div className="panel__header">
          <div>
            <p className="eyebrow">{dictionary.overview.readOnlyOperations}</p>
            <h2 id="jobs-heading">{dictionary.overview.recentJobs}</h2>
          </div>
          <span className="read-only-badge">
            {dictionary.overview.readOnly}
          </span>
        </div>
        {dashboard.discoveryJobs.length ? (
          <div className="job-list">
            {dashboard.discoveryJobs.map((job) => (
              <article className="job-row" key={job.id}>
                <div className="job-row__icon">
                  <RefreshCw aria-hidden="true" size={17} />
                </div>
                <div>
                  <strong>{connectorNames[job.connector_type]}</strong>
                  <span>{job.requested_by}</span>
                </div>
                <code>{job.id.slice(0, 8)}</code>
                <span>
                  {formatUtc(
                    job.started_at ?? job.created_at,
                    locale,
                    dictionary.overview.notStarted,
                  )}
                </span>
                <span>{duration(job)}</span>
                <StatusPill
                  status={job.status}
                  label={dictionary.status[job.status]}
                />
              </article>
            ))}
          </div>
        ) : (
          <div className="empty-state empty-state--compact">
            <RefreshCw aria-hidden="true" size={22} />
            <strong>
              {dashboard.jobsAvailable
                ? dictionary.overview.noJobs
                : dictionary.overview.jobsUnavailable}
            </strong>
            <span>
              {dashboard.jobsAvailable
                ? dictionary.overview.firstRunHint
                : dictionary.overview.jobsUnavailableHint}
            </span>
          </div>
        )}
      </section>
    </ConsoleShell>
  );
}
