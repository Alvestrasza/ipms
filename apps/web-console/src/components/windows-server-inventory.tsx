import { Cpu, HardDrive, MemoryStick, Server, ShieldCheck } from "lucide-react";

import { StatusPill } from "@/components/status-pill";
import { documentLocale } from "@/i18n/config";
import type { WindowsServer } from "@/lib/server-windows";

type Copy = {
  summary: string;
  total: string;
  inventoried: string;
  healthy: string;
  reportedHealthy: string;
  agentOnline: string;
  reportingAgents: string;
  totalMemory: string;
  reportedCapacity: string;
  inventory: string;
  managedPhysicalHeading: string;
  managedVirtualHeading: string;
  name: string;
  operatingSystem: string;
  health: string;
  agent: string;
  cpu: string;
  memory: string;
  hardware: string;
  placement: string;
  source: string;
  lastSeen: string;
  unknown: string;
  notEnrolled: string;
  online: string;
  stale: string;
  offline: string;
  sourceAgent: string;
  sourceHyperV: string;
  noPhysical: string;
  noVirtual: string;
  noPhysicalHint: string;
  noVirtualHint: string;
  statusHealthy: string;
  statusWarning: string;
  statusCritical: string;
  statusUnknown: string;
};

function formatMemory(bytes: number | null, empty: string) {
  if (bytes === null) return empty;
  return `${Math.round(bytes / 1024 ** 3)} GiB`;
}

function formatDate(value: string | null, locale: "de" | "en", empty: string) {
  if (!value) return empty;
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

export function WindowsServerInventory({
  servers,
  serverType,
  locale,
  copy,
}: {
  servers: WindowsServer[];
  serverType: "physical" | "virtual";
  locale: "de" | "en";
  copy: Copy;
}) {
  const healthy = servers.filter(
    (server) => server.health === "healthy",
  ).length;
  const online = servers.filter(
    (server) => server.agent_state === "online",
  ).length;
  const memoryBytes = servers.reduce(
    (total, server) => total + (server.memory_bytes ?? 0),
    0,
  );
  const healthLabels = {
    healthy: copy.statusHealthy,
    warning: copy.statusWarning,
    critical: copy.statusCritical,
    unknown: copy.statusUnknown,
  };
  const agentLabels = {
    "not-enrolled": copy.notEnrolled,
    online: copy.online,
    stale: copy.stale,
    offline: copy.offline,
    unknown: copy.unknown,
  };

  return (
    <>
      <section className="summary-grid" aria-label={copy.summary}>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Server aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.total}</p>
            <strong>{servers.length}</strong>
            <span className="summary-card__detail">{copy.inventoried}</span>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <ShieldCheck aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.healthy}</p>
            <strong>{healthy}</strong>
            <span className="summary-card__detail">{copy.reportedHealthy}</span>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Cpu aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.agentOnline}</p>
            <strong>{online}</strong>
            <span className="summary-card__detail">{copy.reportingAgents}</span>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <MemoryStick aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.totalMemory}</p>
            <strong>{formatMemory(memoryBytes || null, "—")}</strong>
            <span className="summary-card__detail">
              {copy.reportedCapacity}
            </span>
          </div>
        </article>
      </section>

      <section
        className="panel inventory-panel"
        aria-labelledby="windows-inventory-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{copy.inventory}</p>
            <h2 id="windows-inventory-heading">
              {serverType === "physical"
                ? copy.managedPhysicalHeading
                : copy.managedVirtualHeading}
            </h2>
          </div>
          <span className="panel__metric">
            <strong>{servers.length}</strong>
          </span>
        </div>
        {servers.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{copy.name}</th>
                  <th>{copy.operatingSystem}</th>
                  <th>{copy.health}</th>
                  <th>{copy.agent}</th>
                  <th>{copy.cpu}</th>
                  <th>{copy.memory}</th>
                  <th>
                    {serverType === "physical" ? copy.hardware : copy.placement}
                  </th>
                  <th>{copy.source}</th>
                  <th>{copy.lastSeen}</th>
                </tr>
              </thead>
              <tbody>
                {servers.map((server) => {
                  const location =
                    serverType === "physical"
                      ? [server.manufacturer, server.model]
                          .filter(Boolean)
                          .join(" ")
                      : [server.cluster_name, server.hypervisor_host]
                          .filter(Boolean)
                          .join(" · ");
                  return (
                    <tr key={server.id}>
                      <td>
                        <strong>{server.fqdn || server.hostname}</strong>
                        {server.domain_name ? (
                          <small>{server.domain_name}</small>
                        ) : null}
                      </td>
                      <td>
                        {server.operating_system || copy.unknown}
                        {server.os_version ? (
                          <small>{server.os_version}</small>
                        ) : null}
                      </td>
                      <td>
                        <StatusPill
                          status={server.health}
                          label={healthLabels[server.health]}
                        />
                      </td>
                      <td>
                        {agentLabels[server.agent_state]}
                        {server.agent_version ? (
                          <small>v{server.agent_version}</small>
                        ) : null}
                      </td>
                      <td>{server.logical_processors ?? "—"}</td>
                      <td>{formatMemory(server.memory_bytes, "—")}</td>
                      <td>{location || "—"}</td>
                      <td>
                        {server.inventory_source === "agent"
                          ? copy.sourceAgent
                          : copy.sourceHyperV}
                      </td>
                      <td>{formatDate(server.last_seen_at, locale, "—")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <HardDrive aria-hidden="true" size={25} />
            <strong>
              {serverType === "physical" ? copy.noPhysical : copy.noVirtual}
            </strong>
            <span>
              {serverType === "physical"
                ? copy.noPhysicalHint
                : copy.noVirtualHint}
            </span>
          </div>
        )}
      </section>
    </>
  );
}
