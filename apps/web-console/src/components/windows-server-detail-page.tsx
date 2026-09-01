import {
  ArrowLeft,
  Boxes,
  Cpu,
  MonitorCog,
  Network,
  Server,
  ShieldCheck,
} from "lucide-react";
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { WindowsServerTelemetry } from "@/components/windows-server-telemetry";
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

function formatLinkSpeed(bitsPerSecond: number) {
  if (bitsPerSecond >= 1_000_000_000) {
    return `${(bitsPerSecond / 1_000_000_000).toFixed(1)} Gbit/s`;
  }
  if (bitsPerSecond >= 1_000_000) {
    return `${(bitsPerSecond / 1_000_000).toFixed(1)} Mbit/s`;
  }
  return bitsPerSecond > 0 ? `${bitsPerSecond} bit/s` : "—";
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
  const installedRolesFeatures = server.installed_roles_features ?? [];
  const roleFeatureTypeLabels = {
    role: copy.roleType,
    "role-service": copy.roleServiceType,
    feature: copy.featureType,
  };

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
        className="panel network-inventory"
        aria-labelledby="roles-features-heading"
      >
        <div className="bmc-identity__title">
          <span className="connector-mark">
            <Boxes aria-hidden="true" size={18} />
          </span>
          <div>
            <strong id="roles-features-heading">{copy.rolesFeatures}</strong>
            <small>{copy.rolesFeaturesHint}</small>
          </div>
        </div>
        {server.installed_roles_features_status === "unavailable" ? (
          <p className="network-inventory__empty">
            {copy.rolesFeaturesUnavailable}
          </p>
        ) : server.installed_roles_features_status !== "collected" ? (
          <p className="network-inventory__empty">
            {copy.rolesFeaturesNotReported}
          </p>
        ) : installedRolesFeatures.length === 0 ? (
          <p className="network-inventory__empty">{copy.noRolesFeatures}</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{copy.roleFeatureName}</th>
                  <th>{copy.roleFeatureType}</th>
                  <th>{copy.roleFeatureTechnicalName}</th>
                  <th>{copy.roleFeatureParent}</th>
                </tr>
              </thead>
              <tbody>
                {installedRolesFeatures.map((feature) => (
                  <tr key={feature.name}>
                    <td>
                      <strong>{feature.display_name}</strong>
                    </td>
                    <td>{roleFeatureTypeLabels[feature.type]}</td>
                    <td>
                      <code>{feature.name}</code>
                    </td>
                    <td>{display(feature.parent_name)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <WindowsServerTelemetry
        serverId={server.id}
        tenantId={tenant.id}
        locale={locale}
        initialTelemetry={server.latest_telemetry ?? null}
        copy={{
          heading: copy.telemetryHeading,
          hint: copy.telemetryHint,
          refresh: copy.telemetryRefresh,
          unavailable: copy.telemetryUnavailable,
          cpu: copy.telemetryCpu,
          memory: copy.telemetryMemory,
          used: copy.telemetryUsed,
          available: copy.telemetryAvailable,
          volumes: copy.telemetryVolumes,
          volume: copy.telemetryVolume,
          capacity: copy.telemetryCapacity,
          free: copy.telemetryFree,
          observed: copy.telemetryObserved,
        }}
      />

      <section
        className="panel network-inventory"
        aria-labelledby="network-heading"
      >
        <div className="bmc-identity__title">
          <span className="connector-mark">
            <Network aria-hidden="true" size={18} />
          </span>
          <div>
            <strong id="network-heading">{copy.network}</strong>
            <small>{copy.networkHint}</small>
          </div>
        </div>
        {(server.network_interfaces ?? []).length === 0 ? (
          <p className="network-inventory__empty">{copy.noNetworkInterfaces}</p>
        ) : (
          <div className="network-inventory__cards">
            {(server.network_interfaces ?? []).map((networkInterface) => {
              const statusLabels = {
                up: copy.interfaceUp,
                down: copy.interfaceDown,
                testing: copy.interfaceTesting,
                dormant: copy.interfaceDormant,
                "not-present": copy.interfaceNotPresent,
                "lower-layer-down": copy.interfaceLowerLayerDown,
                unknown: copy.unknown,
              };
              return (
                <article key={networkInterface.interface_id}>
                  <header>
                    <div>
                      <strong>
                        {networkInterface.name || networkInterface.description}
                      </strong>
                      <small>{networkInterface.description}</small>
                    </div>
                    <StatusPill
                      status={
                        networkInterface.status === "up"
                          ? "healthy"
                          : networkInterface.status === "down"
                            ? "critical"
                            : "unknown"
                      }
                      label={statusLabels[networkInterface.status]}
                    />
                  </header>
                  <dl>
                    <div>
                      <dt>{copy.macAddress}</dt>
                      <dd>{display(networkInterface.mac_address)}</dd>
                    </div>
                    <div>
                      <dt>{copy.linkSpeed}</dt>
                      <dd>
                        {formatLinkSpeed(
                          Math.max(
                            networkInterface.receive_link_speed_bps,
                            networkInterface.transmit_link_speed_bps,
                          ),
                        )}
                      </dd>
                    </div>
                    <div>
                      <dt>{copy.dhcp}</dt>
                      <dd>
                        {networkInterface.dhcp_enabled
                          ? copy.enabled
                          : copy.disabled}
                      </dd>
                    </div>
                    <div>
                      <dt>{copy.dnsSuffix}</dt>
                      <dd>{display(networkInterface.dns_suffix)}</dd>
                    </div>
                    <div>
                      <dt>{copy.ipAddresses}</dt>
                      <dd>
                        {networkInterface.addresses
                          .map(
                            (address) =>
                              `${address.address}/${address.prefix_length}`,
                          )
                          .join(", ") || "—"}
                      </dd>
                    </div>
                    <div>
                      <dt>{copy.gateways}</dt>
                      <dd>{networkInterface.gateways.join(", ") || "—"}</dd>
                    </div>
                    <div>
                      <dt>{copy.dnsServers}</dt>
                      <dd>{networkInterface.dns_servers.join(", ") || "—"}</dd>
                    </div>
                  </dl>
                </article>
              );
            })}
          </div>
        )}
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
