import { Cpu, MemoryStick, ServerCog, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import {
  getPhysicalInfrastructure,
  type PhysicalSystem,
} from "@/lib/server-physical";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.physical.title };
}

function formatMemory(bytes: number | null, empty: string) {
  if (bytes === null) return empty;
  return `${Math.round(bytes / 1024 ** 3)} GiB`;
}

function formatDate(value: string, locale: "de" | "en") {
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(value));
}

function systemStatus(system: PhysicalSystem) {
  return system.health === "ok" ? "healthy" : system.health;
}

export default async function PhysicalInfrastructurePage() {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);

  const infrastructure = await getPhysicalInfrastructure(tenant.id);
  if (!infrastructure.sessionValid) redirect(`/${locale}/login`);
  const healthy = infrastructure.systems.filter(
    (system) => system.health === "ok",
  ).length;
  const bmcConnectors = infrastructure.connectors.filter(
    (connector) => connector.connector_type === "bmc-api",
  );

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="physical">
      <div
        className={`preview-notice ${infrastructure.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {infrastructure.available
          ? dictionary.physical.liveData
          : dictionary.physical.unavailableData}
      </div>

      <section className="page-heading" aria-labelledby="physical-heading">
        <div>
          <p className="eyebrow">{dictionary.physical.eyebrow}</p>
          <h1 id="physical-heading">{dictionary.physical.heading}</h1>
          <p>
            {dictionary.physical.descriptionPrefix} {tenant.display_name}.
          </p>
        </div>
        <span className="read-only-badge">{dictionary.overview.readOnly}</span>
      </section>

      <section
        className="summary-grid"
        aria-label={dictionary.physical.summary}
      >
        <article className="summary-card">
          <div className="summary-card__icon">
            <ServerCog aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{dictionary.physical.systems}</p>
            <strong>{infrastructure.systems.length}</strong>
            <span className="summary-card__detail">
              {dictionary.physical.discovered}
            </span>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <ShieldCheck aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{dictionary.physical.healthy}</p>
            <strong>{healthy}</strong>
            <span className="summary-card__detail">
              {dictionary.physical.reportedHealthy}
            </span>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Cpu aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{dictionary.physical.processors}</p>
            <strong>
              {infrastructure.systems.reduce(
                (total, system) => total + (system.processor_count ?? 0),
                0,
              )}
            </strong>
            <span className="summary-card__detail">
              {dictionary.physical.installedPackages}
            </span>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <MemoryStick aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{dictionary.physical.iloConnectors}</p>
            <strong>{bmcConnectors.length}</strong>
            <span className="summary-card__detail">
              {dictionary.physical.enrolledEndpoints}
            </span>
          </div>
        </article>
      </section>

      <section
        className="panel inventory-panel"
        aria-labelledby="systems-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{dictionary.physical.inventory}</p>
            <h2 id="systems-heading">{dictionary.physical.managedSystems}</h2>
          </div>
        </div>
        {infrastructure.systems.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{dictionary.physical.name}</th>
                  <th>{dictionary.physical.model}</th>
                  <th>{dictionary.physical.serial}</th>
                  <th>{dictionary.physical.power}</th>
                  <th>{dictionary.physical.health}</th>
                  <th>{dictionary.physical.cpu}</th>
                  <th>{dictionary.physical.memory}</th>
                  <th>{dictionary.physical.firmware}</th>
                  <th>{dictionary.physical.discoveredAt}</th>
                </tr>
              </thead>
              <tbody>
                {infrastructure.systems.map((system) => {
                  const status = systemStatus(system);
                  return (
                    <tr key={system.id}>
                      <td>
                        <strong>{system.name}</strong>
                      </td>
                      <td>{system.model || dictionary.physical.unknown}</td>
                      <td>
                        <code>{system.serial_number || "—"}</code>
                      </td>
                      <td>
                        {system.power_state || dictionary.physical.unknown}
                      </td>
                      <td>
                        <StatusPill
                          status={status}
                          label={dictionary.status[status]}
                        />
                      </td>
                      <td>{system.processor_count ?? "—"}</td>
                      <td>{formatMemory(system.memory_bytes, "—")}</td>
                      <td>{system.bmc_firmware_version || "—"}</td>
                      <td>{formatDate(system.discovered_at, locale)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <ServerCog aria-hidden="true" size={25} />
            <strong>{dictionary.physical.noSystems}</strong>
            <span>{dictionary.physical.noSystemsHint}</span>
          </div>
        )}
      </section>
    </ConsoleShell>
  );
}
