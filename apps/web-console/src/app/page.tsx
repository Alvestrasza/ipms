import {
  Activity,
  Boxes,
  Clock3,
  Network,
  RefreshCw,
  ServerCog,
  ShieldCheck,
} from "lucide-react";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import { ConsoleShell } from "@/components/console-shell";
import { StatusPill } from "@/components/status-pill";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { type DiscoveryJob, getDashboardData } from "@/lib/server-dashboard";
import { selectedTenant } from "@/lib/tenant-selection";

const summaryIcons = [ServerCog, Boxes, Network, ShieldCheck];
const connectorNames = {
  "hyper-v": "Hyper-V",
  "ilo-redfish": "iLO Redfish",
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
  if (!session?.authenticated) redirect("/login");
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect("/login?reason=no-tenant");

  const dashboard = await getDashboardData(tenant.id);
  if (!dashboard.sessionValid) redirect("/login");
  const checkedAt = formatUtc(
    dashboard.checkedAt,
    locale,
    dictionary.overview.notStarted,
  );
  const summaryCards = [
    {
      label: dictionary.overview.physicalSystems,
      value: "0",
      detail: dictionary.overview.awaitingDiscovery,
    },
    {
      label: dictionary.overview.virtualMachines,
      value: "0",
      detail: dictionary.overview.awaitingDiscovery,
    },
    {
      label: dictionary.overview.networkDevices,
      value: "0",
      detail: dictionary.overview.noConnector,
    },
    {
      label: dictionary.overview.restorePoints,
      value: "0",
      detail: dictionary.overview.noBackupData,
    },
  ];
  const connectors: DiscoveryJob["connector_type"][] = [
    "hyper-v",
    "ilo-redfish",
  ];

  return (
    <ConsoleShell session={session} tenant={tenant}>
      <div
        className={`preview-notice ${dashboard.controlPlaneReady ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {dashboard.controlPlaneReady
          ? dictionary.overview.liveData
          : dictionary.overview.unavailableData}
      </div>

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
            <span className="panel__metric panel__metric--empty">
              <strong>—</strong> {dictionary.overview.noData}
            </span>
          </div>
          <div
            className="health-bar health-bar--empty"
            role="img"
            aria-label={dictionary.overview.noObjects}
          />
          <div className="health-legend">
            <span>
              <i className="legend-dot legend-dot--healthy" />
              {dictionary.overview.healthy} <strong>0</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--warning" />
              {dictionary.overview.warning} <strong>0</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--critical" />
              {dictionary.overview.critical} <strong>0</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--unknown" />
              {dictionary.overview.unknown} <strong>0</strong>
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
            const latest = latestConnectorJob(
              dashboard.discoveryJobs,
              connector,
            );
            return (
              <div className="connector-row" key={connector}>
                <span>
                  <i
                    className={`connector-mark ${connector === "ilo-redfish" ? "connector-mark--ilo" : ""}`}
                  >
                    {connector === "hyper-v" ? "H" : "i"}
                  </i>
                  <strong>{connectorNames[connector]}</strong>
                </span>
                <StatusPill
                  status={connectorStatus(latest)}
                  label={dictionary.status[connectorStatus(latest)]}
                />
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
          <button className="outline-button" type="button" disabled>
            <RefreshCw aria-hidden="true" size={15} />
            {dictionary.overview.runDiscovery}
          </button>
        </div>
        <div className="empty-state">
          <ServerCog aria-hidden="true" size={25} />
          <strong>{dictionary.overview.noInventory}</strong>
          <span>{dictionary.overview.inventoryHint}</span>
        </div>
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
