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
import { getServerSession } from "@/lib/server-auth";
import { type DiscoveryJob, getDashboardData } from "@/lib/server-dashboard";
import { selectedTenant } from "@/lib/tenant-selection";

const summaryCards = [
  { label: "Physical systems", value: "0", detail: "Awaiting discovery" },
  { label: "Virtual machines", value: "0", detail: "Awaiting discovery" },
  { label: "Network devices", value: "0", detail: "No connector configured" },
  { label: "Restore points", value: "0", detail: "No backup data available" },
];
const summaryIcons = [ServerCog, Boxes, Network, ShieldCheck];
const connectorNames = {
  "hyper-v": "Hyper-V",
  "ilo-redfish": "iLO Redfish",
};

function formatUtc(value: string | null) {
  if (!value) return "Not started";
  return new Intl.DateTimeFormat("en-GB", {
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
  const session = await getServerSession();
  if (!session?.authenticated) redirect("/login");
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect("/login?reason=no-tenant");

  const dashboard = await getDashboardData(tenant.id);
  if (!dashboard.sessionValid) redirect("/login");
  const checkedAt = formatUtc(dashboard.checkedAt);
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
          ? "Live Control Plane data — no managed infrastructure has been discovered yet."
          : "Control Plane data is currently unavailable. No cached infrastructure values are shown."}
      </div>

      <section className="page-heading" aria-labelledby="overview-heading">
        <div>
          <p className="eyebrow">Management overview</p>
          <h1 id="overview-heading">Infrastructure at a glance</h1>
          <p>Read-only operational status for {tenant.display_name}.</p>
        </div>
        <div className="page-heading__meta">
          <Clock3 aria-hidden="true" size={16} />
          Control Plane checked {checkedAt}
        </div>
      </section>

      <section className="summary-grid" aria-label="Environment summary">
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
              <p className="eyebrow">Environment health</p>
              <h2 id="health-heading">Managed objects</h2>
            </div>
            <span className="panel__metric panel__metric--empty">
              <strong>—</strong> no data
            </span>
          </div>
          <div
            className="health-bar health-bar--empty"
            role="img"
            aria-label="No managed objects have been discovered"
          />
          <div className="health-legend">
            <span>
              <i className="legend-dot legend-dot--healthy" /> Healthy{" "}
              <strong>0</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--warning" /> Warning{" "}
              <strong>0</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--critical" /> Critical{" "}
              <strong>0</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--unknown" /> Unknown{" "}
              <strong>0</strong>
            </span>
          </div>
        </section>

        <section
          className="panel connector-card"
          aria-labelledby="connector-heading"
        >
          <div className="panel__header">
            <div>
              <p className="eyebrow">Connector activity</p>
              <h2 id="connector-heading">Discovery services</h2>
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
                <StatusPill status={connectorStatus(latest)} />
              </div>
            );
          })}
          <p className="connector-footnote">
            Status reflects the latest discovery job.
          </p>
        </section>
      </div>

      <section
        className="panel inventory-panel"
        aria-labelledby="attention-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">Operational focus</p>
            <h2 id="attention-heading">Infrastructure requiring attention</h2>
          </div>
          <button className="outline-button" type="button" disabled>
            <RefreshCw aria-hidden="true" size={15} /> Run discovery
          </button>
        </div>
        <div className="empty-state">
          <ServerCog aria-hidden="true" size={25} />
          <strong>No inventory data</strong>
          <span>
            Read-only iLO and Hyper-V discovery will populate this view.
          </span>
        </div>
      </section>

      <section className="panel jobs-panel" aria-labelledby="jobs-heading">
        <div className="panel__header">
          <div>
            <p className="eyebrow">Read-only operations</p>
            <h2 id="jobs-heading">Recent discovery jobs</h2>
          </div>
          <span className="read-only-badge">Read only</span>
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
                <span>{formatUtc(job.started_at ?? job.created_at)}</span>
                <span>{duration(job)}</span>
                <StatusPill status={job.status} />
              </article>
            ))}
          </div>
        ) : (
          <div className="empty-state empty-state--compact">
            <RefreshCw aria-hidden="true" size={22} />
            <strong>
              {dashboard.jobsAvailable
                ? "No discovery jobs"
                : "Discovery jobs unavailable"}
            </strong>
            <span>
              {dashboard.jobsAvailable
                ? "The first connector run will appear here."
                : "The Control Plane did not return tenant job data."}
            </span>
          </div>
        )}
      </section>
    </ConsoleShell>
  );
}
