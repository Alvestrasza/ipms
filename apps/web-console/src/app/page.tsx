import {
  Activity,
  ArrowRight,
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
import { discoveryJobs, inventoryRows, summaryCards } from "@/lib/console-data";
import { getServerSession } from "@/lib/server-auth";
import { selectedTenant } from "@/lib/tenant-selection";

const summaryIcons = [ServerCog, Boxes, Network, ShieldCheck];

export default async function OverviewPage() {
  const session = await getServerSession();
  if (!session?.authenticated) redirect("/login");
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect("/login?reason=no-tenant");

  return (
    <ConsoleShell session={session} tenant={tenant}>
      <div className="preview-notice" role="status">
        <span className="preview-notice__dot" aria-hidden="true" />
        Preview dataset — no live infrastructure data is displayed yet.
      </div>

      <section className="page-heading" aria-labelledby="overview-heading">
        <div>
          <p className="eyebrow">Management overview</p>
          <h1 id="overview-heading">Infrastructure at a glance</h1>
          <p>Read-only operational status across the selected tenant.</p>
        </div>
        <div className="page-heading__meta">
          <Clock3 aria-hidden="true" size={16} />
          Last synchronized 2 minutes ago
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
                <span
                  className={`summary-card__detail summary-card__detail--${card.status}`}
                >
                  {card.detail}
                </span>
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
            <span className="panel__metric">
              <strong>97%</strong> available
            </span>
          </div>
          <div
            className="health-bar"
            role="img"
            aria-label="97 percent healthy, 2 percent warning, 1 percent critical"
          >
            <span className="health-bar__healthy" style={{ width: "97%" }} />
            <span className="health-bar__warning" style={{ width: "2%" }} />
            <span className="health-bar__critical" style={{ width: "1%" }} />
          </div>
          <div className="health-legend">
            <span>
              <i className="legend-dot legend-dot--healthy" />
              Healthy <strong>183</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--warning" />
              Warning <strong>4</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--critical" />
              Critical <strong>2</strong>
            </span>
            <span>
              <i className="legend-dot legend-dot--unknown" />
              Unknown <strong>1</strong>
            </span>
          </div>
        </section>

        <section
          className="panel connector-card"
          aria-labelledby="connector-heading"
        >
          <div className="panel__header">
            <div>
              <p className="eyebrow">Connector health</p>
              <h2 id="connector-heading">Discovery services</h2>
            </div>
            <Activity aria-hidden="true" size={20} />
          </div>
          <div className="connector-row">
            <span>
              <i className="connector-mark">H</i>
              <strong>Hyper-V</strong>
            </span>
            <StatusPill status="healthy" />
          </div>
          <div className="connector-row">
            <span>
              <i className="connector-mark connector-mark--ilo">i</i>
              <strong>iLO Redfish</strong>
            </span>
            <StatusPill status="warning" />
          </div>
          <button className="text-button" type="button" disabled>
            View connector details <ArrowRight aria-hidden="true" size={15} />
          </button>
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
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Location</th>
                <th>Status</th>
                <th>Details</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {inventoryRows.map((row) => (
                <tr key={row.id}>
                  <td>
                    <strong>{row.name}</strong>
                  </td>
                  <td>{row.kind}</td>
                  <td>{row.location}</td>
                  <td>
                    <StatusPill status={row.status} />
                  </td>
                  <td>{row.detail}</td>
                  <td className="table-muted">{row.updated}</td>
                </tr>
              ))}
            </tbody>
          </table>
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
        <div className="job-list">
          {discoveryJobs.map((job) => (
            <article className="job-row" key={job.id}>
              <div className="job-row__icon">
                <RefreshCw aria-hidden="true" size={17} />
              </div>
              <div>
                <strong>{job.connector}</strong>
                <span>{job.target}</span>
              </div>
              <code>{job.id}</code>
              <span>{job.started}</span>
              <span>{job.duration}</span>
              <StatusPill status={job.status} />
            </article>
          ))}
        </div>
      </section>
    </ConsoleShell>
  );
}
