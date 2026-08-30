import { Filter, ScrollText } from "lucide-react";
import type { Metadata, Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { BmcLogExport } from "@/components/bmc-log-export";
import { ConsoleShell } from "@/components/console-shell";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getBmcLogs } from "@/lib/server-physical";
import { selectedTenant } from "@/lib/tenant-selection";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export async function generateMetadata(): Promise<Metadata> {
  const dictionary = getDictionary(await resolveLocale());
  return { title: dictionary.bmcLogs.title };
}

function values(value: string | string[] | undefined): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function first(value: string | string[] | undefined): string {
  return values(value)[0] ?? "";
}

function formatDate(value: string, locale: "de" | "en") {
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "medium",
    timeZone: "UTC",
  }).format(new Date(value));
}

export default async function BmcLogsPage({
  searchParams,
}: {
  searchParams: SearchParams;
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);

  const selected = await searchParams;
  const query = new URLSearchParams();
  for (const severity of values(selected.severity))
    query.append("severity", severity);
  for (const name of ["connector", "from", "to", "q"] as const) {
    const value = first(selected[name]);
    if (value) query.set(name, value);
  }
  const queryString = query.toString();
  const data = await getBmcLogs(tenant.id, queryString);
  if (!data.sessionValid) redirect(`/${locale}/login`);
  const selectedSeverities = new Set(values(selected.severity));

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="bmc-logs">
      <div
        className={`preview-notice ${data.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {data.available
          ? dictionary.bmcLogs.liveData
          : dictionary.bmcLogs.unavailableData}
      </div>

      <section className="page-heading" aria-labelledby="bmc-logs-heading">
        <div>
          <p className="eyebrow">{dictionary.bmcLogs.eyebrow}</p>
          <h1 id="bmc-logs-heading">{dictionary.bmcLogs.heading}</h1>
          <p>{dictionary.bmcLogs.description}</p>
        </div>
        <BmcLogExport
          tenantId={tenant.id}
          queryString={queryString}
          copy={dictionary.bmcLogs}
        />
      </section>

      <section
        className="panel log-filter-panel"
        aria-labelledby="log-filter-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{dictionary.bmcLogs.filters}</p>
            <h2 id="log-filter-heading">{dictionary.bmcLogs.filters}</h2>
          </div>
          <Filter aria-hidden="true" size={18} />
        </div>
        <form className="log-filters" method="get">
          <fieldset>
            <legend>{dictionary.bmcLogs.severity}</legend>
            {(["debug", "info", "warning", "error"] as const).map(
              (severity) => (
                <label key={severity}>
                  <input
                    type="checkbox"
                    name="severity"
                    value={severity}
                    defaultChecked={selectedSeverities.has(severity)}
                  />
                  {dictionary.bmcLogs[severity]}
                </label>
              ),
            )}
          </fieldset>
          <label>
            {dictionary.bmcLogs.bmc}
            <select name="connector" defaultValue={first(selected.connector)}>
              <option value="">{dictionary.bmcLogs.allBmcs}</option>
              {data.connectors.map((connector) => (
                <option key={connector.id} value={connector.id}>
                  {connector.display_name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {dictionary.bmcLogs.from}
            <input
              type="datetime-local"
              name="from"
              defaultValue={first(selected.from)}
            />
          </label>
          <label>
            {dictionary.bmcLogs.to}
            <input
              type="datetime-local"
              name="to"
              defaultValue={first(selected.to)}
            />
          </label>
          <label>
            {dictionary.bmcLogs.search}
            <input
              type="search"
              name="q"
              defaultValue={first(selected.q)}
              placeholder={dictionary.bmcLogs.searchPlaceholder}
              maxLength={255}
            />
          </label>
          <div className="log-filters__actions">
            <Link
              className="outline-button"
              href={`/${locale}/physical/bmc/logs` as Route}
            >
              {dictionary.bmcLogs.clear}
            </Link>
            <button className="primary-button" type="submit">
              {dictionary.bmcLogs.apply}
            </button>
          </div>
        </form>
      </section>

      <section
        className="panel inventory-panel"
        aria-label={dictionary.bmcLogs.heading}
      >
        {data.logs.length ? (
          <div className="table-scroll">
            <table className="log-table">
              <thead>
                <tr>
                  <th>{dictionary.bmcLogs.time}</th>
                  <th>{dictionary.bmcLogs.severity}</th>
                  <th>{dictionary.bmcLogs.bmc}</th>
                  <th>{dictionary.bmcLogs.event}</th>
                  <th>{dictionary.bmcLogs.request}</th>
                  <th>{dictionary.bmcLogs.status}</th>
                  <th>{dictionary.bmcLogs.duration}</th>
                  <th>{dictionary.bmcLogs.details}</th>
                </tr>
              </thead>
              <tbody>
                {data.logs.map((entry) => {
                  const detail =
                    entry.redfish_message_id ||
                    entry.redfish_error_code ||
                    entry.error_code;
                  return (
                    <tr key={entry.id}>
                      <td>{formatDate(entry.occurred_at, locale)}</td>
                      <td>
                        <span
                          className={`log-level log-level--${entry.severity}`}
                        >
                          {dictionary.bmcLogs[entry.severity]}
                        </span>
                      </td>
                      <td>
                        <strong>{entry.bmc_name}</strong>
                      </td>
                      <td>
                        <code>{entry.event_type}</code>
                      </td>
                      <td>
                        <code>
                          {[entry.method, entry.resource_path]
                            .filter(Boolean)
                            .join(" ") || "—"}
                        </code>
                      </td>
                      <td>{entry.http_status ?? "—"}</td>
                      <td>
                        {entry.duration_ms === null
                          ? "—"
                          : `${entry.duration_ms} ms`}
                      </td>
                      <td>
                        <code>{detail || "—"}</code>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <ScrollText aria-hidden="true" size={25} />
            <strong>{dictionary.bmcLogs.noLogs}</strong>
            <span>{dictionary.bmcLogs.noLogsHint}</span>
          </div>
        )}
        <p className="connector-footnote">{dictionary.bmcLogs.showingLimit}</p>
      </section>
    </ConsoleShell>
  );
}
