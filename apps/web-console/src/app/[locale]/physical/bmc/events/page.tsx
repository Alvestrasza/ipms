import { Filter, ScrollText } from "lucide-react";
import type { Metadata, Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";

import { BmcEventLogExport } from "@/components/bmc-event-log-export";
import { ConsoleShell } from "@/components/console-shell";
import { documentLocale } from "@/i18n/config";
import { getDictionary } from "@/i18n/dictionaries";
import { resolveLocale } from "@/i18n/server";
import { getServerSession } from "@/lib/server-auth";
import { getBmcEventLogs } from "@/lib/server-physical";
import { selectedTenant } from "@/lib/tenant-selection";

type SearchParams = Promise<Record<string, string | string[] | undefined>>;
const values = (value: string | string[] | undefined) =>
  value ? (Array.isArray(value) ? value : [value]) : [];
const first = (value: string | string[] | undefined) => values(value)[0] ?? "";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getDictionary(await resolveLocale()).bmcEvents.title };
}

export default async function BmcEventsPage({
  searchParams,
}: {
  searchParams: SearchParams;
}) {
  const locale = await resolveLocale();
  const dictionary = getDictionary(locale);
  const copy = dictionary.bmcEvents;
  const session = await getServerSession();
  if (!session?.authenticated) redirect(`/${locale}/login`);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/login?reason=no-tenant`);
  const selected = await searchParams;
  const query = new URLSearchParams();
  for (const key of ["severity", "log_type"] as const)
    for (const item of values(selected[key])) query.append(key, item);
  for (const key of ["connector", "from", "to", "q"] as const) {
    const item = first(selected[key]);
    if (item) query.set(key, item);
  }
  const queryString = query.toString();
  const data = await getBmcEventLogs(tenant.id, queryString);
  if (!data.sessionValid) redirect(`/${locale}/login`);
  const severities = new Set(values(selected.severity));
  const logTypes = new Set(values(selected.log_type));
  const formatter = new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "medium",
  });

  return (
    <ConsoleShell session={session} tenant={tenant} activeSection="bmc-events">
      <div
        className={`preview-notice ${data.available ? "preview-notice--live" : ""}`}
        role="status"
      >
        <span className="preview-notice__dot" aria-hidden="true" />
        {data.available ? copy.liveData : copy.unavailableData}
      </div>
      <section className="page-heading" aria-labelledby="bmc-events-heading">
        <div>
          <p className="eyebrow">{copy.eyebrow}</p>
          <h1 id="bmc-events-heading">{copy.heading}</h1>
          <p>{copy.description}</p>
        </div>
        <BmcEventLogExport
          tenantId={tenant.id}
          queryString={queryString}
          copy={copy}
        />
      </section>
      <section
        className="panel log-filter-panel"
        aria-labelledby="event-filter-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{copy.filters}</p>
            <h2 id="event-filter-heading">{copy.filters}</h2>
          </div>
          <Filter aria-hidden="true" size={18} />
        </div>
        <form className="log-filters log-filters--events" method="get">
          <fieldset>
            <legend>{copy.logType}</legend>
            {(["ilo_event_log", "integrated_management_log"] as const).map(
              (type) => (
                <label key={type}>
                  <input
                    type="checkbox"
                    name="log_type"
                    value={type}
                    defaultChecked={logTypes.has(type)}
                  />
                  {copy[type]}
                </label>
              ),
            )}
          </fieldset>
          <fieldset>
            <legend>{copy.severity}</legend>
            {(["info", "warning", "critical", "unknown"] as const).map(
              (severity) => (
                <label key={severity}>
                  <input
                    type="checkbox"
                    name="severity"
                    value={severity}
                    defaultChecked={severities.has(severity)}
                  />
                  {copy[severity]}
                </label>
              ),
            )}
          </fieldset>
          <label>
            {copy.bmc}
            <select name="connector" defaultValue={first(selected.connector)}>
              <option value="">{copy.allBmcs}</option>
              {data.connectors.map((connector) => (
                <option key={connector.id} value={connector.id}>
                  {connector.display_name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {copy.from}
            <input
              type="datetime-local"
              name="from"
              defaultValue={first(selected.from)}
            />
          </label>
          <label>
            {copy.to}
            <input
              type="datetime-local"
              name="to"
              defaultValue={first(selected.to)}
            />
          </label>
          <label>
            {copy.search}
            <input
              type="search"
              name="q"
              defaultValue={first(selected.q)}
              placeholder={copy.searchPlaceholder}
              maxLength={255}
            />
          </label>
          <div className="log-filters__actions">
            <Link
              className="outline-button"
              href={`/${locale}/physical/bmc/events` as Route}
            >
              {copy.clear}
            </Link>
            <button className="primary-button" type="submit">
              {copy.apply}
            </button>
          </div>
        </form>
      </section>
      <section className="panel inventory-panel" aria-label={copy.heading}>
        {data.logs.length ? (
          <div className="table-scroll">
            <table className="log-table">
              <thead>
                <tr>
                  <th>{copy.time}</th>
                  <th>{copy.severity}</th>
                  <th>{copy.bmc}</th>
                  <th>{copy.logType}</th>
                  <th>{copy.message}</th>
                  <th>{copy.repeatCount}</th>
                  <th>{copy.repaired}</th>
                  <th>{copy.code}</th>
                </tr>
              </thead>
              <tbody>
                {data.logs.map((entry) => (
                  <tr key={entry.id}>
                    <td>
                      {entry.source_created_at
                        ? formatter.format(new Date(entry.source_created_at))
                        : "—"}
                    </td>
                    <td>
                      <span
                        className={`log-level log-level--${entry.severity}`}
                      >
                        {copy[entry.severity]}
                      </span>
                    </td>
                    <td>
                      <strong>{entry.bmc_name}</strong>
                    </td>
                    <td>{copy[entry.log_type]}</td>
                    <td className="event-message">{entry.message || "—"}</td>
                    <td>{entry.repeat_count ?? "—"}</td>
                    <td>
                      {entry.repaired === null
                        ? "—"
                        : entry.repaired
                          ? copy.yes
                          : copy.no}
                    </td>
                    <td>
                      <code>
                        {[
                          entry.event_class,
                          entry.event_code,
                          entry.event_number,
                        ]
                          .filter((value) => value !== null)
                          .join("/") || "—"}
                      </code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <ScrollText aria-hidden="true" size={25} />
            <strong>{copy.noLogs}</strong>
            <span>{copy.noLogsHint}</span>
          </div>
        )}
        <p className="connector-footnote">{copy.showingLimit}</p>
      </section>
    </ConsoleShell>
  );
}
