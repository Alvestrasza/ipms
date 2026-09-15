/**
 * File Name: logs-page.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Render tenant-scoped histories with URL filters and authorized pilot details.
 */
import { Filter, ScrollText } from "lucide-react";
import type { Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";
import { documentLocale } from "@/i18n/config";
import { getJobLogsCopy, logStatusLabel } from "@/i18n/job-logs-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import {
  JOB_LOG_STATUSES,
  type JobLogScope,
  type LogSearchParams,
  logQuery,
  logUrl,
} from "@/lib/job-log-types";
import { getServerSession } from "@/lib/server-auth";
import { getGpoImportLog, getJobLogs } from "@/lib/server-job-logs";
import { requireTenantScope } from "@/lib/server-portal-scope";
import { selectedTenant } from "@/lib/tenant-selection";
import { ConsoleShell } from "./console-shell";
import { LogsExport } from "./logs-export";
import { LogsGpoDetail } from "./logs-gpo-detail";
import styles from "./logs-page.module.css";
import { LogsSortHeading } from "./logs-sort-heading";

export async function LogsPage({
  scope,
  searchParams,
}: {
  scope: JobLogScope;
  searchParams: Promise<LogSearchParams>;
}) {
  const locale = await resolveLocale();
  const copy = getJobLogsCopy(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant || !hasPermission(tenant, "inventory.view"))
    redirect(`/${locale}/access-unavailable`);
  const selected = await searchParams;
  const query = logQuery(selected);
  const path = `/${locale}/logs/${scope}`;
  const detailRequested = scope === "baselines" && selected.job !== undefined;
  const canViewPilot =
    hasPermission(tenant, "security.domains.manage") ||
    hasPermission(tenant, "security.gpo_imports.approve");
  const jobId = typeof selected.job === "string" ? selected.job : "";
  const [history, detail] = await Promise.all([
    getJobLogs(tenant.id, scope, query.toString()),
    detailRequested && canViewPilot
      ? getGpoImportLog(tenant.id, jobId)
      : Promise.resolve({ data: null, status: 0 }),
  ]);
  if (history.status === 401 || detail.status === 401)
    redirect(`/${locale}/login`);
  const navigationQuery = new URLSearchParams(query);
  if (detailRequested && jobId) navigationQuery.set("job", jobId);
  const data = history.data;
  const title = scope === "agents" ? copy.agentsTitle : copy.baselinesTitle;
  const pages = data ? Math.max(1, Math.ceil(data.count / data.page_size)) : 1;
  const formatter = new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  });
  const date = (value: string | null) =>
    value ? (
      <time dateTime={value}>{formatter.format(new Date(value))}</time>
    ) : (
      "—"
    );
  const headings = {
    requested_at: copy.requested,
    completed_at: copy.completed,
    system: copy.system,
    kind: copy.kind,
    status: copy.status,
  };
  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection={`logs-${scope}`}
    >
      <section className="page-heading" aria-labelledby="job-logs-heading">
        <div>
          <p className="eyebrow">{copy.navigation}</p>
          <h1 id="job-logs-heading">{title}</h1>
          <p>{copy.description}</p>
        </div>
        <LogsExport
          key={`${tenant.id}:${scope}:${query}`}
          tenantId={tenant.id}
          scope={scope}
          queryString={query.toString()}
          copy={copy}
          disabled={!data}
        />
      </section>
      {scope === "baselines" ? (
        <p className="connector-footnote">{copy.historyHint}</p>
      ) : null}
      {detailRequested ? (
        <section className="panel" aria-labelledby="gpo-log-detail-heading">
          <div className="panel__header">
            <h2 id="gpo-log-detail-heading">{copy.gpoDetails}</h2>
            <Link
              className="outline-button"
              href={logUrl(path, query) as Route}
            >
              {copy.closeDetails}
            </Link>
          </div>
          {detail.data && canViewPilot ? (
            <LogsGpoDetail
              key={`${tenant.id}:${detail.data.id}:${detail.data.input_digest}:${detail.data.policy_revision}:${detail.data.can_approve}:${detail.data.approval_blocker}:${session.csrf_token}:${tenant.permissions.join(",")}`}
              job={detail.data}
              locale={locale}
              tenantId={tenant.id}
              csrfToken={session.csrf_token}
            />
          ) : (
            <p className={styles.notice} role="alert">
              {copy.detailUnavailable}
            </p>
          )}
        </section>
      ) : null}
      <section className="panel" aria-labelledby="job-log-filter-heading">
        <div className="panel__header">
          <h2 id="job-log-filter-heading">{copy.filters}</h2>
          <Filter size={18} aria-hidden="true" />
        </div>
        <form
          key={`${tenant.id}:${query}`}
          method="get"
          action={path}
          className={styles.filters}
        >
          <input
            type="hidden"
            name="sort"
            value={query.get("sort") || "requested_at"}
          />
          <input
            type="hidden"
            name="direction"
            value={query.get("direction") || "desc"}
          />
          <label className={styles.field}>
            {copy.search}
            <input
              type="search"
              name="q"
              maxLength={200}
              defaultValue={query.get("q") || ""}
              placeholder={copy.searchPlaceholder}
            />
          </label>
          <label className={styles.field}>
            {copy.kind}
            <select name="kind" defaultValue={query.get("kind") || ""}>
              <option value="">{copy.all}</option>
              {(data?.available_kinds ?? []).map((kind) => (
                <option key={kind} value={kind}>
                  {copy.kinds[kind]}
                </option>
              ))}
              {query.get("kind") &&
              !data?.available_kinds.some(
                (kind) => kind === query.get("kind"),
              ) ? (
                <option value={query.get("kind") || ""}>
                  {query.get("kind")}
                </option>
              ) : null}
            </select>
          </label>
          <label className={styles.field}>
            {copy.status}
            <select name="status" defaultValue={query.get("status") || ""}>
              <option value="">{copy.all}</option>
              {JOB_LOG_STATUSES.map((status) => (
                <option key={status} value={status}>
                  {copy.statuses[status]}
                </option>
              ))}
            </select>
          </label>
          <label className={styles.field}>
            {copy.from}
            <input
              type="text"
              name="from"
              maxLength={40}
              defaultValue={query.get("from") || ""}
              placeholder="YYYY-MM-DD"
              aria-describedby="job-log-date-hint"
            />
          </label>
          <label className={styles.field}>
            {copy.to}
            <input
              type="text"
              name="to"
              maxLength={40}
              defaultValue={query.get("to") || ""}
              placeholder="YYYY-MM-DD"
              aria-describedby="job-log-date-hint"
            />
          </label>
          <label className={styles.field}>
            {copy.baseline}
            <input
              type="text"
              name="baseline"
              maxLength={96}
              defaultValue={query.get("baseline") || ""}
            />
          </label>
          <label className={styles.field}>
            {copy.domain}
            <input
              type="text"
              name="domain"
              maxLength={253}
              defaultValue={query.get("domain") || ""}
            />
          </label>
          <label className={styles.field}>
            {copy.agent}
            <input
              type="text"
              name="agent"
              maxLength={36}
              defaultValue={query.get("agent") || ""}
            />
          </label>
          <label className={styles.field}>
            {copy.pageSize}
            <select
              name="page_size"
              defaultValue={query.get("page_size") || "25"}
            >
              {[25, 50, 100].map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
          <p className={styles.filterHint} id="job-log-date-hint">
            {copy.dateHint}
          </p>
          <div className={styles.actions}>
            <Link className="outline-button" href={path as Route}>
              {copy.clear}
            </Link>
            <button className={styles.applyButton} type="submit">
              {copy.apply}
            </button>
          </div>
        </form>
      </section>
      <section className="panel inventory-panel" aria-label={title}>
        {!data ? (
          <p className={styles.notice} role="alert">
            {history.status === 400
              ? copy.invalid
              : history.status === 403
                ? copy.forbidden
                : copy.unavailable}
          </p>
        ) : (
          <>
            {data.results.length ? (
              <div className="table-scroll">
                <table className={styles.table} aria-label={title}>
                  <thead>
                    <tr>
                      {Object.entries(headings).map(([column, label]) => (
                        <LogsSortHeading
                          key={column}
                          column={column}
                          label={label}
                          path={path}
                          query={navigationQuery}
                          copy={copy}
                        />
                      ))}
                      <th scope="col">{copy.target}</th>
                      <th scope="col">{copy.result}</th>
                      <th scope="col">{copy.requestedBy}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.results.map((entry) => (
                      <tr key={`${entry.kind}:${entry.id}`}>
                        <td>
                          {date(entry.requested_at)}
                          {entry.started_at ? (
                            <small>
                              {copy.started}: {date(entry.started_at)}
                            </small>
                          ) : null}
                        </td>
                        <td>{date(entry.completed_at)}</td>
                        <td>
                          <strong>{entry.system || "—"}</strong>
                          {entry.domain ? <small>{entry.domain}</small> : null}
                        </td>
                        <td>
                          {copy.kinds[entry.kind]}
                          <small>{entry.action}</small>
                        </td>
                        <td>
                          <span className={styles.status}>
                            {logStatusLabel(entry.status, copy)}
                          </span>
                        </td>
                        <td>
                          {entry.target || "—"}
                          {entry.kind === "gpo_import" && canViewPilot ? (
                            <small>
                              <Link
                                href={
                                  logUrl(`/${locale}/logs/baselines`, query, {
                                    job: entry.id,
                                  }) as Route
                                }
                              >
                                {copy.openDetails}
                              </Link>
                            </small>
                          ) : null}
                        </td>
                        <td>
                          <code>{entry.result_code || "—"}</code>
                        </td>
                        <td>{entry.requested_by || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <ScrollText size={25} aria-hidden="true" />
                <strong>{copy.empty}</strong>
              </div>
            )}
            <nav className={styles.pagination} aria-label={copy.pagination}>
              <span>
                {copy.total.replace(
                  "{count}",
                  new Intl.NumberFormat(documentLocale(locale)).format(
                    data.count,
                  ),
                )}{" "}
                ·{" "}
                {copy.page
                  .replace("{page}", String(data.page))
                  .replace("{pages}", String(pages))}
              </span>
              <div className={styles.pageLinks}>
                {data.page > 1 ? (
                  <Link
                    className="outline-button"
                    rel="prev"
                    href={
                      logUrl(path, navigationQuery, {
                        page: String(data.page - 1),
                      }) as Route
                    }
                  >
                    {copy.previous}
                  </Link>
                ) : null}
                {data.page < pages ? (
                  <Link
                    className="outline-button"
                    rel="next"
                    href={
                      logUrl(path, navigationQuery, {
                        page: String(data.page + 1),
                      }) as Route
                    }
                  >
                    {copy.next}
                  </Link>
                ) : null}
              </div>
            </nav>
          </>
        )}
      </section>
    </ConsoleShell>
  );
}
