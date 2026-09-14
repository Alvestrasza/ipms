/**
 * File Name: page.tsx
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Show latest tenant-bound machine findings without inferring full compliance.
 */
import type { Metadata, Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import styles from "@/components/security-baseline-scans.module.css";
import { documentLocale } from "@/i18n/config";
import { getSecurityCopy } from "@/i18n/security-copy";
import { getSecurityScanCopy } from "@/i18n/security-scan-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import type { SecurityFindingValue } from "@/lib/security-types";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import {
  getSecurityBaselineCatalog,
  getSecurityBaselineFindings,
} from "@/lib/server-security";
import { getWindowsServer } from "@/lib/server-windows";
import { selectedTenant } from "@/lib/tenant-selection";

export async function generateMetadata(): Promise<Metadata> {
  return { title: getSecurityScanCopy(await resolveLocale()).findings };
}

function value(value: SecurityFindingValue) {
  return value === null
    ? "—"
    : typeof value === "string"
      ? value
      : JSON.stringify(value);
}

export default async function BaselineFindingsPage({
  params,
  searchParams,
}: {
  params: Promise<{ baselineId: string; systemId: string }>;
  searchParams: Promise<{ page?: string | string[] }>;
}) {
  const locale = await resolveLocale();
  const copy = getSecurityCopy(locale);
  const scanCopy = getSecurityScanCopy(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  if (!hasPermission(tenant, "inventory.view")) redirect(`/${locale}`);
  const { baselineId, systemId } = await params;
  const query = await searchParams;
  const page =
    typeof query.page === "string" && /^[1-9]\d{0,6}$/.test(query.page)
      ? Number(query.page)
      : 1;
  const [catalog, findings, system] = await Promise.all([
    getSecurityBaselineCatalog(tenant.id),
    getSecurityBaselineFindings(tenant.id, baselineId, systemId, page),
    getWindowsServer(tenant.id, systemId),
  ]);
  if (!catalog.sessionValid || !findings.sessionValid || !system.sessionValid)
    redirect(`/${locale}/login`);
  if (catalog.forbidden || findings.forbidden)
    redirect(`/${locale}/access-unavailable`);
  const baseline = catalog.data?.results.find(
    (entry) => entry.id === baselineId,
  );
  if (findings.notFound || (catalog.available && !baseline)) notFound();
  const data = findings.data;
  const route = `/${locale}/security/baseline/${encodeURIComponent(baselineId)}/systems/${encodeURIComponent(systemId)}/findings`;
  const back =
    `/${locale}/security/baseline?baseline=${encodeURIComponent(baselineId)}` as Route;
  const pages = data ? Math.max(1, Math.ceil(data.count / data.page_size)) : 1;
  if (data && data.page > pages) redirect(route as Route);
  const date = (timestamp: string | null) =>
    timestamp
      ? new Intl.DateTimeFormat(documentLocale(locale), {
          dateStyle: "medium",
          timeStyle: "short",
          timeZone: "UTC",
        }).format(new Date(timestamp))
      : copy.notAssessed;

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-baseline"
    >
      <section className="page-heading" aria-labelledby="findings-heading">
        <div>
          <p className="eyebrow">{baseline?.name ?? baselineId}</p>
          <h1 id="findings-heading">{scanCopy.findings}</h1>
          <p>{system.server?.hostname || system.server?.fqdn || systemId}</p>
        </div>
        <Link className={styles.button} href={back}>
          {scanCopy.back}
        </Link>
      </section>
      <div className={styles.findings}>
        <div className={styles.findingsPanel}>
          <div className={styles.header}>
            <p>{scanCopy.boundary}</p>
            <p>{scanCopy.scopeHint}</p>
          </div>
        </div>
        {!data ? (
          <div className={styles.findingsPanel}>
            <p className={styles.empty} role="status">
              {scanCopy.findingsUnavailable}
            </p>
            <div className={styles.actions}>
              <a className={styles.button} href={`${route}?page=${page}`}>
                {copy.reload}
              </a>
            </div>
          </div>
        ) : !data.assessment_id ? (
          <div className={styles.findingsPanel}>
            <p className={styles.empty}>{scanCopy.noAssessment}</p>
          </div>
        ) : (
          <section
            className={styles.findingsPanel}
            aria-label={scanCopy.findings}
          >
            <div className={styles.findingMetadata}>
              <strong>
                {copy.status}: {copy.statuses[data.status]}
              </strong>
              <span>{copy.reasons[data.reason]}</span>
            </div>
            <dl className={styles.counts}>
              {[
                { label: scanCopy.total, count: data.total_controls },
                { label: scanCopy.passed, count: data.passed_controls },
                { label: scanCopy.failed, count: data.failed_controls },
                { label: scanCopy.unknown, count: data.unknown_controls },
              ].map((entry) => (
                <div key={entry.label}>
                  <dt>{entry.label}</dt>
                  <dd>{entry.count}</dd>
                </div>
              ))}
            </dl>
            <div className={styles.findingMetadata}>
              <span>
                {data.scope_verified
                  ? scanCopy.scopeVerified
                  : scanCopy.scopePartial}
              </span>
              <span>
                {copy.assessmentTime}: {date(data.assessed_at)}
              </span>
              <span>
                {scanCopy.assessment}: {data.assessment_id}
              </span>
            </div>
            {data.results.length === 0 ? (
              <p className={styles.empty}>{scanCopy.noFindings}</p>
            ) : (
              <section
                className={styles.tableScroll}
                aria-label={scanCopy.findings}
                // biome-ignore lint/a11y/noNoninteractiveTabindex: Keyboard users need focus to scroll the overflowing findings table.
                tabIndex={0}
              >
                <table className={styles.findingsTable}>
                  <caption className="sr-only">{scanCopy.findings}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{scanCopy.control}</th>
                      <th scope="col">{scanCopy.scope}</th>
                      <th scope="col">{scanCopy.result}</th>
                      <th scope="col">{scanCopy.expected}</th>
                      <th scope="col">{scanCopy.observed}</th>
                      <th scope="col">{scanCopy.reason}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.results.map((finding) => (
                      <tr key={finding.control_id}>
                        <td>
                          <strong>{finding.label}</strong>
                          <small>
                            {finding.control_id} · {finding.kind}
                          </small>
                        </td>
                        <td>
                          {scanCopy.scopes[
                            finding.scope as keyof typeof scanCopy.scopes
                          ] ?? finding.scope}
                        </td>
                        <td>
                          <span
                            className={styles.findingStatus}
                            data-status={finding.status}
                          >
                            {scanCopy[finding.status]}
                          </span>
                        </td>
                        <td>
                          <code>{value(finding.expected)}</code>
                        </td>
                        <td>
                          <code>{value(finding.observed)}</code>
                        </td>
                        <td>
                          {scanCopy.findingReasons[
                            finding.reason as keyof typeof scanCopy.findingReasons
                          ] ??
                            (finding.reason || "—")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            )}
            <nav className={styles.pagination} aria-label={scanCopy.findings}>
              <span>
                {copy.page} {data.page} {copy.of} {pages} · {data.count}{" "}
                {scanCopy.total}
              </span>
              <div className={styles.actions}>
                {data.page > 1 ? (
                  <Link
                    className={styles.button}
                    href={`${route}?page=${data.page - 1}` as Route}
                  >
                    {copy.previous}
                  </Link>
                ) : null}
                {data.page < pages ? (
                  <Link
                    className={styles.button}
                    href={`${route}?page=${data.page + 1}` as Route}
                  >
                    {copy.next}
                  </Link>
                ) : null}
                <a className={styles.button} href={`${route}?page=${page}`}>
                  {copy.reload}
                </a>
              </div>
            </nav>
          </section>
        )}
      </div>
    </ConsoleShell>
  );
}
