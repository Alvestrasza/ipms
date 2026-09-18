/**
 * File Name: page.tsx
 * Version: v0.1.1
 * Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Display baseline-family application and selectable assessment details.
 */
import {
  ArrowDownToLine,
  ArrowRight,
  ChevronDown,
  CircleHelp,
  ExternalLink,
  EyeOff,
  Layers,
  Monitor,
  RefreshCw,
  ScanLine,
  Server,
  ShieldCheck,
} from "lucide-react";
import type { Metadata, Route } from "next";
import { cookies } from "next/headers";
import Link from "next/link";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { SecurityBaselineDetails } from "@/components/security-baseline-details";
import { SecurityBaselineScansPanel } from "@/components/security-baseline-scans";
import { documentLocale, type Locale } from "@/i18n/config";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import { getSecurityCopy, type SecurityCopy } from "@/i18n/security-copy";
import {
  getSecurityScanCopy,
  type SecurityScanCopy,
} from "@/i18n/security-scan-copy";
import { resolveLocale } from "@/i18n/server";
import { hasPermission } from "@/lib/auth-types";
import type {
  SecurityBaseline,
  SecurityBaselineStatus,
  SecurityBaselineSystems,
  SecurityBaselineTarget,
} from "@/lib/security-types";
import { getServerSession } from "@/lib/server-auth";
import { requireTenantScope } from "@/lib/server-portal-scope";
import {
  getSecurityBaselineCatalog,
  getSecurityBaselineScans,
  getSecurityBaselineSystems,
} from "@/lib/server-security";
import { selectedTenant } from "@/lib/tenant-selection";
import styles from "./security-baseline.module.css";

function baselineHref(
  locale: Locale,
  target: SecurityBaselineTarget,
  baseline?: string,
  page = 1,
): Route {
  const query = new URLSearchParams({ target });
  if (baseline) query.set("baseline", baseline);
  if (page > 1) query.set("page", String(page));
  return `/${locale}/security/baseline?${query}` as Route;
}

function formatDate(value: string | null, locale: Locale) {
  if (!value || !Number.isFinite(Date.parse(value))) return "—";
  return new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    ...(value.includes("T") ? { timeStyle: "short" as const } : {}),
    timeZone: "UTC",
  }).format(new Date(value));
}

function formatPercent(value: number | null, locale: Locale) {
  return value === null
    ? "—"
    : new Intl.NumberFormat(documentLocale(locale), {
        style: "percent",
        maximumFractionDigits: 1,
      }).format(value / 100);
}

function Compliance({
  baseline,
  locale,
  copy,
}: {
  baseline: SecurityBaseline;
  locale: Locale;
  copy: SecurityCopy;
}) {
  const { summary } = baseline;
  return (
    <div className={styles.compliance}>
      <strong>{formatPercent(summary.compliance_percent, locale)}</strong>
      {summary.compliance_percent === null ? (
        <small>
          {summary.applicable === 0 ? copy.noMatching : copy.notAssessed}
        </small>
      ) : (
        <>
          <meter
            min={0}
            max={100}
            value={summary.compliance_percent}
            aria-label={`${baseline.name}: ${copy.compliance}`}
          />
          <small>
            {summary.compliant} / {summary.applicable} {copy.statuses.compliant}
          </small>
        </>
      )}
    </div>
  );
}

function SystemsTable({
  data,
  locale,
  copy,
  target,
  scanCopy,
}: {
  data: SecurityBaselineSystems;
  locale: Locale;
  copy: SecurityCopy;
  target: SecurityBaselineTarget;
  scanCopy: SecurityScanCopy;
}) {
  const pages = Math.max(1, Math.ceil(data.count / data.page_size));
  return (
    <>
      <div className={styles.tableScroll}>
        <table className={styles.systemsTable}>
          <caption className="sr-only">
            {data.baseline.name}: {copy.systems}
          </caption>
          <thead>
            <tr>
              <th scope="col">{copy.system}</th>
              <th scope="col">{copy.operatingSystem}</th>
              <th scope="col">{copy.role}</th>
              <th scope="col">{copy.status}</th>
              <th scope="col">{copy.assessmentTime}</th>
              <th scope="col">{scanCopy.findings}</th>
            </tr>
          </thead>
          <tbody>
            {data.results.map((system) => (
              <tr key={system.id}>
                <td>
                  <strong>{system.hostname || system.fqdn || system.id}</strong>
                  {system.fqdn && system.fqdn !== system.hostname ? (
                    <small>{system.fqdn}</small>
                  ) : null}
                  <small>
                    {copy.systemTypes[
                      system.server_type as keyof typeof copy.systemTypes
                    ] ?? system.server_type}
                  </small>
                </td>
                <td>
                  <span>{system.operating_system || "—"}</span>
                  <small>
                    {copy.build} {system.os_build || "—"}
                  </small>
                </td>
                <td>
                  {system.operating_system_role === "server"
                    ? copy.serverRole
                    : (copy.roles[
                        system.operating_system_role as keyof typeof copy.roles
                      ] ?? system.operating_system_role)}
                </td>
                <td>
                  <span className={styles.status} data-state={system.status}>
                    <span aria-hidden="true" />
                    {copy.statuses[system.status]}
                  </span>
                  <small>{copy.reasons[system.reason]}</small>
                </td>
                <td>
                  {system.assessed_at ? (
                    <time dateTime={system.assessed_at}>
                      {formatDate(system.assessed_at, locale)}
                    </time>
                  ) : (
                    copy.notAssessed
                  )}
                </td>
                <td>
                  {data.baseline.assessment_state === "native-read-only" ? (
                    <Link
                      href={
                        `/${locale}/security/baseline/${encodeURIComponent(data.baseline.id)}/systems/${encodeURIComponent(system.id)}/findings` as Route
                      }
                      className={styles.sourceLink}
                    >
                      {scanCopy.openFindings}
                    </Link>
                  ) : (
                    <span>{copy.assessmentUnavailable}</span>
                  )}
                  {system.controls ? (
                    <small>
                      {system.controls.passed} {scanCopy.passed} ·{" "}
                      {system.controls.failed} {scanCopy.failed} ·{" "}
                      {system.controls.unknown} {scanCopy.unknown}
                    </small>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <nav className={styles.pagination} aria-label={copy.systems}>
        <span>
          {copy.page} {data.page} {copy.of} {pages} · {data.count}{" "}
          {copy.applicable}
        </span>
        <div>
          {data.page > 1 ? (
            <Link
              className={styles.button}
              href={baselineHref(
                locale,
                target,
                data.baseline.id,
                data.page - 1,
              )}
              scroll={false}
            >
              {copy.previous}
            </Link>
          ) : null}
          {data.page < pages ? (
            <Link
              className={styles.button}
              href={baselineHref(
                locale,
                target,
                data.baseline.id,
                data.page + 1,
              )}
              scroll={false}
            >
              {copy.next}
            </Link>
          ) : null}
        </div>
      </nav>
    </>
  );
}

export async function generateMetadata(): Promise<Metadata> {
  return { title: getSecurityCopy(await resolveLocale()).title };
}

export default async function SecurityBaselinePage({
  searchParams,
}: {
  searchParams: Promise<{
    target?: string | string[];
    baseline?: string | string[];
    page?: string | string[];
  }>;
}) {
  const locale = await resolveLocale();
  const copy = getSecurityCopy(locale);
  const scanCopy = getSecurityScanCopy(locale);
  const domainCopy = getDomainSecurityCopy(locale);
  const session = await getServerSession();
  requireTenantScope(session, locale);
  const tenant = selectedTenant(session, await cookies());
  if (!tenant) redirect(`/${locale}/access-unavailable`);
  if (!hasPermission(tenant, "inventory.view")) redirect(`/${locale}`);
  const canManageBaselines = hasPermission(tenant, "security.baselines.manage");

  const query = await searchParams;
  const target: SecurityBaselineTarget =
    query.target === "server" || query.target === "client"
      ? query.target
      : "all";
  const requestedBaseline =
    typeof query.baseline === "string" ? query.baseline : undefined;
  const requestedPage =
    typeof query.page === "string" && /^[1-9]\d{0,6}$/.test(query.page)
      ? Number(query.page)
      : 1;
  const response = await getSecurityBaselineCatalog(tenant.id, target);
  if (!response.sessionValid) redirect(`/${locale}/login`);
  if (response.forbidden) redirect(`/${locale}/access-unavailable`);
  const catalog = response.data;
  const selection = requestedBaseline
    ? catalog?.results.find((baseline) => baseline.id === requestedBaseline)
    : undefined;
  const [systemsResponse, scansResponse] = selection
    ? await Promise.all([
        getSecurityBaselineSystems(tenant.id, selection.id, requestedPage),
        selection.assessment_state === "native-read-only"
          ? getSecurityBaselineScans(tenant.id, selection.id)
          : Promise.resolve(null),
      ])
    : [null, null];
  if (systemsResponse && !systemsResponse.sessionValid)
    redirect(`/${locale}/login`);
  if (systemsResponse?.forbidden) redirect(`/${locale}/access-unavailable`);
  if (scansResponse && !scansResponse.sessionValid)
    redirect(`/${locale}/login`);
  if (scansResponse?.forbidden) redirect(`/${locale}/access-unavailable`);
  const systems = systemsResponse?.data;
  const baseline = systems?.baseline ?? selection;
  const currentHref = baselineHref(
    locale,
    target,
    requestedBaseline ?? selection?.id,
    requestedPage,
  );
  const statuses: SecurityBaselineStatus[] = [
    "compliant",
    "non_compliant",
    "unknown",
    "error",
    "stale",
  ];

  return (
    <ConsoleShell
      session={session}
      tenant={tenant}
      activeSection="security-baseline"
    >
      <section className="page-heading" aria-labelledby="security-heading">
        <div>
          <p className="eyebrow">
            {copy.navigation} / {copy.baselineNavigation}
          </p>
          <h1 id="security-heading">{copy.title}</h1>
          <p>{copy.description}</p>
        </div>
        <div className={styles.headingActions}>
          <span className="read-only-badge">
            {catalog?.capabilities.assessment
              ? scanCopy.readOnly
              : copy.readOnly}
          </span>
          {canManageBaselines ? (
            <Link
              className={styles.button}
              href={`/${locale}/administration/security/baselines` as Route}
            >
              {copy.manageVisibility}
            </Link>
          ) : null}
          {hasPermission(tenant, "security.gpo_imports.run") &&
          (!baseline || baseline.deployment_state === "bundled") ? (
            <Link
              className={styles.button}
              href={
                `/${locale}/security/windows-gpos?baseline=${encodeURIComponent(baseline?.id ?? requestedBaseline ?? "")}` as Route
              }
            >
              {copy.openGpoDeployment}
            </Link>
          ) : null}
          <a className={styles.button} href={currentHref}>
            <RefreshCw size={15} aria-hidden="true" />
            {copy.reload}
          </a>
        </div>
      </section>

      {!catalog ? (
        <div className={styles.empty} role="status">
          <CircleHelp size={26} aria-hidden="true" />
          <strong>{copy.unavailable}</strong>
          <p>{copy.unavailableHint}</p>
        </div>
      ) : (
        <div className={styles.content}>
          <dl className={styles.inventory} aria-label={copy.application}>
            {[
              {
                label: copy.inventoried,
                value: catalog.inventory.total,
                icon: Layers,
              },
              {
                label: copy.servers,
                value: catalog.inventory.servers,
                icon: Server,
              },
              {
                label: copy.clients,
                value: catalog.inventory.clients,
                icon: Monitor,
              },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label}>
                <dt>
                  <Icon size={17} aria-hidden="true" />
                  {label}
                </dt>
                <dd>{value.toLocaleString(documentLocale(locale))}</dd>
              </div>
            ))}
            {catalog.application_groups.map((group) => (
              <div
                key={group.id}
                className={styles.applicationTile}
                data-application-group={group.id}
              >
                <dt>
                  <ShieldCheck size={17} aria-hidden="true" />
                  <span>
                    {group.provider === "microsoft"
                      ? "Microsoft"
                      : group.provider}
                    <br />
                    {copy.applicationTargets[group.target]}
                  </span>
                </dt>
                <dd>
                  <strong>
                    {formatPercent(group.summary.application_percent, locale)}
                  </strong>
                  <span className={styles.tileCaption}>
                    {group.summary.applicable === 0
                      ? copy.noSystems
                      : `${group.summary.applied} / ${group.summary.applicable} · ${copy.confirmed}`}
                  </span>
                  {group.summary.unknown > 0 ? (
                    <span className={styles.tileCaption}>
                      {copy.applicationUnknown}: {group.summary.unknown}
                    </span>
                  ) : null}
                  {group.summary.partial > 0 ? (
                    <span className={styles.tileCaption}>
                      {copy.applicationPartial}: {group.summary.partial}
                    </span>
                  ) : null}
                </dd>
              </div>
            ))}
          </dl>
          <p className={styles.applicationHint}>{copy.applicationHint}</p>

          {catalog.inventory.unclassified > 0 ||
          catalog.inventory.unmatched > 0 ? (
            <div className={styles.mappingNote}>
              <CircleHelp size={18} aria-hidden="true" />
              <div>
                <p>
                  <strong>
                    {copy.unclassified}: {catalog.inventory.unclassified}
                  </strong>
                  <span aria-hidden="true"> · </span>
                  <strong>
                    {copy.unmatched}: {catalog.inventory.unmatched}
                  </strong>
                </p>
                <p>{copy.mappingHint}</p>
              </div>
            </div>
          ) : null}

          <section className={styles.panel} aria-labelledby="catalog-heading">
            <header className={styles.panelHeader}>
              <div>
                <h2 id="catalog-heading">{copy.catalog}</h2>
                <p>{copy.catalogHint}</p>
              </div>
              <span className={styles.provider}>{copy.providers}</span>
            </header>
            <nav className={styles.filters} aria-label={copy.filterLabel}>
              {(["all", "server", "client"] as const).map((value) => (
                <Link
                  key={value}
                  href={baselineHref(locale, value)}
                  className={`${styles.filter} ${target === value ? styles.filterActive : ""}`}
                  aria-current={target === value ? "page" : undefined}
                  scroll={false}
                >
                  {copy.targets[value]}
                </Link>
              ))}
            </nav>
            {catalog.hidden_count > 0 ? (
              <div className={styles.explanation}>
                <EyeOff size={18} aria-hidden="true" />
                <div>
                  <p>
                    <strong>
                      {copy.hiddenCount}: {catalog.hidden_count}
                    </strong>
                  </p>
                  <p>{copy.hiddenHint}</p>
                </div>
              </div>
            ) : null}
            {catalog.results.length === 0 ? (
              <div className={styles.empty}>
                <p>
                  {catalog.hidden_count > 0
                    ? copy.allHidden
                    : copy.catalogEmpty}
                </p>
              </div>
            ) : (
              <div className={styles.tableScroll}>
                <table className={styles.catalogTable}>
                  <caption className="sr-only">{copy.catalog}</caption>
                  <thead>
                    <tr>
                      <th scope="col">{copy.baseline}</th>
                      <th scope="col">{copy.targetRelease}</th>
                      <th scope="col">{copy.compliance}</th>
                      <th scope="col">{copy.coverage}</th>
                      <th scope="col">{copy.applicable}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {catalog.results.map((entry) => (
                      <tr
                        key={entry.id}
                        className={
                          selection?.id === entry.id
                            ? styles.selectedRow
                            : undefined
                        }
                      >
                        <th scope="row">
                          <Link
                            href={baselineHref(locale, target, entry.id)}
                            className={styles.baselineLink}
                            aria-current={
                              selection?.id === entry.id ? "true" : undefined
                            }
                            scroll={false}
                          >
                            <ShieldCheck size={18} aria-hidden="true" />
                            <span>{entry.name}</span>
                          </Link>
                          <small>{entry.provider_label}</small>
                          <small>
                            {copy.availabilityStates[entry.deployment_state]}
                          </small>
                        </th>
                        <td>
                          <span>{copy.targets[entry.target]}</span>
                          <small>{entry.release}</small>
                        </td>
                        <td>
                          <Compliance
                            baseline={entry}
                            locale={locale}
                            copy={copy}
                          />
                        </td>
                        <td>
                          <strong>
                            {formatPercent(
                              entry.summary.coverage_percent,
                              locale,
                            )}
                          </strong>
                          <small>
                            {entry.summary.assessed} /{" "}
                            {entry.summary.applicable} {copy.assessed}
                          </small>
                        </td>
                        <td>
                          <strong>{entry.summary.applicable}</strong>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className={styles.explanation}>
              <CircleHelp size={18} aria-hidden="true" />
              <p>{copy.scope}</p>
            </div>
            {!catalog.capabilities.assessment ? (
              <div className={styles.assessmentNotice} role="status">
                <ScanLine size={20} aria-hidden="true" />
                <p>{copy.assessmentPending}</p>
              </div>
            ) : null}

            {requestedBaseline && !selection ? (
              <div className={styles.empty} role="status">
                <strong>{copy.selectionMissing}</strong>
                <p>{copy.selectBaseline}</p>
              </div>
            ) : null}

            {baseline ? (
              <SecurityBaselineDetails
                baselineId={baseline.id}
                className={styles.baselineDetails}
              >
                <summary className={styles.detailsToggle}>
                  <h3 id="baseline-details-heading">
                    <span>{copy.details}</span>
                    {baseline.name}
                  </h3>
                  <ChevronDown size={20} aria-hidden="true" />
                </summary>
                <header className={styles.panelHeader}>
                  <Link
                    className={styles.sourceLink}
                    href={baselineHref(locale, target)}
                    scroll={false}
                  >
                    {copy.clearSelection}
                  </Link>
                  <a
                    className={styles.sourceLink}
                    href={baseline.source_url}
                    target="_blank"
                    rel="noreferrer noopener"
                  >
                    {copy.openSource}
                    <ExternalLink size={15} aria-hidden="true" />
                  </a>
                </header>
                <dl className={styles.packageDetails}>
                  <div>
                    <dt>{copy.provider}</dt>
                    <dd>{baseline.provider_label}</dd>
                  </div>
                  <div>
                    <dt>{copy.package}</dt>
                    <dd>{baseline.package_name}</dd>
                  </div>
                  <div>
                    <dt>{copy.availability}</dt>
                    <dd>
                      {copy.availabilityStates[baseline.deployment_state]}
                    </dd>
                  </div>
                  <div>
                    <dt>{copy.revision}</dt>
                    <dd>{baseline.revision || "—"}</dd>
                  </div>
                  <div>
                    <dt>{copy.profiles}</dt>
                    <dd>
                      {baseline.profiles
                        .map(
                          (profile) =>
                            copy.roles[profile as keyof typeof copy.roles] ??
                            profile,
                        )
                        .join(" · ") || "—"}
                    </dd>
                  </div>
                  <div>
                    <dt>{copy.verifiedAt}</dt>
                    <dd>{formatDate(baseline.verified_at, locale)}</dd>
                  </div>
                  <div>
                    <dt>{copy.lastAssessed}</dt>
                    <dd>
                      {baseline.summary.last_assessed_at
                        ? formatDate(baseline.summary.last_assessed_at, locale)
                        : copy.notAssessed}
                    </dd>
                  </div>
                </dl>
                {baseline.assessment_state === "native-read-only" ? (
                  <SecurityBaselineScansPanel
                    key={`${tenant.id}:${baseline.id}:${requestedPage}`}
                    baselineId={baseline.id}
                    applicable={baseline.summary.applicable}
                    systems={systems?.results ?? []}
                    initialJobs={scansResponse?.data ?? null}
                    tenantId={tenant.id}
                    csrfToken={session.csrf_token}
                    canRun={hasPermission(tenant, "security.scans.run")}
                    locale={locale}
                    logsLabel={domainCopy.scanLogs}
                    scanCopy={scanCopy}
                  />
                ) : (
                  <div className={styles.assessmentNotice} role="status">
                    <ScanLine size={20} aria-hidden="true" />
                    <p>{copy.assessmentPending}</p>
                  </div>
                )}
                <dl className={styles.statusSummary}>
                  {statuses.map((status) => (
                    <div key={status}>
                      <dt className={styles.status} data-state={status}>
                        <span aria-hidden="true" />
                        {copy.statuses[status]}
                      </dt>
                      <dd>{baseline.summary[status]}</dd>
                    </div>
                  ))}
                </dl>
                <div className={styles.systemsHeading}>
                  <h4>{copy.systems}</h4>
                  <p>{copy.systemsHint}</p>
                </div>
                {systemsResponse?.notFound ? (
                  <div className={styles.empty} role="status">
                    <p>{copy.pageMissing}</p>
                    <Link
                      className={styles.button}
                      href={baselineHref(locale, target, baseline.id)}
                    >
                      {copy.firstPage}
                      <ArrowRight size={15} aria-hidden="true" />
                    </Link>
                  </div>
                ) : !systems ? (
                  <div className={styles.empty} role="status">
                    <p>{copy.systemsUnavailable}</p>
                  </div>
                ) : systems.count === 0 ? (
                  <div className={styles.empty}>
                    <p>{copy.noMatching}</p>
                  </div>
                ) : (
                  <SystemsTable
                    data={systems}
                    locale={locale}
                    copy={copy}
                    target={target}
                    scanCopy={scanCopy}
                  />
                )}
              </SecurityBaselineDetails>
            ) : null}
          </section>

          <section
            className={styles.modules}
            aria-labelledby="security-modules-heading"
          >
            <div>
              <h2 id="security-modules-heading">{copy.modules}</h2>
              <p>{copy.moduleHint}</p>
            </div>
            <ul>
              {[
                { label: copy.moduleCatalog, ready: true, icon: ShieldCheck },
                {
                  label: copy.moduleAssessment,
                  ready: catalog.capabilities.assessment,
                  icon: ScanLine,
                },
                {
                  label: copy.moduleDeployment,
                  ready:
                    catalog.capabilities.deployment &&
                    catalog.capabilities.collections,
                  icon: ArrowDownToLine,
                },
              ].map(({ label, ready, icon: Icon }) => (
                <li key={label}>
                  <Icon size={17} aria-hidden="true" />
                  <span>{label}</span>
                  <small>{ready ? copy.ready : copy.planned}</small>
                </li>
              ))}
            </ul>
          </section>
          <p className={styles.catalogMeta}>
            {copy.catalogRevision}: {catalog.catalog_revision}
            <span aria-hidden="true"> · </span>
            {copy.generatedAt}:{" "}
            <time dateTime={catalog.generated_at}>
              {formatDate(catalog.generated_at, locale)}
            </time>
          </p>
        </div>
      )}
    </ConsoleShell>
  );
}
