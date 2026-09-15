/**
 * File Name: logs-gpo-detail.tsx
 * Version: v0.2.0 | Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Review exact disabled/unlinked GPO imports and submit scoped Portal approval.
 */
"use client";
import { Copy } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { documentLocale, type Locale } from "@/i18n/config";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import { getGpoApprovalCopy } from "@/i18n/gpo-approval-copy";
import { getGpoProductionCopy } from "@/i18n/gpo-production-copy";
import { getJobLogsCopy } from "@/i18n/job-logs-copy";
import { isGpoImportJob } from "@/lib/domain-security-validation";
import {
  type GpoImportLogDetail,
  isGpoImportLogDetail,
} from "@/lib/job-log-types";
import { GpoStateReview } from "./gpo-state-review";
import styles from "./logs-page.module.css";

export function LogsGpoDetail({
  job: initialJob,
  locale,
  tenantId,
  csrfToken,
}: {
  job: GpoImportLogDetail;
  locale: Locale;
  tenantId: string;
  csrfToken: string;
}) {
  const copy = getDomainSecurityCopy(locale);
  const approval = getGpoApprovalCopy(locale);
  const logs = getJobLogsCopy(locale);
  const production = getGpoProductionCopy(locale);
  const router = useRouter();
  const [job, setJob] = useState<GpoImportLogDetail | null>(initialJob);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const mounted = useRef(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      request.current?.abort();
    };
  }, []);
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
  const canApprove = Boolean(
    job?.approval_mode === "portal" &&
      job.can_approve &&
      job.review &&
      job.approval_document &&
      /^[0-9a-f]{64}$/.test(job.input_digest) &&
      !busy,
  );

  async function refresh() {
    if (request.current) return;
    const controller = new AbortController();
    request.current = controller;
    const current = () => mounted.current && request.current === controller;
    setJob(null);
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(
        `/api/v1/logs/gpo-imports/${encodeURIComponent(initialJob.id)}/`,
        {
          credentials: "same-origin",
          cache: "no-store",
          headers: { "X-IPMS-Tenant-ID": tenantId },
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(15_000),
          ]),
        },
      );
      const payload: unknown = response.ok ? await response.json() : null;
      if (!current()) return;
      if (!isGpoImportLogDetail(payload) || payload.id !== initialJob.id) {
        setError(
          response.status === 401
            ? approval.sessionExpired
            : approval.reviewUnavailable,
        );
        return;
      }
      setJob(payload);
    } catch {
      if (current()) setError(approval.reviewUnavailable);
    } finally {
      if (current()) {
        request.current = null;
        setBusy(false);
      }
    }
  }

  async function approve() {
    if (!job || !canApprove || request.current) return;
    const controller = new AbortController();
    request.current = controller;
    const current = () => mounted.current && request.current === controller;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(
        `/api/v1/security/gpo-imports/${encodeURIComponent(job.id)}/approve/`,
        {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(20_000),
          ]),
          body: JSON.stringify({
            input_digest: job.input_digest,
            policy_revision: job.policy_revision,
          }),
        },
      );
      const payload: unknown = response.ok ? await response.json() : null;
      if (!current()) return;
      if (!response.ok) {
        setJob(null);
        setError(
          response.status === 401
            ? approval.sessionExpired
            : response.status >= 500
              ? approval.approvalUncertain
              : approval.reviewInvalidated,
        );
        return;
      }
      if (
        !isGpoImportJob(payload) ||
        payload.id !== job.id ||
        payload.input_digest !== job.input_digest ||
        payload.policy_revision !== job.policy_revision ||
        !payload.approved_at ||
        !payload.approved_by ||
        payload.can_approve
      )
        throw new Error("invalid_approval_receipt");
      setJob({ ...job, ...payload });
      setNotice(approval.approved);
      router.refresh();
    } catch {
      if (current()) {
        setJob(null);
        setError(approval.approvalUncertain);
      }
    } finally {
      if (current()) {
        request.current = null;
        setBusy(false);
      }
    }
  }

  async function copyDocument() {
    if (job?.approval_mode !== "local" || !job.approval_document) return;
    setNotice("");
    setError("");
    try {
      await navigator.clipboard.writeText(
        JSON.stringify(job.approval_document, null, 2),
      );
      if (mounted.current) setNotice(copy.copied);
    } catch {
      if (mounted.current) setError(copy.copyFailed);
    }
  }
  const blocker = job?.approval_blocker;
  const blockerText =
    blocker === "four_eyes_required"
      ? approval.blockers.four_eyes_required
      : blocker === "domain_tier_not_authorized"
        ? approval.blockers.authorization_required
        : blocker === "approval_configuration_changed"
          ? approval.blockers.policy_changed
          : blocker === "job_expired"
            ? approval.blockers.expired
            : blocker === "local_approval_required"
              ? approval.blockers.legacy_local
              : approval.blockers.unavailable;

  return (
    <div className={styles.detail} aria-busy={busy}>
      <div className={styles.detailHeading}>
        {job ? (
          <h3>{job.display_name ?? job.pilot_display_name}</h3>
        ) : (
          <h3>{approval.centralTitle}</h3>
        )}
        <button
          className="outline-button"
          type="button"
          disabled={busy}
          onClick={() => void refresh()}
        >
          {approval.refreshReview}
        </button>
      </div>
      {job ? (
        <>
          <p>
            <span className={styles.status}>
              {job.status === "awaiting_approval"
                ? job.approved_at
                  ? approval.approvedWaiting
                  : job.approval_mode === "portal"
                    ? approval.awaitingPortal
                    : approval.awaitingLocal
                : copy.states[job.status]}
            </span>
          </p>
          <dl className={styles.metadata}>
            {job.operation && job.operation !== "create_unlinked_pilot" ? (
              <div>
                <dt>{production.operation}</dt>
                <dd>{production.actions[job.operation]}</dd>
              </div>
            ) : null}
            <div>
              <dt>{logs.requestId}</dt>
              <dd>
                <code>{job.id}</code>
              </dd>
            </div>
            <div>
              <dt>{logs.domain}</dt>
              <dd>{job.domain}</dd>
            </div>
            <div>
              <dt>{approval.dc}</dt>
              <dd>
                {job.dc_fqdn || job.hostname} · Tier {job.tier}
              </dd>
            </div>
            <div>
              <dt>{logs.baseline}</dt>
              <dd>{job.baseline_id}</dd>
            </div>
            <div>
              <dt>{approval.component}</dt>
              <dd>{job.review?.component_name ?? job.backup_id}</dd>
            </div>
            <div>
              <dt>{logs.componentId}</dt>
              <dd>
                <code>{job.backup_id}</code>
              </dd>
            </div>
            <div>
              <dt>{approval.requestedBy}</dt>
              <dd>{job.requested_by_name}</dd>
            </div>
            <div>
              <dt>{logs.requested}</dt>
              <dd>{date(job.requested_at)}</dd>
            </div>
            <div>
              <dt>{approval.expires}</dt>
              <dd>{date(job.expires_at)}</dd>
            </div>
            <div>
              <dt>{logs.completed}</dt>
              <dd>{date(job.completed_at)}</dd>
            </div>
            <div>
              <dt>{logs.result}</dt>
              <dd>
                <code>{job.error_code || "—"}</code>
              </dd>
            </div>
            {job.gpo_guid ? (
              <div>
                <dt>GPO GUID</dt>
                <dd>
                  <code>{job.gpo_guid}</code>
                </dd>
              </div>
            ) : null}
            {job.approved_by ? (
              <div>
                <dt>{approval.approvedBy}</dt>
                <dd>{job.approved_by_name ?? "—"}</dd>
              </div>
            ) : null}
            {job.approved_at ? (
              <div>
                <dt>{approval.approvedAt}</dt>
                <dd>{date(job.approved_at)}</dd>
              </div>
            ) : null}
          </dl>
          {job.status === "staged" ? (
            <p>{job.managed_id ? production.description : copy.staged}</p>
          ) : null}
          {job.approval_mode === "inspection" ? (
            <p>{production.inspectOnly}</p>
          ) : null}
          {job.approval_mode === "portal" ? (
            <section
              className={styles.approval}
              aria-labelledby="central-gpo-review-heading"
            >
              <h4 id="central-gpo-review-heading">{approval.centralTitle}</h4>
              <p>
                {job.managed_id ? production.actionHint : approval.centralHint}
              </p>
              {job.operation === "activate_managed_gpo" ? (
                <p>{production.activation}</p>
              ) : null}
              {job.operation === "link_managed_gpo" ? (
                <p>{production.linkBoundary}</p>
              ) : null}
              {job.operation === "deactivate_managed_gpo" ? (
                <p>{production.deactivateBoundary}</p>
              ) : null}
              {job.review?.expected_state ? (
                <GpoStateReview
                  state={job.review.expected_state}
                  displayName={job.display_name ?? job.pilot_display_name}
                  locale={locale}
                />
              ) : null}
              {job.review?.safety_review &&
              job.operation === "activate_managed_gpo" ? (
                <ul>
                  <li>
                    {production.management}:{" "}
                    {job.review.safety_review.management_access ? "✓" : "—"}
                  </li>
                  <li>
                    {production.recovery}:{" "}
                    {job.review.safety_review.recovery_access ? "✓" : "—"}
                  </li>
                </ul>
              ) : null}
              <p>
                {job.four_eyes_required
                  ? approval.fourEyesRequired
                  : approval.selfApprovalAllowed}
              </p>
              <dl className={styles.metadata}>
                <div>
                  <dt>{approval.revision}</dt>
                  <dd>{job.policy_revision}</dd>
                </div>
                <div>
                  <dt>{approval.inputDigest}</dt>
                  <dd>
                    <code>{job.input_digest}</code>
                  </dd>
                </div>
                {job.review ? (
                  <div>
                    <dt>{approval.hash}</dt>
                    <dd>
                      <code>{job.review.artifact_sha256}</code>
                    </dd>
                  </div>
                ) : null}
              </dl>
              {job.review ? (
                <>
                  <details className={styles.approval}>
                    <summary>{approval.reviewReport}</summary>
                    <pre>{job.review.report_xml}</pre>
                  </details>
                  <details className={styles.approval}>
                    <summary>{approval.files}</summary>
                    <ul className={styles.reviewFiles}>
                      {job.review.files.map((file) => (
                        <li key={file.path}>
                          <strong>{file.path}</strong>
                          <span>
                            {new Intl.NumberFormat(
                              documentLocale(locale),
                            ).format(file.bytes)}{" "}
                            {approval.bytes}
                          </span>
                          <code>{file.sha256}</code>
                        </li>
                      ))}
                    </ul>
                  </details>
                  {job.approval_document ? (
                    <details className={styles.approval}>
                      <summary>{approval.reviewDocument}</summary>
                      <pre>
                        {JSON.stringify(job.approval_document, null, 2)}
                      </pre>
                    </details>
                  ) : null}
                </>
              ) : job.status === "awaiting_approval" ? (
                <p>{approval.reviewUnavailable}</p>
              ) : null}
              {job.status === "awaiting_approval" &&
              !job.approved_at &&
              !job.can_approve ? (
                <p role="status">{blockerText}</p>
              ) : null}
              {job.status === "awaiting_approval" && !job.approved_at ? (
                <button
                  className={styles.applyButton}
                  type="button"
                  disabled={!canApprove}
                  onClick={() => void approve()}
                >
                  {busy ? approval.approving : approval.approve}
                </button>
              ) : null}
            </section>
          ) : (
            <section
              className={styles.approval}
              aria-labelledby="legacy-gpo-review-heading"
            >
              <h4 id="legacy-gpo-review-heading">{approval.legacyTitle}</h4>
              <p>{approval.legacyHint}</p>
              {job.approval_document ? (
                <details className={styles.approval} open>
                  <summary>{copy.approval}</summary>
                  <p>{copy.approvalHint}</p>
                  <pre>{JSON.stringify(job.approval_document, null, 2)}</pre>
                  <button
                    className="outline-button"
                    type="button"
                    onClick={() => void copyDocument()}
                  >
                    <Copy size={15} aria-hidden="true" />
                    {copy.copyApproval}
                  </button>
                </details>
              ) : (
                <p>{logs.noApproval}</p>
              )}
            </section>
          )}
        </>
      ) : !error ? (
        <p role="status">{approval.reviewUnavailable}</p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
