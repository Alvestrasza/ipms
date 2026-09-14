/**
 * File Name: logs-gpo-detail.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Display a server-authorized pilot receipt and copy its local approval document.
 */
"use client";
import { Copy } from "lucide-react";
import { useState } from "react";
import { documentLocale, type Locale } from "@/i18n/config";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import { getJobLogsCopy } from "@/i18n/job-logs-copy";
import type { GpoImportLogDetail } from "@/lib/job-log-types";
import styles from "./logs-page.module.css";

export function LogsGpoDetail({
  job,
  locale,
}: {
  job: GpoImportLogDetail;
  locale: Locale;
}) {
  const copy = getDomainSecurityCopy(locale);
  const logs = getJobLogsCopy(locale);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const date = new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  });
  async function copyDocument() {
    if (!job.approval_document) return;
    setNotice("");
    setError("");
    try {
      await navigator.clipboard.writeText(
        JSON.stringify(job.approval_document, null, 2),
      );
      setNotice(copy.copied);
    } catch {
      setError(copy.copyFailed);
    }
  }
  return (
    <div className={styles.detail}>
      <div className={styles.detailHeading}>
        <h3>{job.pilot_display_name}</h3>
        <span className={styles.status}>{copy.states[job.status]}</span>
      </div>
      <dl className={styles.metadata}>
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
          <dt>{logs.system}</dt>
          <dd>
            {job.hostname} · Tier {job.tier}
          </dd>
        </div>
        <div>
          <dt>{logs.baseline}</dt>
          <dd>{job.baseline_id}</dd>
        </div>
        <div>
          <dt>{logs.componentId}</dt>
          <dd>
            <code>{job.backup_id}</code>
          </dd>
        </div>
        <div>
          <dt>{logs.requested}</dt>
          <dd>{date.format(new Date(job.requested_at))}</dd>
        </div>
        <div>
          <dt>{logs.completed}</dt>
          <dd>
            {job.completed_at ? date.format(new Date(job.completed_at)) : "—"}
          </dd>
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
      </dl>
      {job.status === "staged" ? <p>{copy.staged}</p> : null}
      {job.approval_document ? (
        <details className={styles.approval} open>
          <summary>{copy.approval}</summary>
          <p>{copy.approvalHint}</p>
          <pre>{JSON.stringify(job.approval_document, null, 2)}</pre>
          <button
            className="outline-button"
            type="button"
            onClick={copyDocument}
          >
            <Copy size={15} aria-hidden="true" />
            {copy.copyApproval}
          </button>
        </details>
      ) : (
        <p>{logs.noApproval}</p>
      )}
      {notice ? <p role="status">{notice}</p> : null}
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
