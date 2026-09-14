/**
 * File Name: security-baseline-scans.tsx
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Request read-only scans and refresh existing jobs within a bounded window.
 */
"use client";

import { RefreshCw, ScanLine } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { documentLocale, type Locale } from "@/i18n/config";
import type { SecurityCopy } from "@/i18n/security-copy";
import type { SecurityScanCopy } from "@/i18n/security-scan-copy";
import {
  isSecurityScanReceipt,
  isSecurityScans,
} from "@/lib/security-scan-validation";
import type {
  SecurityBaselineScanReceipt,
  SecurityBaselineScans,
  SecurityBaselineSystem,
} from "@/lib/security-types";
import styles from "./security-baseline-scans.module.css";

const POLL_WINDOW = 5 * 60_000;

export function SecurityBaselineScansPanel({
  baselineId,
  applicable,
  systems,
  initialJobs,
  tenantId,
  csrfToken,
  canRun,
  locale,
  copy,
  scanCopy,
}: {
  baselineId: string;
  applicable: number;
  systems: Pick<SecurityBaselineSystem, "id" | "hostname">[];
  initialJobs: SecurityBaselineScans | null;
  tenantId: string;
  csrfToken: string;
  canRun: boolean;
  locale: Locale;
  copy: SecurityCopy;
  scanCopy: SecurityScanCopy;
}) {
  const [jobs, setJobs] = useState(initialJobs);
  const [receipt, setReceipt] = useState<SecurityBaselineScanReceipt | null>(
    null,
  );
  const [target, setTarget] = useState("all");
  const [busy, setBusy] = useState<"queue" | "refresh" | null>(null);
  const [error, setError] = useState(
    initialJobs ? "" : scanCopy.statusUnavailable,
  );
  const [uncertain, setUncertain] = useState(false);
  const [deadline, setDeadline] = useState(() => Date.now() + POLL_WINDOW);
  const [paused, setPaused] = useState(false);
  const [pollCycle, setPollCycle] = useState(0);
  const mounted = useRef(false);
  const activeRequest = useRef<AbortController | null>(null);
  const endpoint = `/api/v1/security/baselines/${encodeURIComponent(baselineId)}/scans/`;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeRequest.current?.abort();
      activeRequest.current = null;
    };
  }, []);

  const request = useCallback(
    async (controller: AbortController, body?: { system_ids?: string[] }) => {
      const response = await fetch(endpoint, {
        method: body ? "POST" : "GET",
        credentials: "same-origin",
        cache: "no-store",
        signal: AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(15_000),
        ]),
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      if (!response.ok || (body && response.status !== 202)) {
        if (response.status === 409) {
          const payload: unknown = await response.json();
          if (
            typeof payload === "object" &&
            payload !== null &&
            "error" in payload
          ) {
            const detail = payload.error;
            if (
              typeof detail === "object" &&
              detail !== null &&
              "code" in detail
            ) {
              if (detail.code === "security_scan_scope_too_large")
                throw new Error(scanCopy.limit);
              if (detail.code === "security_scan_queue_full")
                throw new Error(scanCopy.queueFull);
            }
          }
        }
        throw new Error(
          response.status === 401
            ? scanCopy.sessionExpired
            : response.status === 403
              ? scanCopy.permission
              : response.status === 404
                ? scanCopy.missing
                : response.status === 400
                  ? scanCopy.invalid
                  : body
                    ? scanCopy.requestFailed
                    : scanCopy.statusUnavailable,
        );
      }
      return response.json() as Promise<unknown>;
    },
    [endpoint, csrfToken, tenantId, scanCopy],
  );

  const refresh = useCallback(
    async (manual = true) => {
      if (!mounted.current || activeRequest.current) return;
      const controller = new AbortController();
      activeRequest.current = controller;
      setBusy("refresh");
      const current = () =>
        mounted.current && activeRequest.current === controller;
      try {
        const payload = await request(controller);
        if (!isSecurityScans(payload))
          throw new Error(scanCopy.statusUnavailable);
        if (!current()) return;
        setJobs(payload);
        setError("");
        setUncertain(false);
        if (manual) {
          setDeadline(Date.now() + POLL_WINDOW);
          setPaused(false);
        }
      } catch (caught) {
        if (!current()) return;
        const known = [
          scanCopy.sessionExpired,
          scanCopy.permission,
          scanCopy.missing,
        ];
        setError(
          caught instanceof Error && known.includes(caught.message)
            ? caught.message
            : scanCopy.statusUnavailable,
        );
      } finally {
        if (current()) {
          activeRequest.current = null;
          setBusy(null);
        }
      }
    },
    [request, scanCopy],
  );

  useEffect(() => {
    if (busy || error || !jobs?.active || paused) return;
    const timer = window.setTimeout(() => {
      if (Date.now() >= deadline) {
        setPaused(true);
        return;
      }
      if (document.visibilityState === "visible") void refresh(false);
      setPollCycle(pollCycle + 1);
    }, 5_000);
    return () => window.clearTimeout(timer);
  }, [busy, error, jobs?.active, paused, deadline, pollCycle, refresh]);

  async function queue() {
    if (
      !canRun ||
      !mounted.current ||
      activeRequest.current ||
      uncertain ||
      error ||
      !jobs ||
      applicable === 0 ||
      (target === "all" && applicable > 250)
    )
      return;
    if (target !== "all" && !systems.some((system) => system.id === target))
      return;
    const controller = new AbortController();
    activeRequest.current = controller;
    setBusy("queue");
    setReceipt(null);
    const current = () =>
      mounted.current && activeRequest.current === controller;
    try {
      const payload = await request(
        controller,
        target === "all" ? {} : { system_ids: [target] },
      );
      if (!isSecurityScanReceipt(payload))
        throw new Error(scanCopy.requestFailed);
      if (!current()) return;
      setReceipt(payload);
      setDeadline(Date.now() + POLL_WINDOW);
      setPaused(false);
      try {
        const latest = await request(controller);
        if (!isSecurityScans(latest))
          throw new Error(scanCopy.statusUnavailable);
        if (current()) setJobs(latest);
      } catch {
        if (current()) setError(scanCopy.statusUnavailable);
      }
    } catch (caught) {
      if (!current()) return;
      setUncertain(true);
      const known = [
        scanCopy.sessionExpired,
        scanCopy.permission,
        scanCopy.missing,
        scanCopy.invalid,
        scanCopy.limit,
        scanCopy.queueFull,
      ];
      setError(
        caught instanceof Error && known.includes(caught.message)
          ? caught.message
          : scanCopy.requestFailed,
      );
    } finally {
      if (current()) {
        activeRequest.current = null;
        setBusy(null);
      }
    }
  }

  const date = (value: string | null) =>
    value
      ? new Intl.DateTimeFormat(documentLocale(locale), {
          dateStyle: "medium",
          timeStyle: "short",
          timeZone: "UTC",
        }).format(new Date(value))
      : "—";
  return (
    <section className={styles.panel} aria-labelledby="baseline-scans-heading">
      <header className={styles.header}>
        <div>
          <h3 id="baseline-scans-heading">{scanCopy.title}</h3>
          <p>{scanCopy.boundary}</p>
          <p>{scanCopy.requirement}</p>
        </div>
      </header>
      {canRun ? (
        <div className={styles.queue}>
          <label className={styles.field}>
            {scanCopy.target}
            <select
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              disabled={Boolean(busy)}
            >
              <option value="all">
                {scanCopy.allSystems} ({applicable})
              </option>
              {systems.length ? (
                <optgroup label={scanCopy.pageSystems}>
                  {systems.map((system) => (
                    <option key={system.id} value={system.id}>
                      {system.hostname || system.id}
                    </option>
                  ))}
                </optgroup>
              ) : null}
            </select>
          </label>
          <button
            className={styles.button}
            type="button"
            onClick={() => void queue()}
            disabled={
              Boolean(busy) ||
              uncertain ||
              Boolean(error) ||
              !jobs ||
              applicable === 0 ||
              (target === "all" && applicable > 250)
            }
          >
            <ScanLine size={16} aria-hidden="true" />
            {busy === "queue" ? scanCopy.queuing : scanCopy.queue}
          </button>
          {applicable > 250 ? (
            <p className={styles.hint}>{scanCopy.limit}</p>
          ) : null}
        </div>
      ) : null}
      {receipt ? (
        <div className={styles.receipt} role="status">
          <strong>{scanCopy.receipt}</strong>
          <dl>
            {[
              { label: scanCopy.queued, count: receipt.queued },
              { label: scanCopy.existing, count: receipt.existing },
              { label: scanCopy.unavailableAgents, count: receipt.unavailable },
            ].map((entry) => (
              <div key={entry.label}>
                <dt>{entry.label}</dt>
                <dd>{entry.count}</dd>
              </div>
            ))}
          </dl>
          {receipt.unavailable > 0 ? <p>{scanCopy.unavailableHint}</p> : null}
        </div>
      ) : null}
      {error ? (
        <p className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
      <div className={styles.jobHeading}>
        <div>
          <h4>{scanCopy.jobs}</h4>
          <p>{scanCopy.recent}</p>
          {jobs ? (
            <p>
              {scanCopy.active}: {jobs.active}
            </p>
          ) : null}
        </div>
        <div className={styles.actions}>
          <button
            className={styles.button}
            type="button"
            disabled={Boolean(busy)}
            onClick={() => void refresh()}
          >
            <RefreshCw size={15} aria-hidden="true" />
            {busy === "refresh" ? scanCopy.refreshing : scanCopy.refresh}
          </button>
          <a
            className={styles.button}
            href={`/${locale}/security/baseline?baseline=${encodeURIComponent(baselineId)}`}
            aria-disabled={Boolean(busy)}
            onClick={(event) => {
              if (busy) event.preventDefault();
            }}
          >
            {scanCopy.loadResults}
          </a>
        </div>
      </div>
      {jobs?.active && !error ? (
        <p className={styles.hint}>
          {paused ? scanCopy.paused : scanCopy.polling}
        </p>
      ) : null}
      {jobs && jobs.results.length === 0 ? (
        <p className={styles.empty}>{scanCopy.noJobs}</p>
      ) : null}
      {jobs && jobs.results.length > 0 ? (
        <div className={styles.tableScroll}>
          <table>
            <caption className="sr-only">{scanCopy.jobs}</caption>
            <thead>
              <tr>
                <th scope="col">{copy.system}</th>
                <th scope="col">{copy.status}</th>
                <th scope="col">{scanCopy.requested}</th>
                <th scope="col">{scanCopy.completed}</th>
              </tr>
            </thead>
            <tbody>
              {jobs.results.map((job) => (
                <tr key={job.id}>
                  <td>{job.hostname || job.system_id}</td>
                  <td>
                    <span>{scanCopy.statuses[job.status]}</span>
                    {job.error_code ? (
                      <small>
                        {scanCopy.jobErrors[
                          job.error_code as keyof typeof scanCopy.jobErrors
                        ] ?? job.error_code}
                      </small>
                    ) : null}
                  </td>
                  <td>{date(job.requested_at)}</td>
                  <td>{date(job.completed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
