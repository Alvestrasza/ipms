/**
 * File Name: logs-export.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Download all authorized filtered metadata with explicit export-limit feedback.
 */
"use client";
import { Download, LoaderCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { JobLogsCopy } from "@/i18n/job-logs-copy";
import type { JobLogScope } from "@/lib/job-log-types";
import styles from "./logs-page.module.css";

type ExportScope = JobLogScope | "bmc-communication" | "bmc-events";
const EXPORT_ROUTES = {
  agents: {
    path: "/api/v1/logs/agents/export/",
    filename: "ipms-agents-logs.csv",
  },
  baselines: {
    path: "/api/v1/logs/baselines/export/",
    filename: "ipms-baselines-logs.csv",
  },
  "bmc-communication": {
    path: "/api/v1/bmc-logs/export/",
    filename: "ipms-bmc-logs.csv",
  },
  "bmc-events": {
    path: "/api/v1/bmc-event-logs/export/",
    filename: "ipms-bmc-event-logs.csv",
  },
} as const;

export function LogsExport({
  tenantId,
  scope,
  queryString,
  copy,
  disabled = false,
}: {
  tenantId: string;
  scope: ExportScope;
  queryString: string;
  copy: JobLogsCopy;
  disabled?: boolean;
}) {
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  async function exportCsv() {
    if (controller.current || disabled) return;
    const request = new AbortController();
    controller.current = request;
    setExporting(true);
    setError("");
    try {
      const query = new URLSearchParams(queryString);
      for (const key of ["page", "page_size", "job"]) query.delete(key);
      const route = EXPORT_ROUTES[scope];
      const response = await fetch(
        `${route.path}${query.size ? `?${query}` : ""}`,
        {
          credentials: "same-origin",
          cache: "no-store",
          headers: { "X-IPMS-Tenant-ID": tenantId },
          signal: AbortSignal.any([
            request.signal,
            AbortSignal.timeout(30_000),
          ]),
        },
      );
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        setError(
          response.status === 401
            ? copy.sessionExpired
            : response.status === 403
              ? copy.forbidden
              : payload?.error?.code === "log_export_limit_exceeded"
                ? copy.exportLimit
                : copy.exportError,
        );
        return;
      }
      const blob = await response.blob();
      if (request.signal.aborted) return;
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = route.filename;
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch {
      if (!request.signal.aborted) setError(copy.exportError);
    } finally {
      controller.current = null;
      if (!request.signal.aborted) setExporting(false);
    }
  }
  return (
    <div className={styles.export}>
      <button
        className="outline-button"
        type="button"
        onClick={exportCsv}
        disabled={disabled || exporting}
      >
        {exporting ? (
          <LoaderCircle className="spin" size={15} aria-hidden="true" />
        ) : (
          <Download size={15} aria-hidden="true" />
        )}
        {exporting ? copy.exporting : copy.exportCsv}
      </button>
      <small>{copy.exportHint}</small>
      {error ? (
        <p className="form-error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}
