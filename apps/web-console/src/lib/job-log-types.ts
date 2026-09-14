/**
 * File Name: job-log-types.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Define bounded job-history projections and URL navigation helpers.
 */
import type { GpoImportJob } from "./domain-security-types";
import { isGpoImportJob } from "./domain-security-validation";

export type JobLogScope = "agents" | "baselines";
export type LogSearchParams = Record<string, string | string[] | undefined>;
export const JOB_LOG_KINDS = [
  "agent_lifecycle",
  "agent_deployment",
  "baseline_scan",
  "gpo_import",
  "hyperv_power",
  "hyperv_management",
] as const;
export type JobLogKind = (typeof JOB_LOG_KINDS)[number];
export const JOB_LOG_STATUSES = [
  "queued",
  "delivered",
  "running",
  "succeeded",
  "failed",
  "cancelled",
  "completed",
  "expired",
  "awaiting_approval",
  "staged",
  "blocked",
  "reconciliation_required",
  "requires_reconciliation",
] as const;
export const JOB_LOG_QUERY_KEYS = [
  "q",
  "kind",
  "status",
  "from",
  "to",
  "baseline",
  "domain",
  "agent",
  "sort",
  "direction",
  "page",
  "page_size",
] as const;
export type JobLogEntry = {
  id: string;
  kind: JobLogKind;
  action: string;
  status: string;
  system: string;
  target: string;
  enrollment_id: string;
  baseline_id: string;
  domain: string;
  requested_at: string;
  started_at: string | null;
  completed_at: string | null;
  result_code: string;
  requested_by: string;
};
export type JobLogPage = {
  count: number;
  page: number;
  page_size: number;
  results: JobLogEntry[];
  available_kinds: JobLogKind[];
};
export type GpoImportLogDetail = GpoImportJob & {
  domain_id: string;
  domain: string;
};

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function date(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function kind(value: unknown): value is JobLogKind {
  return (
    typeof value === "string" && JOB_LOG_KINDS.some((item) => item === value)
  );
}
export function isLogJobId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    value,
  );
}
export function isJobLogPage(value: unknown): value is JobLogPage {
  return (
    record(value) &&
    Number.isSafeInteger(value.count) &&
    Number(value.count) >= 0 &&
    Number.isSafeInteger(value.page) &&
    Number(value.page) >= 1 &&
    typeof value.page_size === "number" &&
    [25, 50, 100].includes(value.page_size) &&
    Array.isArray(value.available_kinds) &&
    value.available_kinds.every(kind) &&
    Array.isArray(value.results) &&
    value.results.length <= Number(value.page_size) &&
    value.results.every(
      (entry) =>
        record(entry) &&
        kind(entry.kind) &&
        [
          "id",
          "action",
          "status",
          "system",
          "target",
          "enrollment_id",
          "baseline_id",
          "domain",
          "result_code",
          "requested_by",
        ].every((key) => typeof entry[key] === "string") &&
        isLogJobId(entry.id as string) &&
        date(entry.requested_at) &&
        (entry.started_at === null || date(entry.started_at)) &&
        (entry.completed_at === null || date(entry.completed_at)),
    )
  );
}
export function isGpoImportLogDetail(
  value: unknown,
): value is GpoImportLogDetail {
  return (
    record(value) &&
    typeof value.domain_id === "string" &&
    typeof value.domain === "string" &&
    isGpoImportJob(value)
  );
}

/** Preserve duplicates so the server rejects ambiguous filters instead of hiding them. */
export function logQuery(selected: LogSearchParams): URLSearchParams {
  const query = new URLSearchParams();
  for (const key of JOB_LOG_QUERY_KEYS) {
    const values = selected[key];
    for (const value of Array.isArray(values)
      ? values
      : values === undefined
        ? []
        : [values]) {
      query.append(key, value);
    }
  }
  return query;
}
export function logUrl(
  path: string,
  query: URLSearchParams,
  changes: Record<string, string | null> = {},
): string {
  const next = new URLSearchParams(query);
  for (const [key, value] of Object.entries(changes)) {
    if (value === null) next.delete(key);
    else next.set(key, value);
  }
  const suffix = next.toString();
  return suffix ? `${path}?${suffix}` : path;
}
/** Old bookmarked BMC routes must retain repeated severity/log_type selections. */
export function preservedLogQuery(selected: LogSearchParams): string {
  const query = new URLSearchParams();
  for (const [key, values] of Object.entries(selected)) {
    for (const value of Array.isArray(values)
      ? values
      : values === undefined
        ? []
        : [values])
      query.append(key, value);
  }
  return query.toString();
}
