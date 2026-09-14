/**
 * File Name: security-scan-validation.ts
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate scan receipts and native findings before displaying evidence.
 */
import type {
  SecurityBaselineFindings,
  SecurityBaselineScanReceipt,
  SecurityBaselineScans,
} from "./security-types";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
function count(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function date(value: unknown): boolean {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function jobs(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.every(
      (job) =>
        record(job) &&
        ["id", "system_id", "hostname", "error_code"].every(
          (key) => typeof job[key] === "string",
        ) &&
        ["queued", "running", "completed", "failed", "expired"].includes(
          job.status as string,
        ) &&
        date(job.requested_at) &&
        (job.completed_at === null || date(job.completed_at)),
    )
  );
}
export function isSecurityScans(
  value: unknown,
): value is SecurityBaselineScans {
  return (
    record(value) &&
    count(value.count) &&
    count(value.active) &&
    jobs(value.results)
  );
}
export function isSecurityScanReceipt(
  value: unknown,
): value is SecurityBaselineScanReceipt {
  return (
    record(value) &&
    count(value.queued) &&
    count(value.existing) &&
    count(value.unavailable) &&
    jobs(value.results)
  );
}
function scalar(value: unknown): boolean {
  return (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  );
}
function findingValue(value: unknown): boolean {
  return scalar(value) || (Array.isArray(value) && value.every(scalar));
}
export function isSecurityFindings(
  value: unknown,
): value is SecurityBaselineFindings {
  return (
    record(value) &&
    (value.assessment_id === null || typeof value.assessment_id === "string") &&
    (value.assessed_at === null || date(value.assessed_at)) &&
    typeof value.scope_verified === "boolean" &&
    ["compliant", "non_compliant", "unknown", "error", "stale"].includes(
      value.status as string,
    ) &&
    [
      "not_assessed",
      "partial",
      "assessment_error",
      "expired",
      "baseline_changed",
      "system_changed",
      "agent_unavailable",
      "complete",
    ].includes(value.reason as string) &&
    [
      "total_controls",
      "passed_controls",
      "failed_controls",
      "unknown_controls",
      "count",
    ].every((key) => count(value[key])) &&
    count(value.page) &&
    value.page > 0 &&
    count(value.page_size) &&
    value.page_size > 0 &&
    Array.isArray(value.results) &&
    value.results.every(
      (finding) =>
        record(finding) &&
        ["control_id", "label", "scope", "kind", "reason"].every(
          (key) => typeof finding[key] === "string",
        ) &&
        ["passed", "failed", "unknown"].includes(finding.status as string) &&
        findingValue(finding.expected) &&
        findingValue(finding.observed),
    )
  );
}
