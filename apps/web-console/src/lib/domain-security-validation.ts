/**
 * File Name: domain-security-validation.ts
 * Version: v0.1.1 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate domain settings and import receipts before presenting confirmed state.
 */

import type {
  DomainGpoImports,
  DomainSecurityCatalog,
  DomainSecuritySettings,
  GpoImportJob,
  GpoImportReview,
  SecurityTier,
} from "./domain-security-types";
import { GPO_OPERATIONS, isGpoSnapshot } from "./gpo-production-types";
import { isOverrideReview } from "./security-override-types";

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function strings(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((item) => typeof item === "string")
  );
}
function date(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}
function nullableString(value: unknown): boolean {
  return value === null || typeof value === "string";
}
function tier(value: unknown): value is SecurityTier {
  return value === "0" || value === "1" || value === "2";
}

/** Display only locally translated allowlisted codes, never raw server text. */
export function domainSettingsErrorKey(value: unknown) {
  if (!record(value) || !record(value.error)) return null;
  switch (value.error.code) {
    case "security_domain_name_invalid":
      return "domain";
    case "security_domain_tier_0_ou_invalid":
      return "tier0";
    case "security_domain_tier_1_ou_invalid":
      return "tier1";
    case "security_domain_tier_2_ou_invalid":
      return "tier2";
    case "security_domain_ou_overlap":
      return "overlap";
    case "security_domain_template_invalid":
      return "template";
    case "security_domain_order_invalid":
      return "order";
    default:
      return null;
  }
}

export function isDomainSettings(
  value: unknown,
): value is DomainSecuritySettings {
  return (
    record(value) &&
    ["id", "domain_name", "gpo_name_template"].every(
      (key) => typeof value[key] === "string" && value[key] !== "",
    ) &&
    Number.isSafeInteger(value.revision) &&
    (value.revision as number) > 0 &&
    record(value.tier_ous) &&
    ["0", "1", "2"].every((key) =>
      strings((value.tier_ous as Record<string, unknown>)[key]),
    ) &&
    strings(value.baseline_order) &&
    new Set(value.baseline_order).size === value.baseline_order.length &&
    date(value.updated_at) &&
    value.verification_status === "unverified" &&
    Array.isArray(value.name_previews) &&
    value.name_previews.every(
      (item) =>
        record(item) &&
        tier(item.tier) &&
        typeof item.production === "string" &&
        typeof item.pilot === "string",
    )
  );
}

export function isDomainSecurityCatalog(
  value: unknown,
): value is DomainSecurityCatalog {
  return (
    record(value) &&
    typeof value.default_name_template === "string" &&
    typeof value.catalog_revision === "string" &&
    strings(value.discovered_domains) &&
    Array.isArray(value.results) &&
    value.results.every(isDomainSettings) &&
    Array.isArray(value.baseline_options) &&
    value.baseline_options.every(
      (baseline) =>
        record(baseline) &&
        ["id", "name", "provider", "revision"].every(
          (key) => typeof baseline[key] === "string",
        ) &&
        strings(baseline.profiles) &&
        Array.isArray(baseline.components) &&
        baseline.components.every(
          (component) =>
            record(component) &&
            ["id", "name", "purpose", "artifact_sha256"].every(
              (key) => typeof component[key] === "string",
            ) &&
            ["machine", "user", "domain"].includes(component.scope as string) &&
            typeof component.available === "boolean",
        ),
    )
  );
}

export function isGpoImportJob(value: unknown): value is GpoImportJob {
  return (
    record(value) &&
    [
      "id",
      "baseline_id",
      "backup_id",
      "pilot_display_name",
      "hostname",
      "error_code",
      "requested_by_name",
      "input_digest",
      "dc_fqdn",
    ].every((key) => typeof value[key] === "string") &&
    [
      "queued",
      "awaiting_approval",
      "running",
      "staged",
      "inspected",
      "linked",
      "activated",
      "deactivated",
      "deleted",
      "reconciled",
      "blocked",
      "failed",
      "expired",
      "reconciliation_required",
    ].includes(value.status as string) &&
    tier(value.tier) &&
    date(value.requested_at) &&
    (value.completed_at === null || date(value.completed_at)) &&
    nullableString(value.gpo_guid) &&
    nullableString(value.requested_by) &&
    (value.approval_document === null || record(value.approval_document)) &&
    (value.approval_mode === "local" ||
      value.approval_mode === "portal" ||
      value.approval_mode === "inspection") &&
    (value.display_name === undefined ||
      typeof value.display_name === "string") &&
    (value.operation === undefined ||
      [
        ...GPO_OPERATIONS,
        "inspect_managed_gpo",
        "create_unlinked_pilot",
      ].includes(value.operation as string)) &&
    (value.managed_id === undefined || nullableString(value.managed_id)) &&
    (value.preflight_state === undefined ||
      value.preflight_state === null ||
      isGpoSnapshot(value.preflight_state)) &&
    (value.can_prepare === undefined ||
      typeof value.can_prepare === "boolean") &&
    (value.inspection_expires_at === undefined ||
      value.inspection_expires_at === null ||
      date(value.inspection_expires_at)) &&
    nullableString(value.approved_by) &&
    nullableString(value.approved_by_name) &&
    (value.approved_at === null || date(value.approved_at)) &&
    typeof value.four_eyes_required === "boolean" &&
    Number.isSafeInteger(value.policy_revision) &&
    Number(value.policy_revision) >= 0 &&
    typeof value.can_approve === "boolean" &&
    nullableString(value.approval_blocker) &&
    date(value.expires_at) &&
    (value.review === null || isGpoImportReview(value.review))
  );
}

export function isGpoImportReview(value: unknown): value is GpoImportReview {
  const sha256 = (digest: unknown) =>
    typeof digest === "string" && /^[0-9a-f]{64}$/.test(digest);
  return (
    record(value) &&
    (value.override === undefined || isOverrideReview(value.override)) &&
    typeof value.component_name === "string" &&
    sha256(value.artifact_sha256) &&
    typeof value.report_xml === "string" &&
    value.report_xml.length <= 1024 * 1024 &&
    Array.isArray(value.files) &&
    value.files.length <= 1024 &&
    value.files.every(
      (file) =>
        record(file) &&
        typeof file.path === "string" &&
        file.path.length <= 1024 &&
        Number.isSafeInteger(file.bytes) &&
        Number(file.bytes) >= 0 &&
        Number(file.bytes) <= 1024 * 1024 &&
        sha256(file.sha256),
    ) &&
    new Set(value.files.map((file) => file.path)).size === value.files.length &&
    Array.isArray(value.changes) &&
    value.changes.length >= 1 &&
    value.changes.length <= 8 &&
    value.changes.every(
      (change) => typeof change === "string" && change.length <= 128,
    ) &&
    (value.expected_state === undefined ||
      value.expected_state === null ||
      isGpoSnapshot(value.expected_state)) &&
    (value.target_ous === undefined ||
      (Array.isArray(value.target_ous) &&
        value.target_ous.length <= 32 &&
        value.target_ous.every(
          (dn) => typeof dn === "string" && dn.length <= 2048,
        ))) &&
    (value.safety_review === undefined ||
      (record(value.safety_review) &&
        typeof value.safety_review.management_access === "boolean" &&
        typeof value.safety_review.recovery_access === "boolean"))
  );
}

export function isDomainGpoImports(value: unknown): value is DomainGpoImports {
  return (
    record(value) &&
    Array.isArray(value.results) &&
    value.results.every(isGpoImportJob) &&
    Array.isArray(value.executors) &&
    value.executors.every(
      (executor) =>
        record(executor) &&
        [
          "system_id",
          "hostname",
          "agent_version",
          "state",
          "domain_name",
          "domain_guid",
          "forest_name",
          "dc_fqdn",
        ].every((key) => typeof executor[key] === "string") &&
        typeof executor.eligible === "boolean" &&
        (executor.last_seen === null || date(executor.last_seen)),
    )
  );
}

/** An example only; the API validates and renders authoritative saved names. */
export function previewGpoName(
  template: string,
  selectedTier: SecurityTier,
): string | null {
  const tokens: Record<string, string> = {
    tier: selectedTier,
    scope: "C",
    target: "ALL",
    purpose: "Baseline",
    version: "1.0.0",
  };
  if (!template || template.length > 160) return null;
  const fields = template.match(/\{[^{}]+\}/g) ?? [];
  if (
    fields.length !== 5 ||
    new Set(fields).size !== 5 ||
    Object.keys(tokens).some((name) => !fields.includes(`{${name}}`))
  )
    return null;
  let valid = true;
  const rendered = template.replace(/\{([^{}]+)\}/g, (_, name: string) => {
    if (!Object.hasOwn(tokens, name)) {
      valid = false;
      return "";
    }
    return tokens[name];
  });
  return valid &&
    rendered.length <= 240 &&
    rendered.trim() === rendered &&
    /^[A-Za-z0-9][A-Za-z0-9 ._-]*$/.test(rendered)
    ? rendered
    : null;
}
