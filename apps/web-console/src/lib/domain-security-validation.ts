/**
 * File Name: domain-security-validation.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate domain settings and import receipts before presenting confirmed state.
 */
import type {
  DomainGpoImports,
  DomainSecurityCatalog,
  DomainSecuritySettings,
  GpoImportJob,
  SecurityTier,
} from "./domain-security-types";

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
    ].every((key) => typeof value[key] === "string") &&
    [
      "queued",
      "awaiting_approval",
      "running",
      "staged",
      "blocked",
      "failed",
      "expired",
      "reconciliation_required",
    ].includes(value.status as string) &&
    tier(value.tier) &&
    date(value.requested_at) &&
    (value.completed_at === null || date(value.completed_at)) &&
    nullableString(value.gpo_guid) &&
    (value.approval_document === null || record(value.approval_document))
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
