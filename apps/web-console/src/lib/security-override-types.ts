/**
 * File Name: security-override-types.ts
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Bound sparse overrides to the authoritative original setting catalog.
 */
export type OverrideValue = number | string | string[];
export type OverrideEntry = { setting_id: string; value: OverrideValue };
export type OverrideReview = {
  override_id: string;
  override_revision: number;
  override_sha256: string;
  override_entries: OverrideEntry[];
  settings: {
    setting_id: string;
    label: string;
    category: string;
    baseline_value: OverrideValue;
    value: OverrideValue;
  }[];
};
export type SecurityOverride = {
  id: string;
  name: string;
  baseline_id: string;
  backup_id: string;
  artifact_sha256: string;
  revision: number;
  enabled: boolean;
  kind?: "override" | "custom";
  entries: OverrideEntry[];
  sha256: string;
};
export type OverrideSetting = {
  setting_id: string;
  label: string;
  category: string;
  kind: string;
  file: string;
  path: string;
  name: string;
  scope: string;
  value_type: "integer" | "string" | "string_list" | "unsupported";
  baseline_value: OverrideValue | { hex: string } | null;
  editable: boolean;
  readonly_reason: string;
  min: number;
  max: number;
  max_length: number;
  max_items: number;
  enum_options: { value: OverrideValue; label: string }[];
};
export type OverrideCatalog = {
  baseline_id: string;
  backup_id: string;
  artifact_sha256: string;
  settings: OverrideSetting[];
};
const record = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const hash = (v: unknown) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const uuid = (v: unknown) =>
  typeof v === "string" &&
  /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v);
const text = (v: unknown, max = 4096): v is string =>
  typeof v === "string" && v.length <= max;
const value = (v: unknown): v is OverrideValue =>
  Number.isSafeInteger(v) ||
  text(v, 65536) ||
  (Array.isArray(v) && v.length <= 128 && v.every((x) => text(x, 4096)));
export const sameOverrideValue = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
export function isOverrideEntry(v: unknown): v is OverrideEntry {
  return (
    record(v) &&
    Object.keys(v).length === 2 &&
    hash(v.setting_id) &&
    value(v.value)
  );
}
export function isOverrideReview(v: unknown): v is OverrideReview {
  if (
    !record(v) ||
    !uuid(v.override_id) ||
    !Number.isSafeInteger(v.override_revision) ||
    Number(v.override_revision) < 1 ||
    !hash(v.override_sha256) ||
    !Array.isArray(v.override_entries) ||
    v.override_entries.length > 128 ||
    !v.override_entries.every(isOverrideEntry) ||
    !Array.isArray(v.settings) ||
    v.settings.length !== v.override_entries.length
  )
    return false;
  const entries = v.override_entries;
  return (
    new Set(entries.map((e) => e.setting_id)).size === entries.length &&
    v.settings.every(
      (s, i) =>
        record(s) &&
        s.setting_id === entries[i].setting_id &&
        text(s.label) &&
        text(s.category) &&
        value(s.baseline_value) &&
        value(s.value) &&
        sameOverrideValue(s.value, entries[i].value),
    )
  );
}
export function isSecurityOverride(v: unknown): v is SecurityOverride {
  return (
    record(v) &&
    uuid(v.id) &&
    text(v.name, 80) &&
    text(v.baseline_id, 128) &&
    text(v.backup_id, 128) &&
    hash(v.artifact_sha256) &&
    Number.isSafeInteger(v.revision) &&
    Number(v.revision) >= 1 &&
    typeof v.enabled === "boolean" &&
    (v.kind === undefined || ["override", "custom"].includes(String(v.kind))) &&
    hash(v.sha256) &&
    Array.isArray(v.entries) &&
    v.entries.length <= 128 &&
    v.entries.every(isOverrideEntry) &&
    new Set(v.entries.map((e) => e.setting_id)).size === v.entries.length
  );
}
export function isOverrideList(
  v: unknown,
): v is { results: SecurityOverride[] } {
  return (
    record(v) &&
    Array.isArray(v.results) &&
    v.results.length <= 10000 &&
    v.results.every(isSecurityOverride)
  );
}
export function isOverrideCatalog(v: unknown): v is OverrideCatalog {
  return (
    record(v) &&
    text(v.baseline_id, 128) &&
    text(v.backup_id, 128) &&
    hash(v.artifact_sha256) &&
    Array.isArray(v.settings) &&
    v.settings.length <= 10000 &&
    v.settings.every(
      (s) =>
        record(s) &&
        hash(s.setting_id) &&
        [
          "label",
          "category",
          "kind",
          "file",
          "path",
          "name",
          "scope",
          "readonly_reason",
        ].every((k) => text(s[k])) &&
        ["integer", "string", "string_list", "unsupported"].includes(
          String(s.value_type),
        ) &&
        (s.baseline_value === null ||
          value(s.baseline_value) ||
          (!s.editable &&
            record(s.baseline_value) &&
            Object.keys(s.baseline_value).length === 1 &&
            typeof s.baseline_value.hex === "string" &&
            s.baseline_value.hex.length <= 131072 &&
            /^(?:[a-fA-F0-9]{2})*$/.test(s.baseline_value.hex))) &&
        typeof s.editable === "boolean" &&
        (!s.editable || s.value_type !== "unsupported") &&
        [s.min, s.max, s.max_length, s.max_items].every(Number.isSafeInteger) &&
        Array.isArray(s.enum_options) &&
        s.enum_options.length <= 256 &&
        s.enum_options.every(
          (e) => record(e) && value(e.value) && text(e.label),
        ),
    ) &&
    new Set(v.settings.map((s) => s.setting_id)).size === v.settings.length
  );
}
const forbiddenText = (input: string) =>
  Array.from(input).some((character) => {
    const code = character.codePointAt(0) ?? 0;
    return code < 32 || code === 127 || (code >= 0xd800 && code <= 0xdfff);
  });
/** Return null for invalid input; an empty list is a deliberate value, not reset. */
export function parseOverrideInput(
  s: OverrideSetting,
  input: string,
): OverrideValue | null {
  if (!s.editable) return null;
  let result: OverrideValue;
  if (s.value_type === "integer") {
    if (!/^-?\d+$/.test(input)) return null;
    result = Number(input);
    if (!Number.isSafeInteger(result) || result < s.min || result > s.max)
      return null;
  } else if (s.value_type === "string") {
    if (input.length > s.max_length || forbiddenText(input)) return null;
    result = input;
  } else if (s.value_type === "string_list") {
    result = input === "" ? [] : input.split(/\r?\n/);
    if (
      result.length > s.max_items ||
      result.some((x) => !x || x.length > s.max_length || forbiddenText(x))
    )
      return null;
    if (new Set(result).size !== result.length) return null;
    if (
      s.kind === "privilege_right" &&
      result.some((entry) => {
        if (!/^S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}$/.test(entry))
          return true;
        const parts = entry.split("-").slice(2).map(Number);
        return parts[0] >= 2 ** 48 || parts.slice(1).some((n) => n >= 2 ** 32);
      })
    )
      return null;
  } else return null;
  if (
    s.enum_options.length &&
    !s.enum_options.some((e) => sameOverrideValue(e.value, result))
  )
    return null;
  return result;
}
