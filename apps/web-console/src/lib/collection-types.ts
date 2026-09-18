/**
 * File Name: collection-types.ts
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate tenant device and multi-domain policy collection projections.
 */
import type { SecurityTier } from "./domain-security-types";

export type CollectionDevice = {
  id: string;
  hostname: string;
  fqdn: string;
  domain_name: string;
  server_type: string;
  operating_system_role: string;
  operating_system_family: string;
};
export type DeviceRule = Partial<{
  domain_name: string;
  server_type: string;
  operating_system_role: string;
  operating_system_family: string;
  hostname_contains: string;
}>;
export type DeviceCollection = {
  id: string;
  name: string;
  description: string;
  revision: number;
  static_system_ids: string[];
  rules: DeviceRule[];
  member_count: number;
  members: CollectionDevice[];
  updated_at: string;
};
export type DeviceCollectionCatalog = {
  results: DeviceCollection[];
  inventory: CollectionDevice[];
};
export type PolicyCollectionEntry = {
  source: "baseline" | "override" | "custom";
  baseline_id: string;
  backup_id: string;
  target: string;
  version: string;
  override_id: string | null;
  component_name: string;
  scope: "machine" | "user" | "domain";
};
export type PolicyCollectionBinding = {
  domain_id: string;
  domain_name: string;
  domain_revision: number;
  tier: SecurityTier;
  target_ous: string[];
};
export type PolicyCollection = {
  id: string;
  name: string;
  description: string;
  revision: number;
  entries: PolicyCollectionEntry[];
  bindings: PolicyCollectionBinding[];
  deployment_count: number;
  updated_at: string;
};
export type PolicyCollectionCatalog = { results: PolicyCollection[] };
export type PolicyCollectionPreview = {
  collection_id: string;
  revision: number;
  ready: boolean;
  items: Array<{
    policy_index: number;
    domain_id: string;
    domain_name: string;
    tier: SecurityTier;
    target_ous: string[];
    source: "baseline" | "override" | "custom";
    component_name: string;
    executor: null | { system_id: string; hostname: string; dc_fqdn: string };
    ready: boolean;
    blocker: string | null;
  }>;
};
export type PolicyCollectionDeployment = {
  id: string;
  collection_id: string;
  collection_revision: number;
  status: string;
  requested_at: string;
  completed_at: string | null;
  items: Array<{
    id: string;
    domain_id: string;
    domain_name: string;
    policy_index: number;
    sequence: number;
    status: string;
    component_name: string;
    preflight_job_id: string | null;
    write_job_id: string | null;
    error_code: string;
  }>;
};

const record = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((item) => typeof item === "string");
const integer = (value: unknown, minimum = 0) =>
  Number.isSafeInteger(value) && Number(value) >= minimum;
const device = (value: unknown): value is CollectionDevice =>
  record(value) &&
  [
    "id",
    "hostname",
    "fqdn",
    "domain_name",
    "server_type",
    "operating_system_role",
    "operating_system_family",
  ].every((key) => typeof value[key] === "string");
const rule = (value: unknown): value is DeviceRule =>
  record(value) &&
  Object.keys(value).length > 0 &&
  Object.values(value).every((item) => typeof item === "string");
export const isDeviceCollection = (value: unknown): value is DeviceCollection =>
  record(value) &&
  ["id", "name", "description", "updated_at"].every(
    (key) => typeof value[key] === "string",
  ) &&
  integer(value.revision, 1) &&
  strings(value.static_system_ids) &&
  Array.isArray(value.rules) &&
  value.rules.every(rule) &&
  integer(value.member_count) &&
  Array.isArray(value.members) &&
  value.members.every(device);
export const isDeviceCollectionCatalog = (
  value: unknown,
): value is DeviceCollectionCatalog =>
  record(value) &&
  Array.isArray(value.results) &&
  value.results.every(isDeviceCollection) &&
  Array.isArray(value.inventory) &&
  value.inventory.every(device);

const entry = (value: unknown): value is PolicyCollectionEntry =>
  record(value) &&
  ["baseline_id", "backup_id", "target", "version", "component_name"].every(
    (key) => typeof value[key] === "string",
  ) &&
  ["baseline", "override", "custom"].includes(String(value.source)) &&
  ["machine", "user", "domain"].includes(String(value.scope)) &&
  (value.override_id === null || typeof value.override_id === "string");
const binding = (value: unknown): value is PolicyCollectionBinding =>
  record(value) &&
  typeof value.domain_id === "string" &&
  typeof value.domain_name === "string" &&
  integer(value.domain_revision, 1) &&
  ["0", "1", "2"].includes(String(value.tier)) &&
  strings(value.target_ous);
const policyCollection = (value: unknown): value is PolicyCollection =>
  record(value) &&
  ["id", "name", "description", "updated_at"].every(
    (key) => typeof value[key] === "string",
  ) &&
  integer(value.revision, 1) &&
  integer(value.deployment_count) &&
  Array.isArray(value.entries) &&
  value.entries.every(entry) &&
  Array.isArray(value.bindings) &&
  value.bindings.every(binding);
export const isPolicyCollectionCatalog = (
  value: unknown,
): value is PolicyCollectionCatalog =>
  record(value) &&
  Array.isArray(value.results) &&
  value.results.every(policyCollection);
export const isPolicyCollection = policyCollection;
export const isPolicyCollectionPreview = (
  value: unknown,
): value is PolicyCollectionPreview =>
  record(value) &&
  typeof value.collection_id === "string" &&
  integer(value.revision, 1) &&
  typeof value.ready === "boolean" &&
  Array.isArray(value.items) &&
  value.items.every(
    (item) =>
      record(item) &&
      integer(item.policy_index) &&
      ["domain_id", "domain_name", "component_name"].every(
        (key) => typeof item[key] === "string",
      ) &&
      ["0", "1", "2"].includes(String(item.tier)) &&
      strings(item.target_ous) &&
      typeof item.ready === "boolean" &&
      (item.blocker === null || typeof item.blocker === "string") &&
      (item.executor === null ||
        (record(item.executor) &&
          ["system_id", "hostname", "dc_fqdn"].every(
            (key) =>
              typeof (item.executor as Record<string, unknown>)[key] ===
              "string",
          ))),
  );
export const isPolicyCollectionDeployment = (
  value: unknown,
): value is PolicyCollectionDeployment =>
  record(value) &&
  ["id", "collection_id", "status", "requested_at"].every(
    (key) => typeof value[key] === "string",
  ) &&
  integer(value.collection_revision, 1) &&
  (value.completed_at === null || typeof value.completed_at === "string") &&
  Array.isArray(value.items) &&
  value.items.every(
    (item) =>
      record(item) &&
      [
        "id",
        "domain_id",
        "domain_name",
        "status",
        "component_name",
        "error_code",
      ].every((key) => typeof item[key] === "string") &&
      integer(item.policy_index) &&
      integer(item.sequence, 1) &&
      [item.preflight_job_id, item.write_job_id].every(
        (id) => id === null || typeof id === "string",
      ),
  );
