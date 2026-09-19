/**
 * File Name: gpo-production-types.ts
 * Version: v0.2.0 | Created: 2026-09-15 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Bound production GPO observations and managed policy projections.
 */
export const GPO_OPERATIONS = [
  "import_and_link_managed_gpo",
  "import_managed_gpo",
  "link_managed_gpo",
  "activate_managed_gpo",
  "deactivate_managed_gpo",
  "delete_managed_gpo",
] as const;
export type GpoOperation = (typeof GPO_OPERATIONS)[number];
export type GpoLink = {
  guid: string;
  domain: string;
  dn: string;
  kind: "ou" | "domain" | "site";
  enabled: boolean;
  enforced: boolean;
  order: number;
};
export type GpoSnapshot = {
  schema: 1;
  domain_admins_sid: string;
  name_available: boolean;
  gpo: null | {
    guid: string;
    name: string;
    description: string;
    computer_enabled: boolean;
    user_enabled: boolean;
    computer_ds: number;
    computer_sysvol: number;
    user_ds: number;
    user_sysvol: number;
    owner_sid: string;
    security_digest: string;
    wmi_filter: string;
    links: GpoLink[];
  };
  ous: {
    dn: string;
    guid: string;
    usn: string;
    blocked: boolean;
    links: GpoLink[];
    inherited_links: GpoLink[];
  }[];
};
export type ManagedGpo = {
  override_id?: string | null;
  id: string;
  revision: number;
  display_name: string;
  active_display_name?: string | null;
  gpo_guid: string | null;
  tier: "0" | "1" | "2";
  target_ous: string[];
  baseline_id: string;
  backup_id: string;
  profile: string;
  target: string;
  version: string;
  state:
    | "new"
    | "prepared"
    | "linked"
    | "active"
    | "inactive"
    | "reconciliation_required";
  origin_job_id: string | null;
  staged_job_id: string | null;
  active_job_id: string | null;
};
export type GpoDirectoryNode = {
  dn: string;
  kind: "domain" | "ou";
  tiers: ("0" | "1" | "2")[];
  observed: boolean;
  blocked: boolean | null;
  links: GpoLink[];
  inherited_links: GpoLink[];
};
export type GpoDirectoryItem = {
  managed_id: string;
  guid: string | null;
  name: string;
  source: "baseline" | "override" | "custom";
  state: ManagedGpo["state"];
  tier: "0" | "1" | "2";
  targets: string[];
  observed_at: string | null;
  computer_enabled: boolean | null;
  user_enabled: boolean | null;
  computer_version: { directory: number; sysvol: number } | null;
  user_version: { directory: number; sysvol: number } | null;
  owner_sid: string | null;
  wmi_filter: string | null;
  links: GpoLink[];
};
export type GpoDirectoryView = {
  schema: 1;
  domain_dns_name: string;
  scope: "configured-targets-and-managed-gpos";
  nodes: GpoDirectoryNode[];
  gpos: GpoDirectoryItem[];
};
const object = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const uuid = (v: unknown) =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const text = (v: unknown, max = 2048) =>
  typeof v === "string" && v.length <= max;
const integer = (v: unknown, min = 0) =>
  Number.isSafeInteger(v) && Number(v) >= min;
const sid = (v: unknown) =>
  typeof v === "string" &&
  /^S-1-(?:0|[1-9][0-9]{0,14})(?:-(?:0|[1-9][0-9]{0,9})){2,15}$/.test(v);
const keys = (v: Record<string, unknown>, expected: string[]) =>
  Object.keys(v).length === expected.length &&
  expected.every((k) => Object.hasOwn(v, k));
export function isGpoLinks(v: unknown): v is GpoLink[] {
  return (
    Array.isArray(v) &&
    v.length <= 128 &&
    v.every(
      (l) =>
        object(l) &&
        keys(l, [
          "guid",
          "domain",
          "dn",
          "kind",
          "enabled",
          "enforced",
          "order",
        ]) &&
        uuid(l.guid) &&
        text(l.domain, 253) &&
        text(l.dn) &&
        ["ou", "domain", "site"].includes(String(l.kind)) &&
        typeof l.enabled === "boolean" &&
        typeof l.enforced === "boolean" &&
        integer(l.order, 1),
    )
  );
}
export function isGpoSnapshot(v: unknown): v is GpoSnapshot {
  if (
    !object(v) ||
    !keys(v, ["schema", "domain_admins_sid", "gpo", "ous", "name_available"]) ||
    v.schema !== 1 ||
    !sid(v.domain_admins_sid) ||
    typeof v.name_available !== "boolean" ||
    !Array.isArray(v.ous) ||
    v.ous.length > 32
  )
    return false;
  if (
    !v.ous.every(
      (o) =>
        object(o) &&
        keys(o, ["dn", "guid", "usn", "blocked", "links", "inherited_links"]) &&
        text(o.dn) &&
        uuid(o.guid) &&
        typeof o.usn === "string" &&
        /^\d{1,20}$/.test(o.usn) &&
        typeof o.blocked === "boolean" &&
        isGpoLinks(o.links) &&
        isGpoLinks(o.inherited_links),
    )
  )
    return false;
  const g = v.gpo;
  return (
    g === null ||
    (object(g) &&
      keys(g, [
        "guid",
        "name",
        "description",
        "computer_enabled",
        "user_enabled",
        "computer_ds",
        "computer_sysvol",
        "user_ds",
        "user_sysvol",
        "owner_sid",
        "security_digest",
        "wmi_filter",
        "links",
      ]) &&
      uuid(g.guid) &&
      text(g.name, 240) &&
      text(g.description, 4096) &&
      typeof g.computer_enabled === "boolean" &&
      typeof g.user_enabled === "boolean" &&
      [g.computer_ds, g.computer_sysvol, g.user_ds, g.user_sysvol].every((x) =>
        integer(x),
      ) &&
      sid(g.owner_sid) &&
      typeof g.security_digest === "string" &&
      /^[a-f0-9]{64}$/.test(g.security_digest) &&
      text(g.wmi_filter) &&
      isGpoLinks(g.links))
  );
}
export function isManagedGpo(v: unknown): v is ManagedGpo {
  return (
    object(v) &&
    uuid(v.id) &&
    (v.override_id === undefined ||
      v.override_id === null ||
      uuid(v.override_id)) &&
    integer(v.revision, 1) &&
    text(v.display_name, 240) &&
    (v.active_display_name === undefined ||
      v.active_display_name === null ||
      text(v.active_display_name, 240)) &&
    (v.gpo_guid === null || v.gpo_guid === "" || uuid(v.gpo_guid)) &&
    ["0", "1", "2"].includes(String(v.tier)) &&
    Array.isArray(v.target_ous) &&
    v.target_ous.length > 0 &&
    v.target_ous.length <= 32 &&
    v.target_ous.every((value) => text(value)) &&
    ["baseline_id", "backup_id", "profile", "target", "version"].every((k) =>
      text(v[k], 128),
    ) &&
    [
      "new",
      "prepared",
      "linked",
      "active",
      "inactive",
      "reconciliation_required",
    ].includes(String(v.state)) &&
    [v.origin_job_id, v.staged_job_id, v.active_job_id].every(
      (id) => id === null || uuid(id),
    )
  );
}
const nullableBoolean = (value: unknown) =>
  value === null || typeof value === "boolean";
const version = (value: unknown) =>
  value === null ||
  (object(value) &&
    keys(value, ["directory", "sysvol"]) &&
    integer(value.directory) &&
    integer(value.sysvol));
export function isGpoDirectoryView(v: unknown): v is GpoDirectoryView {
  if (
    !object(v) ||
    !keys(v, ["schema", "domain_dns_name", "scope", "nodes", "gpos"]) ||
    v.schema !== 1 ||
    !text(v.domain_dns_name, 253) ||
    v.scope !== "configured-targets-and-managed-gpos" ||
    !Array.isArray(v.nodes) ||
    v.nodes.length > 96 ||
    !Array.isArray(v.gpos) ||
    v.gpos.length > 10000
  )
    return false;
  const nodes = v.nodes.every(
    (node) =>
      object(node) &&
      keys(node, [
        "dn",
        "kind",
        "tiers",
        "observed",
        "blocked",
        "links",
        "inherited_links",
      ]) &&
      text(node.dn) &&
      ["domain", "ou"].includes(String(node.kind)) &&
      Array.isArray(node.tiers) &&
      node.tiers.length > 0 &&
      node.tiers.length <= 3 &&
      node.tiers.every((tier) => ["0", "1", "2"].includes(String(tier))) &&
      new Set(node.tiers).size === node.tiers.length &&
      typeof node.observed === "boolean" &&
      nullableBoolean(node.blocked) &&
      isGpoLinks(node.links) &&
      isGpoLinks(node.inherited_links),
  );
  return (
    nodes &&
    v.gpos.every(
      (gpo) =>
        object(gpo) &&
        keys(gpo, [
          "managed_id",
          "guid",
          "name",
          "source",
          "state",
          "tier",
          "targets",
          "observed_at",
          "computer_enabled",
          "user_enabled",
          "computer_version",
          "user_version",
          "owner_sid",
          "wmi_filter",
          "links",
        ]) &&
        uuid(gpo.managed_id) &&
        (gpo.guid === null || uuid(gpo.guid)) &&
        text(gpo.name, 240) &&
        ["baseline", "override", "custom"].includes(String(gpo.source)) &&
        [
          "new",
          "prepared",
          "linked",
          "active",
          "inactive",
          "reconciliation_required",
        ].includes(String(gpo.state)) &&
        ["0", "1", "2"].includes(String(gpo.tier)) &&
        Array.isArray(gpo.targets) &&
        gpo.targets.length > 0 &&
        gpo.targets.length <= 32 &&
        gpo.targets.every((target) => text(target)) &&
        (gpo.observed_at === null || text(gpo.observed_at, 64)) &&
        nullableBoolean(gpo.computer_enabled) &&
        nullableBoolean(gpo.user_enabled) &&
        version(gpo.computer_version) &&
        version(gpo.user_version) &&
        (gpo.owner_sid === null || sid(gpo.owner_sid)) &&
        (gpo.wmi_filter === null || text(gpo.wmi_filter)) &&
        isGpoLinks(gpo.links),
    )
  );
}
