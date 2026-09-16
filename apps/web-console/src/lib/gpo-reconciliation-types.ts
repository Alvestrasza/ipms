/**
 * File Name: gpo-reconciliation-types.ts
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate bounded read-only directory reconciliation projections.
 */
import {
  type GpoLink,
  type GpoSnapshot,
  isGpoLinks,
  isGpoSnapshot,
} from "./gpo-production-types";
export type ReconciliationObservation = {
  schema: 1;
  state: GpoSnapshot | null;
  forest_links: GpoLink[];
  forest_complete: boolean;
  acl_consistent: boolean | null;
  gpo_presence: "present" | "absent" | "unknown";
  issues: string[];
  gpo_guid: string;
  quiescent: boolean;
};
export type GpoReconciliation = {
  id: string;
  status:
    | "requested"
    | "observed"
    | "accept_requested"
    | "accepted"
    | "failed"
    | "stale";
  requested_at: string;
  expires_at: string;
  observation: ReconciliationObservation | null;
  observation_digest: string;
  issues: string[];
  can_accept: boolean;
  accept_blocked_reason: string | null;
  accepted_at: string | null;
};
export type ReconciliationProjection = {
  can_request: boolean;
  request_blocked_reason: string | null;
  latest: GpoReconciliation | null;
};
const record = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === "object" && !Array.isArray(v);
const uuid = (v: unknown) =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const date = (v: unknown) =>
  typeof v === "string" && Number.isFinite(Date.parse(v));
const code = (v: unknown) =>
  typeof v === "string" && /^[a-z][a-z0-9_]{0,95}$/.test(v);
const reason = (v: unknown) => v === null || code(v);
const codes = (v: unknown) =>
  Array.isArray(v) && v.length <= 64 && v.every(code);
function observation(v: unknown): v is ReconciliationObservation {
  return (
    record(v) &&
    new TextEncoder().encode(JSON.stringify(v)).length <= 32768 &&
    Object.keys(v).length === 9 &&
    v.schema === 1 &&
    (v.state === null ||
      (isGpoSnapshot(v.state) &&
        new TextEncoder().encode(JSON.stringify(v.state)).length <= 16384)) &&
    isGpoLinks(v.forest_links) &&
    typeof v.forest_complete === "boolean" &&
    (v.acl_consistent === null || typeof v.acl_consistent === "boolean") &&
    ["present", "absent", "unknown"].includes(String(v.gpo_presence)) &&
    codes(v.issues) &&
    (v.gpo_guid === "" || uuid(v.gpo_guid)) &&
    typeof v.quiescent === "boolean"
  );
}
export function isReconciliationProjection(
  v: unknown,
): v is ReconciliationProjection {
  if (
    !record(v) ||
    typeof v.can_request !== "boolean" ||
    !reason(v.request_blocked_reason)
  )
    return false;
  const r = v.latest;
  return (
    r === null ||
    (record(r) &&
      uuid(r.id) &&
      [
        "requested",
        "observed",
        "accept_requested",
        "accepted",
        "failed",
        "stale",
      ].includes(String(r.status)) &&
      date(r.requested_at) &&
      date(r.expires_at) &&
      (r.observation === null || observation(r.observation)) &&
      typeof r.observation_digest === "string" &&
      (r.observation_digest === "" ||
        /^[0-9a-f]{64}$/.test(r.observation_digest)) &&
      codes(r.issues) &&
      typeof r.can_accept === "boolean" &&
      reason(r.accept_blocked_reason) &&
      (r.accepted_at === null || date(r.accepted_at)))
  );
}
