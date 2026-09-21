/**
 * File Name: hgs-types.ts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Validate tenant-bound HGS plans and gate reviewed execution.
 */
export type HgsProfile = "vtpm" | "shielded";
export type HgsAttestation = "host_key" | "tpm";
export type HgsStatus =
  | "draft"
  | "inspecting"
  | "blocked"
  | "ready"
  | "running"
  | "waiting_for_reboot"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "reconciliation_required";
export type HgsSystem = {
  id: string;
  hostname: string;
  agent_version: string;
  eligible: boolean;
  reason: string;
};
export type HgsNode = {
  id: string;
  system_id: string;
  hostname: string;
  role: "primary" | "additional";
  status: string;
  readiness: Record<string, unknown> | null;
  blockers: string[];
  observed_at: string | null;
};
export type HgsStep = {
  id: string;
  operation: string;
  node_id: string;
  hostname: string;
  mutates: boolean;
  requires_reboot: boolean;
  status: string;
};
export type HgsJob = {
  id: string;
  node_id: string;
  operation: string;
  status: string;
  result_code: string;
  created_at: string;
  completed_at: string | null;
};
export type HgsDeployment = {
  id: string;
  tenant_id: string;
  name: string;
  profile: HgsProfile;
  attestation_mode: HgsAttestation;
  status: HgsStatus;
  domain_name: string;
  service_name: string;
  plan_digest: string;
  config: {
    feature_source: string;
    signing_thumbprint: string;
    encryption_thumbprint: string;
    dsrm_secret_ref: string;
    join_secret_ref: string;
    allow_reboot: boolean;
    primary_server: string;
  };
  plan_expires_at: string;
  approval_expires_at: string | null;
  created_at: string;
  updated_at: string;
  blockers: string[];
  nodes: HgsNode[];
  steps: HgsStep[];
  jobs: HgsJob[];
  reconciliation?: {
    job_id: string;
    observation_digest: string;
    can_resolve: boolean;
    reason: string;
  } | null;
};
export type HgsOverview = {
  tenant_purpose: "infrastructure" | "hgs";
  can_manage: boolean;
  profiles: { id: HgsProfile; label: string }[];
  systems: HgsSystem[];
  deployments: HgsDeployment[];
  single_appliance_supported: boolean;
};

const statuses: HgsStatus[] = [
  "draft",
  "inspecting",
  "blocked",
  "ready",
  "running",
  "waiting_for_reboot",
  "succeeded",
  "failed",
  "cancelled",
  "reconciliation_required",
];
const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): value is string =>
  typeof value === "string" && value.length <= 4096;
const uuid = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}$/i.test(value);
const date = (value: unknown): value is string =>
  typeof value === "string" && Number.isFinite(Date.parse(value));
const nullableDate = (value: unknown): value is string | null =>
  value === null || date(value);
const strings = (value: unknown): value is string[] =>
  Array.isArray(value) && value.length <= 1000 && value.every(text);
const profile = (value: unknown): value is HgsProfile =>
  value === "vtpm" || value === "shielded";
function node(value: unknown): value is HgsNode {
  return (
    record(value) &&
    uuid(value.id) &&
    uuid(value.system_id) &&
    text(value.hostname) &&
    ["primary", "additional"].includes(String(value.role)) &&
    text(value.status) &&
    (value.readiness === null || record(value.readiness)) &&
    strings(value.blockers) &&
    nullableDate(value.observed_at)
  );
}
function step(value: unknown): value is HgsStep {
  return (
    record(value) &&
    text(value.id) &&
    text(value.operation) &&
    uuid(value.node_id) &&
    text(value.hostname) &&
    typeof value.mutates === "boolean" &&
    typeof value.requires_reboot === "boolean" &&
    text(value.status)
  );
}
function job(value: unknown): value is HgsJob {
  return (
    record(value) &&
    uuid(value.id) &&
    uuid(value.node_id) &&
    text(value.operation) &&
    text(value.status) &&
    text(value.result_code) &&
    date(value.created_at) &&
    nullableDate(value.completed_at)
  );
}

/** A response for another tenant or an inconsistent secure profile is never displayed. */
export function isHgsDeployment(
  value: unknown,
  tenantId: string,
): value is HgsDeployment {
  if (
    !record(value) ||
    !uuid(value.id) ||
    value.tenant_id !== tenantId ||
    !text(value.name) ||
    !profile(value.profile) ||
    !["host_key", "tpm"].includes(String(value.attestation_mode)) ||
    (value.profile === "shielded" && value.attestation_mode !== "tpm") ||
    !statuses.includes(value.status as HgsStatus) ||
    !text(value.domain_name) ||
    !text(value.service_name) ||
    typeof value.plan_digest !== "string" ||
    !/^[a-f\d]{64}$/i.test(value.plan_digest) ||
    !record(value.config) ||
    ![
      "feature_source",
      "signing_thumbprint",
      "encryption_thumbprint",
      "dsrm_secret_ref",
      "join_secret_ref",
      "primary_server",
    ].every((key) => text((value.config as Record<string, unknown>)[key])) ||
    typeof value.config.allow_reboot !== "boolean" ||
    !date(value.plan_expires_at) ||
    !nullableDate(value.approval_expires_at) ||
    !date(value.created_at) ||
    !date(value.updated_at) ||
    !strings(value.blockers) ||
    !Array.isArray(value.nodes) ||
    !value.nodes.length ||
    value.nodes.length > 64 ||
    !value.nodes.every(node) ||
    !Array.isArray(value.steps) ||
    !value.steps.length ||
    value.steps.length > 1000 ||
    !value.steps.every(step) ||
    !Array.isArray(value.jobs) ||
    value.jobs.length > 1000 ||
    !value.jobs.every(job) ||
    (value.reconciliation !== undefined &&
      value.reconciliation !== null &&
      (!record(value.reconciliation) ||
        !uuid(value.reconciliation.job_id) ||
        typeof value.reconciliation.observation_digest !== "string" ||
        !/^(?:[a-f\d]{64})?$/i.test(value.reconciliation.observation_digest) ||
        typeof value.reconciliation.can_resolve !== "boolean" ||
        !text(value.reconciliation.reason) ||
        (value.reconciliation.can_resolve &&
          !value.reconciliation.observation_digest)))
  )
    return false;
  const nodeIds = new Set(value.nodes.map((item) => item.id));
  return (
    nodeIds.size === value.nodes.length &&
    new Set(value.nodes.map((item) => item.system_id)).size ===
      value.nodes.length &&
    value.nodes.filter((item) => item.role === "primary").length === 1 &&
    value.steps.every((item) => nodeIds.has(item.node_id)) &&
    value.jobs.every((item) => nodeIds.has(item.node_id))
  );
}

export function isHgsOverview(
  value: unknown,
  tenantId: string,
): value is HgsOverview {
  return (
    record(value) &&
    ["infrastructure", "hgs"].includes(String(value.tenant_purpose)) &&
    typeof value.can_manage === "boolean" &&
    value.single_appliance_supported === true &&
    Array.isArray(value.profiles) &&
    value.profiles.length <= 2 &&
    value.profiles.every(
      (item) => record(item) && profile(item.id) && text(item.label),
    ) &&
    Array.isArray(value.systems) &&
    value.systems.length <= 10000 &&
    value.systems.every(
      (item) =>
        record(item) &&
        uuid(item.id) &&
        text(item.hostname) &&
        text(item.agent_version) &&
        typeof item.eligible === "boolean" &&
        text(item.reason),
    ) &&
    Array.isArray(value.deployments) &&
    value.deployments.length <= 1000 &&
    value.deployments.every((item) => isHgsDeployment(item, tenantId))
  );
}

/** The server remains authoritative; the browser additionally fences stale review state. */
export function canExecuteHgsPlan(
  plan: HgsDeployment,
  reviewedDigest: string,
  now: number,
): boolean {
  return (
    plan.status === "ready" &&
    reviewedDigest === plan.plan_digest &&
    Date.parse(plan.plan_expires_at) > now &&
    plan.blockers.length === 0 &&
    plan.nodes.every(
      (item) =>
        item.blockers.length === 0 &&
        item.observed_at !== null &&
        Date.parse(item.observed_at) <= now + 60_000 &&
        Date.parse(item.observed_at) > now - 30 * 60_000,
    )
  );
}

export function shouldPollHgsPlan(plan: HgsDeployment | null): boolean {
  return (
    !!plan &&
    (["inspecting", "running", "waiting_for_reboot"].includes(plan.status) ||
      plan.jobs.some((item) =>
        ["queued", "offered", "running", "waiting_for_reboot"].includes(
          item.status,
        ),
      ))
  );
}

export function hgsRecoveryReviewKey(plan: HgsDeployment): string {
  const evidence = plan.reconciliation;
  return evidence?.can_resolve && evidence.observation_digest
    ? `${plan.id}:${plan.plan_digest}:${evidence.job_id}:${evidence.observation_digest}`
    : "";
}

export function canResolveHgsPlan(
  plan: HgsDeployment,
  reviewedKey: string,
): boolean {
  return (
    plan.status === "reconciliation_required" &&
    !!reviewedKey &&
    reviewedKey === hgsRecoveryReviewKey(plan)
  );
}

/** Match the bounded native-provider path contract before a plan is submitted. */
export function isHgsFeatureSource(source: string): boolean {
  return (
    source.length >= 4 &&
    source.length <= 240 &&
    /^[A-Za-z]:\\/.test(source) &&
    !/[<>"|?*$;`]/.test(source) &&
    !source.slice(2).includes(":") &&
    !source.includes("..") &&
    !source.split("\\").includes(".") &&
    [...source].every(
      (char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) < 127,
    )
  );
}
