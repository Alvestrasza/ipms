/**
 * File Name: hgs-contract.test.mjs
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Verify HGS browser contract boundaries and exact, unexpired execution review.
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  canExecuteHgsPlan,
  canResolveHgsPlan,
  hgsRecoveryReviewKey,
  isHgsDeployment,
  isHgsFeatureSource,
  isHgsOverview,
  shouldPollHgsPlan,
} from "../src/lib/hgs-types.ts";

const tenant = "10000000-0000-4000-8000-000000000001";
const node = "20000000-0000-4000-8000-000000000001";
const system = "30000000-0000-4000-8000-000000000001";
const now = Date.parse("2026-09-19T12:00:00Z");
const plan = {
  id: "40000000-0000-4000-8000-000000000001",
  tenant_id: tenant,
  name: "HGS fixture",
  profile: "vtpm",
  attestation_mode: "host_key",
  status: "ready",
  domain_name: "hgs.example.test",
  service_name: "hgs",
  plan_digest: "a".repeat(64),
  config: {
    feature_source: "D:\\Sources\\SxS",
    signing_thumbprint: "b".repeat(40),
    encryption_thumbprint: "c".repeat(40),
    dsrm_secret_ref: "hgs-dsrm",
    join_secret_ref: "",
    allow_reboot: true,
    primary_server: "",
  },
  plan_expires_at: "2026-09-20T11:45:00Z",
  approval_expires_at: null,
  created_at: "2026-09-19T11:45:00Z",
  updated_at: "2026-09-19T11:58:00Z",
  blockers: [],
  nodes: [
    {
      id: node,
      system_id: system,
      hostname: "hgs-lab",
      role: "primary",
      status: "ready",
      readiness: { ready: true },
      blockers: [],
      observed_at: "2026-09-19T11:58:00Z",
    },
  ],
  steps: [
    {
      id: "step-1",
      operation: "install_role",
      node_id: node,
      hostname: "hgs-lab",
      mutates: true,
      requires_reboot: true,
      status: "pending",
    },
  ],
  jobs: [],
};

test("both HGS profiles are accepted on one Appliance without equating vTPM to shielding", () => {
  const secure = { ...plan, profile: "shielded", attestation_mode: "tpm" };
  assert.equal(isHgsDeployment(plan, tenant), true);
  assert.equal(isHgsDeployment(secure, tenant), true);
  assert.equal(
    isHgsDeployment({ ...plan, attestation_mode: "tpm" }, tenant),
    true,
  );
  assert.equal(
    isHgsDeployment({ ...plan, profile: "shielded" }, tenant),
    false,
  );
  assert.equal(
    isHgsOverview(
      {
        tenant_purpose: "hgs",
        can_manage: true,
        profiles: [
          { id: "vtpm", label: "vTPM" },
          { id: "shielded", label: "Shielded" },
        ],
        systems: [],
        deployments: [plan, secure],
        single_appliance_supported: true,
      },
      tenant,
    ),
    true,
  );
});

test("foreign tenants, malformed references and unsupported states are rejected", () => {
  assert.equal(isHgsDeployment(plan, "foreign-tenant"), false);
  assert.equal(
    isHgsDeployment(
      { ...plan, steps: [{ ...plan.steps[0], node_id: system }] },
      tenant,
    ),
    false,
  );
  assert.equal(
    isHgsDeployment({ ...plan, nodes: [...plan.nodes, plan.nodes[0]] }, tenant),
    false,
  );
  assert.equal(
    isHgsDeployment({ ...plan, plan_digest: "not-a-digest" }, tenant),
    false,
  );
  assert.equal(
    isHgsDeployment({ ...plan, status: "assumed_success" }, tenant),
    false,
  );
  assert.equal(
    isHgsDeployment({ ...plan, plan_expires_at: "invalid" }, tenant),
    false,
  );
  assert.equal(
    isHgsDeployment(
      { ...plan, config: { ...plan.config, allow_reboot: "true" } },
      tenant,
    ),
    false,
  );
});

test("execution needs exact review, a ready unexpired plan and fresh evidence from every node", () => {
  assert.equal(canExecuteHgsPlan(plan, plan.plan_digest, now), true);
  assert.equal(canExecuteHgsPlan(plan, "", now), false);
  assert.equal(canExecuteHgsPlan(plan, "d".repeat(64), now), false);
  for (const status of [
    "draft",
    "blocked",
    "inspecting",
    "failed",
    "cancelled",
    "reconciliation_required",
    "running",
    "waiting_for_reboot",
    "succeeded",
  ])
    assert.equal(
      canExecuteHgsPlan({ ...plan, status }, plan.plan_digest, now),
      false,
      status,
    );
  assert.equal(
    canExecuteHgsPlan(
      { ...plan, plan_expires_at: new Date(now).toISOString() },
      plan.plan_digest,
      now,
    ),
    false,
  );
  assert.equal(
    canExecuteHgsPlan(
      { ...plan, blockers: ["certificate_missing"] },
      plan.plan_digest,
      now,
    ),
    false,
  );
  for (const observed_at of [
    null,
    "2026-09-19T11:30:00Z",
    "2026-09-19T12:10:00Z",
  ])
    assert.equal(
      canExecuteHgsPlan(
        { ...plan, nodes: [{ ...plan.nodes[0], observed_at }] },
        plan.plan_digest,
        now,
      ),
      false,
    );
  assert.equal(
    canExecuteHgsPlan(
      { ...plan, nodes: [{ ...plan.nodes[0], blockers: ["secret_missing"] }] },
      plan.plan_digest,
      now,
    ),
    false,
  );
});

test("only active inspections, execution and reboot waits need automatic polling", () => {
  assert.equal(shouldPollHgsPlan(null), false);
  for (const status of [
    "draft",
    "blocked",
    "ready",
    "failed",
    "cancelled",
    "succeeded",
    "reconciliation_required",
  ])
    assert.equal(shouldPollHgsPlan({ ...plan, status }), false, status);
  for (const status of ["inspecting", "running", "waiting_for_reboot"])
    assert.equal(shouldPollHgsPlan({ ...plan, status }), true, status);
});

test("recovery release binds explicit review to the exact plan, interrupted job and fresh evidence", () => {
  const recovery = {
    ...plan,
    status: "reconciliation_required",
    reconciliation: {
      job_id: "50000000-0000-4000-8000-000000000001",
      observation_digest: "e".repeat(64),
      can_resolve: true,
      reason: "",
    },
  };
  const review = hgsRecoveryReviewKey(recovery);
  assert.equal(isHgsDeployment(recovery, tenant), true);
  assert.equal(canResolveHgsPlan(recovery, ""), false);
  assert.equal(canResolveHgsPlan(recovery, review), true);
  assert.equal(
    canResolveHgsPlan({ ...recovery, plan_digest: "f".repeat(64) }, review),
    false,
  );
  assert.equal(
    canResolveHgsPlan(
      {
        ...recovery,
        reconciliation: {
          ...recovery.reconciliation,
          observation_digest: "f".repeat(64),
        },
      },
      review,
    ),
    false,
  );
  assert.equal(
    canResolveHgsPlan(
      {
        ...recovery,
        reconciliation: { ...recovery.reconciliation, can_resolve: false },
      },
      review,
    ),
    false,
  );
  assert.equal(
    canResolveHgsPlan({ ...recovery, status: "running" }, review),
    false,
  );
  assert.equal(
    isHgsDeployment(
      {
        ...recovery,
        reconciliation: { ...recovery.reconciliation, observation_digest: "" },
      },
      tenant,
    ),
    false,
  );
  assert.equal(
    shouldPollHgsPlan({ ...recovery, jobs: [{ status: "queued" }] }),
    true,
  );
});

test("offline feature sources stay inside the bounded local path contract", () => {
  for (const source of ["D:\\Sources\\SxS", "E:\\Approved Windows\\sources"])
    assert.equal(isHgsFeatureSource(source), true, source);
  for (const source of [
    "\\\\server\\share",
    "https://example.test/source",
    "C:relative",
    "D:\\a..b",
    "D:\\..\\source",
    "D:\\.\\source",
    "D:\\source:stream",
    "D:\\$source",
    "D:\\source;command",
    "D:\\source`name",
    "D:\\source*",
    "D:\\source?",
    "D:\\source\nname",
    `D:\\${"a".repeat(238)}`,
  ])
    assert.equal(isHgsFeatureSource(source), false, source);
});
