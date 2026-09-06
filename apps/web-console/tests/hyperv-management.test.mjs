import assert from "node:assert/strict";
import test from "node:test";
import {
  checkpointOperationAllowed,
  checkpointSubtree,
  isManagementJobActive,
  isManagementSnapshotFresh,
  settingsOperationAllowed,
  settingsRequest,
} from "../src/lib/hyperv-management-types.ts";

const now = Date.parse("2026-01-01T00:00:00Z");
const checkpoint = (id, parent_id = null) => ({
  id,
  parent_id,
  name: `Checkpoint ${id}`,
  can_apply: true,
  can_delete: true,
});
const payload = () => ({
  fresh: true,
  valid_until: "2026-01-01T00:01:00Z",
  active_operation: null,
  snapshot: {
    checkpoints: [checkpoint("a")],
    collection_status: { checkpoints: "collected" },
    capabilities: {
      checkpoint_create: true,
      checkpoint_apply: true,
      checkpoint_delete: true,
    },
  },
});

test("snapshot freshness requires server attestation, a snapshot and a future valid timestamp", () => {
  assert.equal(isManagementSnapshotFresh(payload(), now), true);
  for (const document of [
    null,
    { ...payload(), fresh: false },
    { ...payload(), snapshot: null },
    { ...payload(), valid_until: null },
    { ...payload(), valid_until: "invalid" },
    { ...payload(), valid_until: "2026-01-01T00:00:00Z" },
  ])
    assert.equal(isManagementSnapshotFresh(document, now), false);
  assert.equal(isManagementSnapshotFresh(payload(), Number.NaN), false);
});

test("reconciliation remains an active blocker; terminal states do not", () => {
  for (const status of [
    "queued",
    "delivered",
    "running",
    "requires_reconciliation",
  ])
    assert.equal(isManagementJobActive({ status }), true);
  for (const status of ["succeeded", "failed", "cancelled"])
    assert.equal(isManagementJobActive({ status }), false);
  assert.equal(isManagementJobActive(null), false);
});

test("deletion acknowledgement contains selected checkpoint and every descendant, deterministically sorted", () => {
  const tree = [
    checkpoint("z", "b"),
    checkpoint("b", "a"),
    checkpoint("other"),
    checkpoint("a"),
    checkpoint("c", "a"),
  ];
  assert.deepEqual(
    checkpointSubtree(tree, "a").map((item) => item.id),
    ["a", "b", "c", "z"],
  );
  assert.deepEqual(
    checkpointSubtree([...tree].reverse(), "b").map((item) => item.id),
    ["b", "z"],
  );
  assert.deepEqual(checkpointSubtree(tree, "missing"), []);
  assert.deepEqual(
    checkpointSubtree(
      Array.from({ length: 257 }, (_, index) => checkpoint(String(index))),
      "0",
    ),
    [],
  );
});

test("malformed cyclic checkpoint input cannot loop indefinitely", () => {
  assert.deepEqual(
    checkpointSubtree([checkpoint("a", "b"), checkpoint("b", "a")], "a").map(
      (item) => item.id,
    ),
    ["a", "b"],
  );
});

test("checkpoint operations require permission, fresh collection, positive native capabilities, no job and no client submission", () => {
  for (const operation of [
    "checkpoint_create",
    "checkpoint_delete",
    "checkpoint_apply",
  ]) {
    const parameters = {
      payload: payload(),
      operation,
      permitted: true,
      now,
      active: false,
      busy: false,
      checkpointId: "a",
    };
    assert.equal(checkpointOperationAllowed(parameters), true);
    for (const override of [
      { permitted: false },
      { active: true },
      { busy: true },
      { now: now + 60_000 },
      { payload: null },
    ])
      assert.equal(
        checkpointOperationAllowed({ ...parameters, ...override }),
        false,
      );
    for (const active_operation of [
      "queued",
      "running",
      "requires_reconciliation",
    ])
      assert.equal(
        checkpointOperationAllowed({
          ...parameters,
          payload: {
            ...payload(),
            active_operation: { status: active_operation },
          },
        }),
        false,
      );
    for (const collection_status of ["unavailable", "not-reported"]) {
      const document = payload();
      document.snapshot.collection_status.checkpoints = collection_status;
      assert.equal(
        checkpointOperationAllowed({ ...parameters, payload: document }),
        false,
      );
    }
    const document = payload();
    document.snapshot.capabilities[operation] = false;
    assert.equal(
      checkpointOperationAllowed({ ...parameters, payload: document }),
      false,
    );
    if (operation !== "checkpoint_create") {
      assert.equal(
        checkpointOperationAllowed({ ...parameters, checkpointId: "unknown" }),
        false,
      );
      const unsupported = payload();
      unsupported.snapshot.checkpoints[0][
        operation === "checkpoint_delete" ? "can_delete" : "can_apply"
      ] = false;
      assert.equal(
        checkpointOperationAllowed({ ...parameters, payload: unsupported }),
        false,
      );
    }
  }
});

test("settings updates send exactly one typed section with no provider or extra fields", () => {
  assert.deepEqual(
    settingsRequest("general", {
      name: " VM name ",
      notes: "Notes\r\nwith\ttabs",
      command: "ignored",
    }),
    {
      operation: "settings_update",
      parameters: {
        section: "general",
        values: { name: " VM name ", notes: "Notes\r\nwith\ttabs" },
      },
    },
  );
  assert.deepEqual(
    settingsRequest("processor", { count: "4", name: "ignored" }),
    {
      operation: "settings_update",
      parameters: { section: "processor", values: { count: 4 } },
    },
  );
  assert.deepEqual(
    settingsRequest("memory", {
      startup_mib: "4096",
      minimum_mib: "1024",
      maximum_mib: "8192",
      dynamic_enabled: true,
      command: "ignored",
    }),
    {
      operation: "settings_update",
      parameters: {
        section: "memory",
        values: {
          startup_mib: 4096,
          minimum_mib: 1024,
          maximum_mib: 8192,
          dynamic_enabled: true,
        },
      },
    },
  );
});

test("settings text has exact UTF-16 and UTF-8 bounds with no null or malformed Unicode", () => {
  for (const name of [
    null,
    "",
    " ",
    "a".repeat(101),
    "😀".repeat(51),
    "中".repeat(86),
    "x\0y",
    "x\ny",
    "x\ty",
    "\ud800",
    "\udfff",
  ])
    assert.throws(
      () => settingsRequest("general", { name, notes: "" }),
      /invalid_request/,
    );
  for (const notes of [null, "x\0y", "\ud800", "é".repeat(2049)])
    assert.throws(
      () => settingsRequest("general", { name: "VM", notes }),
      /invalid_request/,
    );
  assert.equal(
    settingsRequest("general", {
      name: "😀".repeat(50),
      notes: "é".repeat(2048),
    }).parameters.values.name.length,
    100,
  );
});

test("settings integers and complete memory tuples cannot default unknown values or accept exponent forms", () => {
  assert.throws(
    () =>
      settingsRequest("unknown", {
        startup_mib: "4096",
        minimum_mib: "1024",
        maximum_mib: "8192",
        dynamic_enabled: true,
      }),
    /invalid_request/,
  );
  for (const count of [
    null,
    true,
    "",
    "0",
    "-1",
    "1.5",
    "1e2",
    "01",
    " 4 ",
    "2049",
    "Infinity",
  ])
    assert.throws(
      () => settingsRequest("processor", { count }),
      /invalid_request/,
    );
  const memory = {
    startup_mib: "4096",
    minimum_mib: "1024",
    maximum_mib: "8192",
    dynamic_enabled: false,
  };
  for (const overrides of [
    { minimum_mib: "8192" },
    { maximum_mib: "1024" },
    { startup_mib: null },
    { dynamic_enabled: null },
    { dynamic_enabled: "false" },
    { maximum_mib: String(2 ** 40 + 1) },
  ])
    assert.throws(
      () => settingsRequest("memory", { ...memory, ...overrides }),
      /invalid_request/,
    );
});

test("settings editing is fail-closed for running, unknown, stale, unsupported or busy VMs", () => {
  const document = payload();
  document.snapshot.state = "stopped";
  document.snapshot.collection_status.settings = "collected";
  document.snapshot.capabilities.settings_update = true;
  assert.equal(settingsOperationAllowed(document, true, now, false), true);
  assert.equal(settingsOperationAllowed(document, false, now, false), false);
  assert.equal(settingsOperationAllowed(document, true, now, true), false);
  assert.equal(
    settingsOperationAllowed(document, true, now + 60_000, false),
    false,
  );
  for (const state of ["running", "paused", "unknown", "starting"])
    assert.equal(
      settingsOperationAllowed(
        { ...document, snapshot: { ...document.snapshot, state } },
        true,
        now,
        false,
      ),
      false,
    );
  for (const settings of ["unavailable", "not-reported"])
    assert.equal(
      settingsOperationAllowed(
        {
          ...document,
          snapshot: {
            ...document.snapshot,
            collection_status: {
              ...document.snapshot.collection_status,
              settings,
            },
          },
        },
        true,
        now,
        false,
      ),
      false,
    );
  assert.equal(
    settingsOperationAllowed(
      { ...document, active_operation: { status: "requires_reconciliation" } },
      true,
      now,
      false,
    ),
    false,
  );
});
