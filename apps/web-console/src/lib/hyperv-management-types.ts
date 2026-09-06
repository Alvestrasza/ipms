import type { HyperVVirtualMachine } from "./hyperv-types";

export type ManagementSection =
  | "settings"
  | "checkpoints"
  | "migration"
  | "cluster";
export type ManagementOperation =
  | "inspect"
  | "checkpoint_create"
  | "checkpoint_delete"
  | "checkpoint_apply"
  | "settings_update";
export type ManagementCollectionStatus =
  | "collected"
  | "unavailable"
  | "not-reported";
export type ManagementCheckpoint = {
  id: string;
  parent_id: string | null;
  name: string;
  created_at: string | null;
  type: "standard" | "production" | "recovery" | "unknown";
  is_current: boolean;
  can_apply: boolean;
  can_delete: boolean;
};
export type ManagementSnapshot = {
  schema_version: 1;
  vm_source_id: string;
  vm_name: string;
  state: HyperVVirtualMachine["state"];
  revision: string;
  settings: {
    name: string | null;
    notes: string | null;
    configuration_version: string | null;
    generation: 1 | 2 | null;
    processor: {
      count: number | null;
      reservation_milli_percent: number | null;
      limit_milli_percent: number | null;
      weight: number | null;
      compatibility_for_migration: boolean | null;
    };
    memory: {
      startup_mib: number | null;
      minimum_mib: number | null;
      maximum_mib: number | null;
      dynamic_enabled: boolean | null;
      buffer_percent: number | null;
      weight: number | null;
    };
    automatic_start_action: number | null;
    automatic_start_delay: string | null;
    automatic_stop_action: number | null;
    checkpoint_policy: 2 | 3 | 4 | 5 | null;
  };
  checkpoints: ManagementCheckpoint[];
  devices: { network_adapters: never[]; storage: never[] };
  capabilities: Record<ManagementOperation, boolean>;
  collection_status: Record<
    "settings" | "checkpoints" | "devices",
    ManagementCollectionStatus
  >;
};
export type ManagementJob = {
  id: string;
  request_id: string;
  virtual_machine_id: string | null;
  operation: ManagementOperation;
  status:
    | "queued"
    | "delivered"
    | "running"
    | "requires_reconciliation"
    | "succeeded"
    | "failed"
    | "cancelled";
  phase: string;
  progress: number | null;
  result_code: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  can_cancel: false;
};
export type ManagementPayload = {
  virtual_machine_id: string;
  vm_source_id: string;
  vm_name: string;
  collection_status: "collected" | "not-reported";
  snapshot: ManagementSnapshot | null;
  observed_at: string | null;
  valid_until: string | null;
  fresh: boolean;
  active_operation: ManagementJob | null;
  latest_operation: ManagementJob | null;
};
export type CheckpointRequest =
  | { operation: "checkpoint_create"; parameters: { policy: "configured" } }
  | {
      operation: "checkpoint_delete";
      parameters: {
        checkpoint_id: string;
        acknowledged_checkpoint_ids: string[];
      };
    }
  | {
      operation: "checkpoint_apply";
      parameters: {
        checkpoint_id: string;
        confirmation_vm_name: string;
        confirmation_checkpoint_name: string;
      };
    };

export type SettingsSection = "general" | "processor" | "memory";
export type SettingsRequest = {
  operation: "settings_update";
  parameters:
    | { section: "general"; values: { name: string; notes: string } }
    | { section: "processor"; values: { count: number } }
    | {
        section: "memory";
        values: {
          startup_mib: number;
          minimum_mib: number;
          maximum_mib: number;
          dynamic_enabled: boolean;
        };
      };
};

export function settingsOperationAllowed(
  payload: ManagementPayload | null,
  permitted: boolean,
  now: number,
  busy: boolean,
): boolean {
  return (
    permitted &&
    !busy &&
    isManagementSnapshotFresh(payload, now) &&
    !isManagementJobActive(payload?.active_operation ?? null) &&
    payload?.snapshot?.state === "stopped" &&
    payload.snapshot.collection_status.settings === "collected" &&
    payload.snapshot.capabilities.settings_update === true
  );
}

export function settingsRequest(
  section: SettingsSection,
  fields: Record<string, string | boolean | null>,
): SettingsRequest {
  function text(
    key: string,
    byteLimit: number,
    allowWhitespaceControls: boolean,
  ): string {
    const value = fields[key];
    if (
      typeof value !== "string" ||
      new TextEncoder().encode(value).byteLength > byteLimit
    )
      throw new Error("invalid_request");
    for (const character of value) {
      const code = character.codePointAt(0) ?? 0;
      if (
        (code >= 0xd800 && code <= 0xdfff) ||
        (code < 32 && !(allowWhitespaceControls && [9, 10, 13].includes(code)))
      )
        throw new Error("invalid_request");
    }
    return value;
  }
  function integer(key: string, maximum: number): number {
    const value = fields[key];
    if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value))
      throw new Error("invalid_request");
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed) || parsed > maximum)
      throw new Error("invalid_request");
    return parsed;
  }
  if (section === "general") {
    const name = text("name", 256, false);
    if (name.length > 100 || !name.trim()) throw new Error("invalid_request");
    return {
      operation: "settings_update",
      parameters: {
        section,
        values: { name, notes: text("notes", 4096, true) },
      },
    };
  }
  if (section === "processor")
    return {
      operation: "settings_update",
      parameters: { section, values: { count: integer("count", 2048) } },
    };
  if (section !== "memory") throw new Error("invalid_request");
  const startup_mib = integer("startup_mib", 2 ** 40);
  const minimum_mib = integer("minimum_mib", 2 ** 40);
  const maximum_mib = integer("maximum_mib", 2 ** 40);
  const dynamic_enabled = fields.dynamic_enabled;
  if (
    minimum_mib > startup_mib ||
    startup_mib > maximum_mib ||
    typeof dynamic_enabled !== "boolean"
  )
    throw new Error("invalid_request");
  return {
    operation: "settings_update",
    parameters: {
      section,
      values: { startup_mib, minimum_mib, maximum_mib, dynamic_enabled },
    },
  };
}

export function isManagementJobActive(job: ManagementJob | null): boolean {
  return (
    job !== null &&
    ["queued", "delivered", "running", "requires_reconciliation"].includes(
      job.status,
    )
  );
}

export function isManagementSnapshotFresh(
  payload: ManagementPayload | null,
  now: number,
): boolean {
  return (
    payload?.fresh === true &&
    payload.snapshot !== null &&
    payload.valid_until !== null &&
    Number.isFinite(now) &&
    Date.parse(payload.valid_until) > now
  );
}

// The server independently recomputes this exact subtree under the revision lock.
export function checkpointSubtree(
  checkpoints: ManagementCheckpoint[],
  selectedId: string,
): ManagementCheckpoint[] {
  if (
    checkpoints.length > 256 ||
    !checkpoints.some((item) => item.id === selectedId)
  )
    return [];
  const selected = new Set([selectedId]);
  for (let iteration = 0; iteration < checkpoints.length; iteration++) {
    const previousSize = selected.size;
    for (const item of checkpoints) {
      if (item.parent_id !== null && selected.has(item.parent_id))
        selected.add(item.id);
    }
    if (selected.size === previousSize) break;
  }
  return checkpoints
    .filter((item) => selected.has(item.id))
    .sort((left, right) =>
      left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
    );
}

export function checkpointOperationAllowed({
  payload,
  operation,
  permitted,
  now,
  active,
  busy,
  checkpointId,
}: {
  payload: ManagementPayload | null;
  operation: CheckpointRequest["operation"];
  permitted: boolean;
  now: number;
  active: boolean;
  busy: boolean;
  checkpointId?: string;
}): boolean {
  if (!permitted || active || busy || !isManagementSnapshotFresh(payload, now))
    return false;
  const snapshot = payload?.snapshot;
  if (
    snapshot?.collection_status.checkpoints !== "collected" ||
    snapshot.capabilities[operation] !== true ||
    isManagementJobActive(payload?.active_operation ?? null)
  )
    return false;
  if (operation === "checkpoint_create") return true;
  const checkpoint = snapshot.checkpoints.find(
    (item) => item.id === checkpointId,
  );
  return (
    (operation === "checkpoint_delete"
      ? checkpoint?.can_delete
      : checkpoint?.can_apply) === true
  );
}
