"use client";

import {
  Camera,
  ChevronRight,
  RefreshCw,
  Settings,
  TriangleAlert,
  X,
} from "lucide-react";
import { useCallback, useEffect, useId, useRef, useState } from "react";

import {
  getHyperVManagementCopy,
  type HyperVManagementCopy,
} from "@/i18n/hyperv-management-copy";
import { useLocale } from "@/i18n/locale-provider";
import {
  type CheckpointRequest,
  checkpointOperationAllowed,
  checkpointSubtree,
  isManagementJobActive,
  isManagementSnapshotFresh,
  type ManagementCheckpoint,
  type ManagementJob,
  type ManagementPayload,
  type ManagementSection,
  type ManagementSnapshot,
  type SettingsRequest,
  type SettingsSection,
  settingsFieldRule,
  settingsOperationAllowed,
  settingsRequest,
} from "@/lib/hyperv-management-types";
import type { HyperVVirtualMachine } from "@/lib/hyperv-types";

type Confirmation = {
  operation: "checkpoint_delete" | "checkpoint_apply";
  checkpoint: ManagementCheckpoint;
  affected: ManagementCheckpoint[];
  revision: string;
  vmName: string;
};

function timestamp(value: string | null, unknown: string): string {
  if (!value) return unknown;
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? unknown
    : date.toISOString().replace("T", " ").replace(".000Z", " UTC");
}

function errorMessage(code: string, copy: HyperVManagementCopy): string {
  return Object.hasOwn(copy.errors, code)
    ? copy.errors[code as keyof typeof copy.errors]
    : copy.errors.unknown;
}

async function responseDocument<T>(response: Response): Promise<T> {
  const document = await response.json();
  if (!response.ok) {
    throw new Error(
      typeof document?.error?.code === "string"
        ? document.error.code
        : "unknown",
    );
  }
  return document as T;
}

function SettingsEditor({
  snapshot,
  section,
  allowed,
  copy,
  formId,
  onDirty,
  onSubmit,
}: {
  snapshot: ManagementSnapshot;
  section: SettingsSection;
  allowed: boolean;
  copy: HyperVManagementCopy;
  formId: string;
  onDirty: (section: SettingsSection, dirty: boolean) => void;
  onSubmit: (request: SettingsRequest) => void;
}) {
  const settings = snapshot.settings;
  const initial: Record<string, string | boolean | null> = {
    name: settings.name,
    notes: settings.notes,
    count: settings.processor.count?.toString() ?? null,
    startup_mib: settings.memory.startup_mib?.toString() ?? null,
    minimum_mib: settings.memory.minimum_mib?.toString() ?? null,
    maximum_mib: settings.memory.maximum_mib?.toString() ?? null,
    dynamic_enabled: settings.memory.dynamic_enabled,
  };
  const [fields, setFields] = useState(initial);
  const [invalid, setInvalid] = useState(false);
  const keys =
    section === "general"
      ? ["name", "notes"]
      : section === "processor"
        ? ["count"]
        : ["startup_mib", "minimum_mib", "maximum_mib", "dynamic_enabled"];
  const known =
    snapshot.schema_version === 2
      ? keys.some((key) =>
          ["editable", "increase_only", "decrease_only"].includes(
            settingsFieldRule(snapshot, section, key),
          ),
        )
      : keys.every((key) => initial[key] !== null);
  const changed = keys.some((key) => fields[key] !== initial[key]);
  const editable = (key: string) =>
    allowed &&
    ["editable", "increase_only", "decrease_only"].includes(
      settingsFieldRule(snapshot, section, key),
    );
  const hint = (key: string) => {
    const rule = settingsFieldRule(snapshot, section, key);
    return rule === "editable" ? null : (
      <small id={`${formId}-${key}-hint`}>{copy.fieldRules[rule]}</small>
    );
  };
  useEffect(() => {
    onDirty(section, known && changed);
  }, [section, known, changed, onDirty]);
  const update = (key: string, value: string | boolean) => {
    setFields((previous) => ({ ...previous, [key]: value }));
    setInvalid(false);
  };
  function numeric(key: string, label: string, maximum: number) {
    const rule = settingsFieldRule(snapshot, section, key);
    return (
      <label key={key}>
        <span id={`${formId}-${key}-label`}>{label}</span>
        <input
          type="number"
          aria-labelledby={`${formId}-${key}-label`}
          aria-describedby={
            rule !== "editable" ? `${formId}-${key}-hint` : undefined
          }
          disabled={!editable(key)}
          min={rule === "increase_only" ? Number(initial[key]) : 1}
          max={rule === "decrease_only" ? Number(initial[key]) : maximum}
          step={1}
          required
          value={typeof fields[key] === "string" ? fields[key] : ""}
          placeholder={copy.unknown}
          onChange={(event) => update(key, event.target.value)}
        />
        {hint(key)}
      </label>
    );
  }
  return (
    <form
      id={formId}
      className="hyperv-management-dialog__settings-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (!allowed || !known || !changed) return;
        try {
          onSubmit(settingsRequest(section, fields, snapshot));
        } catch {
          setInvalid(true);
        }
      }}
    >
      <fieldset disabled={!allowed || !known}>
        <legend className="sr-only">{copy.settings[section]}</legend>
        {section === "general" ? (
          <>
            <label>
              {copy.settings.name}
              <input
                disabled={!editable("name")}
                aria-label={copy.settings.name}
                required
                maxLength={100}
                autoComplete="off"
                value={typeof fields.name === "string" ? fields.name : ""}
                placeholder={copy.unknown}
                onChange={(event) => update("name", event.target.value)}
              />
              {hint("name")}
            </label>
            <label>
              <span id={`${formId}-notes-label`}>{copy.settings.notes}</span>
              <textarea
                disabled={!editable("notes")}
                aria-labelledby={`${formId}-notes-label`}
                maxLength={4096}
                rows={3}
                value={typeof fields.notes === "string" ? fields.notes : ""}
                placeholder={copy.unknown}
                onChange={(event) => update("notes", event.target.value)}
              />
              {hint("notes")}
            </label>
          </>
        ) : section === "processor" ? (
          numeric("count", copy.settings.count, 2048)
        ) : (
          <>
            {numeric("startup_mib", `${copy.settings.startup} (MiB)`, 2 ** 40)}
            {numeric("minimum_mib", `${copy.settings.minimum} (MiB)`, 2 ** 40)}
            {numeric("maximum_mib", `${copy.settings.maximum} (MiB)`, 2 ** 40)}
            <label>
              <input
                type="checkbox"
                disabled={!editable("dynamic_enabled")}
                aria-label={copy.settings.dynamic}
                checked={fields.dynamic_enabled === true}
                onChange={(event) =>
                  update("dynamic_enabled", event.target.checked)
                }
              />{" "}
              {copy.settings.dynamic}
              {fields.dynamic_enabled === null ? ` · ${copy.unknown}` : ""}
              {hint("dynamic_enabled")}
            </label>
          </>
        )}
      </fieldset>
      {keys.some((key) => initial[key] === null) ? (
        <p>{copy.settingsMissing}</p>
      ) : null}
      {invalid ? (
        <p className="form-error" role="alert">
          {copy.settingsInvalid}
        </p>
      ) : null}
    </form>
  );
}

type SettingsPage = SettingsSection | "automatic" | "devices" | "policy";
const settingsGroups = [
  { label: "identity", pages: ["general"] },
  { label: "hardware", pages: ["processor", "memory", "devices"] },
  { label: "management", pages: ["automatic", "policy"] },
] as const;
const editablePages: SettingsSection[] = ["general", "processor", "memory"];

function SettingsView({
  snapshot,
  page,
  copy,
  allowed,
  formId,
  onDirty,
  onSubmit,
}: {
  snapshot: ManagementSnapshot;
  page: SettingsPage;
  copy: HyperVManagementCopy;
  allowed: boolean;
  formId: string;
  onDirty: (section: SettingsSection, dirty: boolean) => void;
  onSubmit: (request: SettingsRequest) => void;
}) {
  const settings = snapshot.settings;
  const scalar = (value: string | number | boolean | null) =>
    value === null
      ? copy.unknown
      : typeof value === "boolean"
        ? value
          ? copy.yes
          : copy.no
        : String(value);
  const percent = (value: number | null, divisor = 1) =>
    value === null ? copy.unknown : `${value / divisor} %`;
  // Editable values appear only in their form. This list contains additional,
  // read-only properties, never a second copy of the same setting.
  const fields: Record<SettingsPage, [string, string][]> = {
    general: [
      [copy.settings.version, scalar(settings.configuration_version)],
      [copy.settings.generation, scalar(settings.generation)],
    ],
    processor: [
      [
        copy.settings.reservation,
        percent(settings.processor.reservation_milli_percent, 1000),
      ],
      [
        copy.settings.limit,
        percent(settings.processor.limit_milli_percent, 1000),
      ],
      [copy.settings.weight, scalar(settings.processor.weight)],
      [
        copy.settings.compatibility,
        scalar(settings.processor.compatibility_for_migration),
      ],
    ],
    memory: [
      [copy.settings.buffer, percent(settings.memory.buffer_percent)],
      [copy.settings.weight, scalar(settings.memory.weight)],
    ],
    automatic: [
      [copy.settings.startAction, scalar(settings.automatic_start_action)],
      [copy.settings.startDelay, scalar(settings.automatic_start_delay)],
      [copy.settings.stopAction, scalar(settings.automatic_stop_action)],
    ],
    policy: [
      [
        copy.settings.policy,
        settings.checkpoint_policy === null
          ? copy.unknown
          : copy.policies[settings.checkpoint_policy],
      ],
    ],
    devices: [],
  };
  if (snapshot.collection_status.settings !== "collected")
    return (
      <p className="hyperv-management-dialog__muted">{copy.unavailable}</p>
    );
  return (
    <>
      {editablePages.map((item) => (
        <div key={item} hidden={page !== item}>
          <SettingsEditor
            key={`${snapshot.revision}:${item}`}
            snapshot={snapshot}
            section={item}
            allowed={allowed}
            copy={copy}
            formId={`${formId}-${item}`}
            onDirty={onDirty}
            onSubmit={onSubmit}
          />
        </div>
      ))}
      {fields[page].length ? (
        <section
          aria-label={copy.settings.additional}
          className="hyperv-management-dialog__properties"
        >
          <div className="hyperv-management-dialog__properties-heading">
            <h5>{copy.settings.additional}</h5>
            <span>{copy.settings.readOnlyLabel}</span>
          </div>
          <dl className="hyperv-management-dialog__details">
            {fields[page].map(([label, value]) => (
              <div key={label}>
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        </section>
      ) : (
        <p className="hyperv-management-dialog__notice">
          {copy.settings.devicesHint}
        </p>
      )}
    </>
  );
}

function CheckpointTree({
  checkpoints,
  selectedId,
  onSelect,
  copy,
  parentId = null,
  visited = new Set<string>(),
}: {
  checkpoints: ManagementCheckpoint[];
  selectedId: string;
  onSelect: (checkpoint: ManagementCheckpoint) => void;
  copy: HyperVManagementCopy;
  parentId?: string | null;
  visited?: Set<string>;
}) {
  const children = checkpoints.filter(
    (item) => item.parent_id === parentId && !visited.has(item.id),
  );
  if (!children.length || visited.size >= 256) return null;
  return (
    <ul className="hyperv-management-dialog__tree">
      {children.map((checkpoint) => (
        <li key={checkpoint.id}>
          <button
            className="hyperv-management-dialog__checkpoint"
            type="button"
            aria-pressed={checkpoint.id === selectedId}
            onClick={() => onSelect(checkpoint)}
          >
            <Camera aria-hidden="true" size={16} />
            <span>
              {checkpoint.name}
              {checkpoint.is_current ? ` · ${copy.checkpoints.current}` : ""}
            </span>
          </button>
          <CheckpointTree
            checkpoints={checkpoints}
            selectedId={selectedId}
            onSelect={onSelect}
            copy={copy}
            parentId={checkpoint.id}
            visited={new Set([...visited, checkpoint.id])}
          />
        </li>
      ))}
    </ul>
  );
}

export function HyperVManagementDialog({
  virtualMachine,
  initialSection,
  tenantId,
  csrfToken,
  canManageCheckpoints,
  canConfigure,
  onClose,
}: {
  virtualMachine: HyperVVirtualMachine;
  initialSection: ManagementSection;
  tenantId: string;
  csrfToken: string;
  canManageCheckpoints: boolean;
  canConfigure: boolean;
  onClose: () => void;
}) {
  const { locale } = useLocale();
  const copy = getHyperVManagementCopy(locale);
  const headingId = useId();
  const settingsFormId = useId();
  const sectionHeadingId = useId();
  const [settingsPage, setSettingsPage] = useState<SettingsPage>("general");
  const [dirtySections, setDirtySections] = useState<
    Partial<Record<SettingsSection, boolean>>
  >({});
  const recordDirty = useCallback((item: SettingsSection, dirty: boolean) => {
    setDirtySections((previous) =>
      previous[item] === dirty ? previous : { ...previous, [item]: dirty },
    );
  }, []);
  const dialog = useRef<HTMLDialogElement>(null);
  const alive = useRef(false);
  const writeInFlight = useRef(false);
  const writeController = useRef<AbortController | null>(null);
  const jobReference = useRef<ManagementJob | null>(null);
  const [section, setSection] = useState(initialSection);
  const [data, setData] = useState<ManagementPayload | null>(null);
  const [job, setJob] = useState<ManagementJob | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [reload, setReload] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [selectedId, setSelectedId] = useState("");
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [vmConfirmation, setVmConfirmation] = useState("");
  const [checkpointConfirmation, setCheckpointConfirmation] = useState("");
  const [needsInspection, setNeedsInspection] = useState(false);
  const endpoint = `/api/v1/hyper-v/virtual-machines/${virtualMachine.id}/management/`;

  useEffect(() => {
    alive.current = true;
    const element = dialog.current;
    if (element && !element.open) element.showModal();
    const clock = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => {
      alive.current = false;
      writeController.current?.abort();
      window.clearInterval(clock);
      element?.close();
    };
  }, []);

  // GET only resumes observation. Refreshing host data always requires an explicit POST.
  useEffect(() => {
    const controller = new AbortController();
    let timer: number | undefined;
    const options = {
      signal: controller.signal,
      cache: "no-store" as const,
      credentials: "same-origin" as const,
      headers: { "X-IPMS-Tenant-ID": tenantId },
    };
    async function poll() {
      try {
        if (isManagementJobActive(jobReference.current)) {
          const current = await responseDocument<ManagementJob>(
            await fetch(
              `/api/v1/hyper-v/management-jobs/${jobReference.current?.id}/`,
              options,
            ),
          );
          if (controller.signal.aborted) return;
          jobReference.current = current;
          setJob(current);
          if (current.operation === "inspect" && current.status === "succeeded")
            setNeedsInspection(false);
        }
        const next = await responseDocument<ManagementPayload>(
          await fetch(endpoint, options),
        );
        if (controller.signal.aborted) return;
        setData(next);
        setNow(Date.now());
        if (next.active_operation) {
          jobReference.current = next.active_operation;
          setJob(next.active_operation);
        } else if (next.latest_operation) {
          jobReference.current = next.latest_operation;
          setJob(next.latest_operation);
        }
      } catch (caught) {
        if (!controller.signal.aborted) {
          setData((previous) =>
            previous ? { ...previous, fresh: false } : previous,
          );
          setError(caught instanceof Error ? caught.message : "unknown");
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
          if (isManagementJobActive(jobReference.current))
            timer = window.setTimeout(poll, 3_000);
        }
      }
    }
    void reload; // An explicit status reload restarts observation, never a mutation.
    void poll();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [endpoint, tenantId, reload]);

  // Reloading or locking a focused control can move browser focus to <body>.
  // Keep keyboard orientation inside the open modal without scrolling its pane.
  useEffect(() => {
    const element = dialog.current;
    if (
      data &&
      !loading &&
      element?.open &&
      !element.contains(document.activeElement)
    )
      element
        .querySelector<HTMLElement>(
          ".hyperv-management-dialog__section-heading",
        )
        ?.focus({ preventScroll: true });
  }, [data, loading]);

  const snapshot = data?.snapshot ?? null;
  const fresh = !needsInspection && isManagementSnapshotFresh(data, now);
  const poweredOn = (snapshot?.state ?? virtualMachine.state) === "running";
  const active =
    isManagementJobActive(job) ||
    isManagementJobActive(data?.active_operation ?? null);
  const checkpointCollection =
    snapshot?.collection_status.checkpoints === "collected";
  const selected =
    snapshot?.checkpoints.find((item) => item.id === selectedId) ?? null;
  const enabled = (
    operation: CheckpointRequest["operation"],
    currentTime = now,
  ) =>
    checkpointOperationAllowed({
      payload: data,
      operation,
      permitted: canManageCheckpoints && !needsInspection,
      now: currentTime,
      active,
      busy: submitting || loading,
      checkpointId: selectedId,
    });
  const createEnabled = enabled("checkpoint_create");
  const deleteEnabled = enabled("checkpoint_delete");
  const applyEnabled = enabled("checkpoint_apply");
  const settingsEnabled = (currentTime = now) =>
    settingsOperationAllowed(
      data,
      canConfigure && !needsInspection,
      currentTime,
      active || submitting || loading,
    );

  async function submit(
    request: CheckpointRequest | SettingsRequest | null,
    revision?: string,
  ) {
    if (writeInFlight.current || active || loading) return;
    if (
      request &&
      (!(request.operation === "settings_update"
        ? settingsEnabled(Date.now())
        : enabled(request.operation, Date.now())) ||
        snapshot?.capabilities[request.operation] !== true ||
        !revision ||
        revision !== snapshot.revision)
    )
      return;
    writeInFlight.current = true;
    const controller = new AbortController();
    writeController.current = controller;
    setSubmitting(true);
    setError("");
    try {
      const next = await responseDocument<ManagementJob>(
        await fetch(`${endpoint}${request ? "operations" : "refresh"}/`, {
          method: "POST",
          cache: "no-store",
          credentials: "same-origin",
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify(
            request
              ? {
                  request_id: crypto.randomUUID(),
                  expected_revision: revision,
                  ...request,
                }
              : { request_id: crypto.randomUUID() },
          ),
        }),
      );
      if (!alive.current) return;
      jobReference.current = next;
      setJob(next);
      setConfirmation(null);
      setData((previous) =>
        previous
          ? { ...previous, fresh: false, active_operation: next }
          : previous,
      );
    } catch (caught) {
      if (alive.current && !controller.signal.aborted) {
        setNeedsInspection(true);
        setData((previous) =>
          previous ? { ...previous, fresh: false } : previous,
        );
        setError(caught instanceof Error ? caught.message : "unknown");
      }
    } finally {
      writeInFlight.current = false;
      if (alive.current) {
        setSubmitting(false);
        setReload((value) => value + 1);
      }
    }
  }

  function requestConfirmation(operation: Confirmation["operation"]) {
    if (
      !snapshot ||
      !selected ||
      (operation === "checkpoint_delete" ? !deleteEnabled : !applyEnabled)
    )
      return;
    setAcknowledged(false);
    setVmConfirmation("");
    setCheckpointConfirmation("");
    setConfirmation({
      operation,
      checkpoint: selected,
      affected: checkpointSubtree(snapshot.checkpoints, selected.id),
      revision: snapshot.revision,
      vmName: snapshot.vm_name,
    });
  }

  function confirmMutation() {
    if (
      !confirmation ||
      !snapshot ||
      !fresh ||
      confirmation.revision !== snapshot.revision
    )
      return;
    if (confirmation.operation === "checkpoint_delete") {
      if (!acknowledged || !deleteEnabled) return;
      void submit(
        {
          operation: "checkpoint_delete",
          parameters: {
            checkpoint_id: confirmation.checkpoint.id,
            acknowledged_checkpoint_ids: confirmation.affected.map(
              (item) => item.id,
            ),
          },
        },
        confirmation.revision,
      );
    } else {
      if (
        !applyEnabled ||
        vmConfirmation !== confirmation.vmName ||
        checkpointConfirmation !== confirmation.checkpoint.name
      )
        return;
      void submit(
        {
          operation: "checkpoint_apply",
          parameters: {
            checkpoint_id: confirmation.checkpoint.id,
            confirmation_vm_name: vmConfirmation,
            confirmation_checkpoint_name: checkpointConfirmation,
          },
        },
        confirmation.revision,
      );
    }
  }

  const confirmationAllowed =
    confirmation !== null &&
    confirmation.revision === snapshot?.revision &&
    (confirmation.operation === "checkpoint_delete"
      ? deleteEnabled && acknowledged
      : applyEnabled &&
        vmConfirmation === confirmation.vmName &&
        checkpointConfirmation === confirmation.checkpoint.name);

  const settingsEditable =
    section === "settings" &&
    editablePages.includes(settingsPage as SettingsSection);
  const settingsGroup = settingsGroups.find((group) =>
    (group.pages as readonly string[]).includes(settingsPage),
  );
  function navigate(value: string) {
    if (value.startsWith("settings:")) {
      setSection("settings");
      setSettingsPage(value.slice(9) as SettingsPage);
    } else setSection(value as ManagementSection);
    setConfirmation(null);
  }

  return (
    <dialog
      ref={dialog}
      className="modal-card hyperv-management-dialog"
      aria-labelledby={headingId}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <header className="modal-card__heading">
        <div className="hyperv-management-dialog__identity">
          <p className="eyebrow">{copy.title}</p>
          <h3 id={headingId}>{data?.vm_name ?? virtualMachine.name}</h3>
        </div>
        <button
          className="icon-button"
          type="button"
          aria-label={copy.close}
          onClick={onClose}
        >
          <X aria-hidden="true" size={18} />
        </button>
        <div className="hyperv-management-dialog__host-row">
          <p className="hyperv-management-dialog__host">
            {copy.host}:{" "}
            {virtualMachine.host_fqdn || virtualMachine.host_hostname}
          </p>
          {poweredOn ? (
            <span
              className="hyperv-management-dialog__power-warning"
              role="status"
              aria-label={copy.powerState}
            >
              <TriangleAlert aria-hidden="true" size={18} />
              {fresh ? copy.poweredOn : copy.lastPoweredOn}
            </span>
          ) : null}
        </div>
      </header>
      <label className="hyperv-management-dialog__mobile-nav">
        <span id={`${headingId}-navigation`}>{copy.currentSection}</span>
        <select
          aria-labelledby={`${headingId}-navigation`}
          value={section === "settings" ? `settings:${settingsPage}` : section}
          onChange={(event) => navigate(event.target.value)}
        >
          {settingsGroups.map((group) => (
            <optgroup
              key={group.label}
              label={copy.settings.groups[group.label]}
            >
              {group.pages.map((item) => (
                <option key={item} value={`settings:${item}`}>
                  {copy.settings[item]}
                </option>
              ))}
            </optgroup>
          ))}
          <optgroup label={copy.otherActions}>
            {(Object.keys(copy.sections) as ManagementSection[])
              .filter((item) => item !== "settings")
              .map((item) => (
                <option key={item} value={item}>
                  {copy.sections[item]}
                </option>
              ))}
          </optgroup>
        </select>
      </label>
      <div className="hyperv-management-dialog__layout">
        <nav className="hyperv-management-dialog__nav" aria-label={copy.title}>
          <button
            type="button"
            aria-expanded={section === "settings"}
            onClick={() => navigate("settings:general")}
          >
            <Settings aria-hidden="true" size={16} />
            <span>{copy.sections.settings}</span>
          </button>
          {section === "settings" ? (
            <div className="hyperv-management-dialog__settings-nav">
              {settingsGroups.map((group) => (
                <div key={group.label}>
                  <p>{copy.settings.groups[group.label]}</p>
                  {group.pages.map((item) => (
                    <button
                      key={item}
                      type="button"
                      aria-current={settingsPage === item ? "page" : undefined}
                      aria-controls={sectionHeadingId}
                      onClick={() => navigate(`settings:${item}`)}
                    >
                      <ChevronRight aria-hidden="true" size={14} />
                      <span>{copy.settings[item]}</span>
                      {dirtySections[item as SettingsSection] ? (
                        <span
                          className="hyperv-management-dialog__draft-dot"
                          aria-hidden="true"
                          title={copy.unsaved}
                        >
                          •
                        </span>
                      ) : null}
                    </button>
                  ))}
                </div>
              ))}
            </div>
          ) : null}
          <p className="hyperv-management-dialog__nav-label">
            {copy.otherActions}
          </p>
          {(Object.keys(copy.sections) as ManagementSection[])
            .filter((item) => item !== "settings")
            .map((item) => (
              <button
                key={item}
                type="button"
                aria-current={section === item ? "page" : undefined}
                onClick={() => navigate(item)}
              >
                {item === "checkpoints" ? (
                  <Camera aria-hidden="true" size={16} />
                ) : (
                  <ChevronRight aria-hidden="true" size={16} />
                )}
                <span>{copy.sections[item]}</span>
              </button>
            ))}
        </nav>
        <div className="hyperv-management-dialog__body">
          <div
            className="hyperv-management-dialog__section-heading"
            id={sectionHeadingId}
            tabIndex={-1}
          >
            {section === "settings" && settingsGroup ? (
              <p>{copy.settings.groups[settingsGroup.label]}</p>
            ) : null}
            <h4>
              {section === "settings"
                ? copy.settings[settingsPage]
                : copy.sections[section]}
            </h4>
          </div>
          <div className="hyperv-management-dialog__toolbar">
            <button
              className="outline-button"
              type="button"
              title={copy.refreshHint}
              disabled={submitting || active || loading}
              onClick={() => void submit(null)}
            >
              <RefreshCw aria-hidden="true" size={16} />
              {copy.refresh}
            </button>
            <button
              className="outline-button"
              type="button"
              disabled={submitting || loading}
              onClick={() => {
                setError("");
                setLoading(true);
                setReload((value) => value + 1);
              }}
            >
              {copy.reload}
            </button>
          </div>
          {loading ? <p role="status">{copy.loading}</p> : null}
          {error ? (
            <p className="form-error" role="alert">
              {errorMessage(error, copy)}
            </p>
          ) : null}
          {needsInspection ? (
            <p className="hyperv-stop-warning" role="alert">
              {copy.uncertainSubmission}
            </p>
          ) : null}
          {job &&
          (job.operation !== "inspect" || job.status !== "succeeded") ? (
            <details
              className="hyperv-management-dialog__job"
              aria-label={copy.job}
              open={
                active ||
                job.status === "failed" ||
                job.status === "requires_reconciliation"
              }
            >
              <summary aria-live="polite" aria-atomic="true">
                <strong>{copy.operations[job.operation]}</strong> ·{" "}
                {copy.statuses[job.status]}
                {job.progress !== null ? ` · ${job.progress}%` : ""}
              </summary>
              <p className="hyperv-management-dialog__muted">
                {copy.jobId}: {job.id}
              </p>
              {job.result_code ? (
                <p>
                  {copy.result}: <code>{job.result_code}</code>
                </p>
              ) : null}
              {job.status === "failed" ? (
                <p>{errorMessage(job.result_code, copy)}</p>
              ) : null}
              {job.status === "requires_reconciliation" ? (
                <p className="hyperv-stop-warning" role="alert">
                  {copy.reconciliation}
                </p>
              ) : active ? (
                <p>{copy.continuing}</p>
              ) : null}
            </details>
          ) : null}
          {section === "migration" || section === "cluster" ? (
            <section>
              <h4>{copy.pending}</h4>
              <p>{copy[section]}</p>
            </section>
          ) : (
            <>
              {snapshot ? (
                <p className="hyperv-management-dialog__muted">
                  {fresh ? copy.fresh : copy.stale} · {copy.observed}:{" "}
                  {timestamp(data?.observed_at ?? null, copy.unknown)}
                </p>
              ) : !loading ? (
                <p>{copy.empty}</p>
              ) : null}
              {section === "settings" ? (
                <>
                  {settingsEditable && snapshot ? (
                    !canConfigure ? (
                      <p className="hyperv-management-dialog__notice">
                        {copy.permission}
                      </p>
                    ) : snapshot.state !== "stopped" ? (
                      <p className="hyperv-management-dialog__notice">
                        {snapshot.state === "running"
                          ? snapshot.schema_version === 2
                            ? copy.settingsRunning
                            : copy.settingsLegacy
                          : copy.settingsStopped}
                      </p>
                    ) : !snapshot.capabilities.settings_update ? (
                      <p className="hyperv-management-dialog__notice">
                        {copy.unsupported}
                      </p>
                    ) : null
                  ) : null}
                  {snapshot ? (
                    <SettingsView
                      snapshot={snapshot}
                      page={settingsPage}
                      copy={copy}
                      formId={settingsFormId}
                      onDirty={recordDirty}
                      allowed={settingsEnabled()}
                      onSubmit={(request) =>
                        void submit(request, snapshot.revision)
                      }
                    />
                  ) : null}
                </>
              ) : (
                <>
                  <div className="hyperv-management-dialog__toolbar">
                    <button
                      className="outline-button"
                      type="button"
                      disabled={!createEnabled}
                      onClick={() =>
                        void submit(
                          {
                            operation: "checkpoint_create",
                            parameters: { policy: "configured" },
                          },
                          snapshot?.revision,
                        )
                      }
                    >
                      {copy.checkpoints.create}
                    </button>
                    <button
                      className="outline-button"
                      type="button"
                      disabled={!applyEnabled}
                      onClick={() => requestConfirmation("checkpoint_apply")}
                    >
                      {copy.checkpoints.apply}
                    </button>
                    <button
                      className="danger-button"
                      type="button"
                      disabled={!deleteEnabled}
                      onClick={() => requestConfirmation("checkpoint_delete")}
                    >
                      {copy.checkpoints.remove}
                    </button>
                  </div>
                  <p className="hyperv-management-dialog__muted">
                    {copy.checkpoints.createHint}
                  </p>
                  {snapshot?.settings.checkpoint_policy === 3 ||
                  snapshot?.settings.checkpoint_policy === 4 ? (
                    <p>{copy.productionUnsupported}</p>
                  ) : snapshot?.settings.checkpoint_policy === 2 ? (
                    <p>{copy.checkpointsDisabled}</p>
                  ) : null}
                  {!canManageCheckpoints ? (
                    <p>{copy.permission}</p>
                  ) : snapshot &&
                    !snapshot.capabilities.checkpoint_create &&
                    !snapshot.capabilities.checkpoint_apply &&
                    !snapshot.capabilities.checkpoint_delete ? (
                    <p>{copy.unsupported}</p>
                  ) : null}
                  {confirmation ? (
                    <section
                      className="hyperv-management-dialog__confirmation"
                      aria-label={
                        confirmation.operation === "checkpoint_delete"
                          ? copy.checkpoints.deleteTitle
                          : copy.checkpoints.applyTitle
                      }
                    >
                      <h4>
                        {confirmation.operation === "checkpoint_delete"
                          ? copy.checkpoints.deleteTitle
                          : copy.checkpoints.applyTitle}
                      </h4>
                      <p className="hyperv-stop-warning">
                        {confirmation.operation === "checkpoint_delete"
                          ? copy.checkpoints.deleteWarning
                          : copy.checkpoints.applyWarning}
                      </p>
                      <p>
                        <strong>{confirmation.vmName}</strong> ·{" "}
                        {confirmation.checkpoint.name}
                      </p>
                      {confirmation.operation === "checkpoint_delete" ? (
                        <>
                          <ul>
                            {confirmation.affected.map((item) => (
                              <li key={item.id}>
                                <strong>{item.name}</strong>
                                <br />
                                <code>{item.id}</code>
                              </li>
                            ))}
                          </ul>
                          <label>
                            <input
                              type="checkbox"
                              checked={acknowledged}
                              disabled={submitting}
                              onChange={(event) =>
                                setAcknowledged(event.target.checked)
                              }
                            />{" "}
                            {copy.checkpoints.acknowledge}
                          </label>
                        </>
                      ) : (
                        <>
                          <label>
                            {copy.checkpoints.confirmVm}
                            <input
                              value={vmConfirmation}
                              maxLength={256}
                              autoComplete="off"
                              disabled={submitting}
                              onChange={(event) =>
                                setVmConfirmation(event.target.value)
                              }
                            />
                          </label>
                          <label>
                            {copy.checkpoints.confirmCheckpoint}
                            <input
                              value={checkpointConfirmation}
                              maxLength={256}
                              autoComplete="off"
                              disabled={submitting}
                              onChange={(event) =>
                                setCheckpointConfirmation(event.target.value)
                              }
                            />
                          </label>
                        </>
                      )}
                      <div className="hyperv-management-dialog__toolbar">
                        <button
                          className="outline-button"
                          type="button"
                          disabled={submitting}
                          onClick={() => setConfirmation(null)}
                        >
                          {copy.cancel}
                        </button>
                        <button
                          className="danger-button"
                          type="button"
                          disabled={!confirmationAllowed || submitting}
                          onClick={confirmMutation}
                        >
                          {confirmation.operation === "checkpoint_delete"
                            ? copy.checkpoints.remove
                            : copy.checkpoints.apply}
                        </button>
                      </div>
                    </section>
                  ) : null}
                  {snapshot && !checkpointCollection ? (
                    <p>{copy.unavailable}</p>
                  ) : snapshot && snapshot.checkpoints.length === 0 ? (
                    <p>{copy.checkpoints.empty}</p>
                  ) : snapshot ? (
                    <CheckpointTree
                      checkpoints={snapshot.checkpoints}
                      selectedId={selectedId}
                      copy={copy}
                      onSelect={(item) => {
                        setSelectedId(item.id);
                        setConfirmation(null);
                      }}
                    />
                  ) : null}
                  {selected ? (
                    <dl className="hyperv-management-dialog__details">
                      <div>
                        <dt>{copy.checkpoints.name}</dt>
                        <dd>{selected.name}</dd>
                      </div>
                      <div>
                        <dt>{copy.checkpoints.id}</dt>
                        <dd>
                          <code>{selected.id}</code>
                        </dd>
                      </div>
                      <div>
                        <dt>{copy.checkpoints.parent}</dt>
                        <dd>{selected.parent_id ?? "—"}</dd>
                      </div>
                      <div>
                        <dt>{copy.checkpoints.created}</dt>
                        <dd>{timestamp(selected.created_at, copy.unknown)}</dd>
                      </div>
                      <div>
                        <dt>{copy.checkpoints.type}</dt>
                        <dd>{copy.checkpoints.types[selected.type]}</dd>
                      </div>
                      <div>
                        <dt>{copy.checkpoints.current}</dt>
                        <dd>{selected.is_current ? copy.yes : copy.no}</dd>
                      </div>
                    </dl>
                  ) : snapshot?.checkpoints.length ? (
                    <p>{copy.checkpoints.select}</p>
                  ) : null}
                </>
              )}
            </>
          )}
        </div>
      </div>
      <footer className="hyperv-management-dialog__footer">
        {settingsEditable ? (
          <>
            <p className="hyperv-management-dialog__footer-hint">
              {dirtySections[settingsPage as SettingsSection]
                ? copy.unsaved
                : copy.applyHint}
            </p>
            <button
              className="primary-button"
              type="submit"
              form={`${settingsFormId}-${settingsPage}`}
              disabled={
                !settingsEnabled() ||
                !dirtySections[settingsPage as SettingsSection]
              }
            >
              {copy.applySettings}
            </button>
          </>
        ) : null}
        <button className="outline-button" type="button" onClick={onClose}>
          {copy.close}
        </button>
      </footer>
    </dialog>
  );
}
