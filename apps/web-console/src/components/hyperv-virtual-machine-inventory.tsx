"use client";

import {
  Boxes,
  CirclePause,
  CirclePlay,
  Cpu,
  MemoryStick,
  Play,
  Power,
  PowerOff,
  Square,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { DialogPortal } from "@/components/dialog-portal";
import { StatusPill } from "@/components/status-pill";
import type {
  HyperVAction,
  HyperVActionJob,
  HyperVVirtualMachine,
} from "@/lib/hyperv-types";

type Copy = {
  summary: string;
  total: string;
  running: string;
  stopped: string;
  assignedMemory: string;
  inventory: string;
  tableHeading: string;
  name: string;
  state: string;
  host: string;
  vcpu: string;
  memory: string;
  uptime: string;
  configurationVersion: string;
  ipAddresses: string;
  noVirtualMachines: string;
  noVirtualMachinesHint: string;
  contextHint: string;
  actionMenu: string;
  actions: Record<HyperVAction, string>;
  confirmTitle: string;
  confirmBody: string;
  stopWarning: string;
  cancel: string;
  confirm: string;
  queued: string;
  actionFailed: string;
  states: Record<string, string>;
};

type Menu = { vm: HyperVVirtualMachine; x: number; y: number };
type ActionRequest = { vm: HyperVVirtualMachine; action: HyperVAction };
type StopConfirmation = { vm: HyperVVirtualMachine; action: "stop" };
const wait = (milliseconds: number) =>
  new Promise((resolve) => window.setTimeout(resolve, milliseconds));

function availableActions(vm: HyperVVirtualMachine): HyperVAction[] {
  if (vm.state === "running") return ["pause", "shutdown", "stop"];
  if (vm.state === "paused") return ["resume", "stop"];
  if (vm.state === "stopped") return ["start"];
  return [];
}

function actionIcon(action: HyperVAction) {
  if (action === "pause") return <CirclePause aria-hidden="true" size={16} />;
  if (action === "shutdown") return <PowerOff aria-hidden="true" size={16} />;
  if (action === "stop") return <Square aria-hidden="true" size={16} />;
  return <CirclePlay aria-hidden="true" size={16} />;
}

function formatMemory(bytes: number | null) {
  return bytes === null ? "—" : `${Math.round(bytes / 1024 ** 3)} GiB`;
}

function formatUptime(seconds: number | null) {
  if (seconds === null) return "—";
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  const minutes = Math.floor((seconds % 3_600) / 60);
  return [days ? `${days}d` : "", hours ? `${hours}h` : "", `${minutes}m`]
    .filter(Boolean)
    .join(" ");
}

function stateStatus(state: HyperVVirtualMachine["state"]) {
  if (state === "running") return "healthy" as const;
  if (state === "stopped" || state === "offline") return "unknown" as const;
  if (state === "unknown") return "warning" as const;
  return "running" as const;
}

export function HyperVVirtualMachineInventory({
  copy,
  virtualMachines,
  csrfToken,
  tenantId,
  canManage,
}: {
  copy: Copy;
  virtualMachines: HyperVVirtualMachine[];
  csrfToken: string;
  tenantId: string;
  canManage: boolean;
}) {
  const router = useRouter();
  const [menu, setMenu] = useState<Menu | null>(null);
  const [pending, setPending] = useState<StopConfirmation | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const close = () => setMenu(null);
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("click", close);
    window.addEventListener("keydown", handleEscape);
    window.addEventListener("resize", close);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("keydown", handleEscape);
      window.removeEventListener("resize", close);
    };
  }, []);

  const running = virtualMachines.filter((vm) => vm.state === "running").length;
  const stopped = virtualMachines.filter((vm) => vm.state === "stopped").length;
  const memory = virtualMachines.reduce(
    (total, vm) => total + (vm.memory_bytes ?? 0),
    0,
  );

  function openMenu(vm: HyperVVirtualMachine, x: number, y: number) {
    if (busy || !canManage || availableActions(vm).length === 0) return;
    setMenu({
      vm,
      x: Math.max(8, Math.min(x, window.innerWidth - 220)),
      y: Math.max(8, Math.min(y, window.innerHeight - 190)),
    });
  }

  async function runAction(request: ActionRequest) {
    setBusy(true);
    setError("");
    setMessage(copy.queued);
    try {
      const response = await fetch(
        `/api/v1/hyper-v/virtual-machines/${request.vm.id}/actions/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({ action: request.action }),
        },
      );
      if (!response.ok) throw new Error("queue_failed");
      let job = (await response.json()) as HyperVActionJob;
      for (
        let attempt = 0;
        attempt < 210 &&
        !["succeeded", "failed", "cancelled"].includes(job.status);
        attempt += 1
      ) {
        await wait(1_000);
        const statusResponse = await fetch(
          `/api/v1/hyper-v/actions/${job.id}/`,
          {
            cache: "no-store",
            credentials: "same-origin",
            headers: { "X-IPMS-Tenant-ID": tenantId },
          },
        );
        if (!statusResponse.ok) throw new Error("status_failed");
        job = (await statusResponse.json()) as HyperVActionJob;
      }
      if (job.status !== "succeeded")
        throw new Error(job.result_code || "action_failed");
      setPending(null);
      setMessage("");
      router.refresh();
    } catch (caught) {
      const code = caught instanceof Error ? caught.message : "action_failed";
      setError(copy.actionFailed.replace("{code}", code));
      setMessage("");
    } finally {
      setBusy(false);
    }
  }

  function requestAction(vm: HyperVVirtualMachine, action: HyperVAction) {
    setMenu(null);
    setError("");
    setMessage("");
    if (action === "stop") {
      setPending({ vm, action });
      return;
    }
    void runAction({ vm, action });
  }

  return (
    <>
      <section className="summary-grid" aria-label={copy.summary}>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Boxes aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.total}</p>
            <strong>{virtualMachines.length}</strong>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Play aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.running}</p>
            <strong>{running}</strong>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <Power aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.stopped}</p>
            <strong>{stopped}</strong>
          </div>
        </article>
        <article className="summary-card">
          <div className="summary-card__icon">
            <MemoryStick aria-hidden="true" size={21} />
          </div>
          <div>
            <p>{copy.assignedMemory}</p>
            <strong>{formatMemory(memory || null)}</strong>
          </div>
        </article>
      </section>
      <section
        className="panel inventory-panel"
        aria-labelledby="hyperv-vm-inventory-heading"
      >
        <div className="panel__header">
          <div>
            <p className="eyebrow">{copy.inventory}</p>
            <h2 id="hyperv-vm-inventory-heading">{copy.tableHeading}</h2>
          </div>
          <span className="panel__metric">
            <strong>{virtualMachines.length}</strong>
          </span>
        </div>
        {canManage && virtualMachines.length > 0 ? (
          <p className="hyperv-context-hint">{copy.contextHint}</p>
        ) : null}
        {error && !pending ? (
          <p className="form-error hyperv-action-message" role="alert">
            {error}
          </p>
        ) : null}
        {message && !pending ? (
          <p className="hyperv-action-progress" role="status">
            {message}
          </p>
        ) : null}
        {virtualMachines.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>{copy.name}</th>
                  <th>{copy.state}</th>
                  <th>{copy.host}</th>
                  <th>{copy.vcpu}</th>
                  <th>{copy.memory}</th>
                  <th>{copy.uptime}</th>
                  <th>{copy.configurationVersion}</th>
                  <th>{copy.ipAddresses}</th>
                </tr>
              </thead>
              <tbody>
                {virtualMachines.map((vm) => (
                  <tr
                    key={vm.id}
                    className={
                      canManage && availableActions(vm).length
                        ? "hyperv-vm-row--actionable"
                        : undefined
                    }
                    tabIndex={
                      canManage && availableActions(vm).length ? 0 : undefined
                    }
                    onContextMenu={(event) => {
                      if (canManage && availableActions(vm).length) {
                        event.preventDefault();
                        openMenu(vm, event.clientX, event.clientY);
                      }
                    }}
                    onKeyDown={(event) => {
                      if (
                        event.key === "ContextMenu" ||
                        (event.shiftKey && event.key === "F10")
                      ) {
                        event.preventDefault();
                        const bounds =
                          event.currentTarget.getBoundingClientRect();
                        openMenu(vm, bounds.left + 48, bounds.top + 32);
                      }
                    }}
                  >
                    <td>
                      <strong>{vm.name}</strong>
                    </td>
                    <td>
                      <StatusPill
                        status={stateStatus(vm.state)}
                        label={copy.states[vm.state] ?? vm.state}
                      />
                    </td>
                    <td>{vm.host_fqdn || vm.host_hostname}</td>
                    <td>{vm.vcpu_count ?? "—"}</td>
                    <td>{formatMemory(vm.memory_bytes)}</td>
                    <td>{formatUptime(vm.uptime_seconds)}</td>
                    <td>{vm.configuration_version || "—"}</td>
                    <td>
                      {vm.ip_addresses.length
                        ? vm.ip_addresses.join(", ")
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <Cpu aria-hidden="true" size={25} />
            <strong>{copy.noVirtualMachines}</strong>
            <span>{copy.noVirtualMachinesHint}</span>
          </div>
        )}
      </section>
      {menu ? (
        <div
          className="hyperv-context-menu"
          role="menu"
          aria-label={copy.actionMenu}
          style={{ left: menu.x, top: menu.y }}
        >
          <strong>{menu.vm.name}</strong>
          {availableActions(menu.vm).map((action) => (
            <button
              key={action}
              type="button"
              role="menuitem"
              className={
                action === "stop" ? "hyperv-context-menu__danger" : undefined
              }
              disabled={busy}
              onClick={() => requestAction(menu.vm, action)}
            >
              {actionIcon(action)}
              <span>{copy.actions[action]}</span>
            </button>
          ))}
        </div>
      ) : null}
      {pending ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section
              className="modal-card"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="hyperv-action-heading"
            >
              <div className="modal-card__heading modal-card__heading--danger">
                <h3 id="hyperv-action-heading">{copy.confirmTitle}</h3>
                <button
                  className="icon-button"
                  type="button"
                  aria-label={copy.cancel}
                  disabled={busy}
                  onClick={() => setPending(null)}
                >
                  <X aria-hidden="true" size={17} />
                </button>
              </div>
              <p>
                {copy.confirmBody
                  .replace("{action}", copy.actions[pending.action])
                  .replace("{name}", pending.vm.name)}
              </p>
              <p className="hyperv-stop-warning">{copy.stopWarning}</p>
              {message ? (
                <p className="hyperv-action-progress" role="status">
                  {message}
                </p>
              ) : null}
              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  className="outline-button"
                  type="button"
                  disabled={busy}
                  onClick={() => setPending(null)}
                >
                  {copy.cancel}
                </button>
                <button
                  className="danger-button"
                  type="button"
                  disabled={busy}
                  onClick={() => void runAction(pending)}
                >
                  {copy.confirm}
                </button>
              </div>
            </section>
          </div>
        </DialogPortal>
      ) : null}
    </>
  );
}
