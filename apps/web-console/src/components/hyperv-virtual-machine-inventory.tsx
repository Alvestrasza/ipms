"use client";

import {
  Boxes,
  Camera,
  ChevronRight,
  CirclePause,
  CirclePlay,
  Cpu,
  MemoryStick,
  MonitorUp,
  MoreHorizontal,
  Play,
  Power,
  PowerOff,
  Settings,
  Square,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { DialogPortal } from "@/components/dialog-portal";
import type { ConsoleCopy } from "@/components/hyperv-console-dialog";
import { HyperVManagementDialog } from "@/components/hyperv-management-dialog";
import { StatusPill } from "@/components/status-pill";
import { getHyperVManagementCopy } from "@/i18n/hyperv-management-copy";
import { useLocale } from "@/i18n/locale-provider";
import type { ManagementSection } from "@/lib/hyperv-management-types";
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
  console: ConsoleCopy & { open: string; popupBlocked: string };
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
  canConsole,
  canManageCheckpoints,
  canConfigure,
}: {
  copy: Copy;
  virtualMachines: HyperVVirtualMachine[];
  csrfToken: string;
  tenantId: string;
  canManage: boolean;
  canConsole: boolean;
  canManageCheckpoints: boolean;
  canConfigure: boolean;
}) {
  const router = useRouter();
  const { locale } = useLocale();
  const managementCopy = getHyperVManagementCopy(locale);
  const menuElement = useRef<HTMLDivElement>(null);
  const menuOpener = useRef<HTMLElement | null>(null);
  const [menu, setMenu] = useState<Menu | null>(null);
  const [management, setManagement] = useState<{
    vm: HyperVVirtualMachine;
    section: ManagementSection;
  } | null>(null);
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

  useEffect(() => {
    if (menu)
      menuElement.current
        ?.querySelector<HTMLButtonElement>("button:not(:disabled)")
        ?.focus();
  }, [menu]);

  const running = virtualMachines.filter((vm) => vm.state === "running").length;
  const stopped = virtualMachines.filter((vm) => vm.state === "stopped").length;
  const memory = virtualMachines.reduce(
    (total, vm) => total + (vm.memory_bytes ?? 0),
    0,
  );

  function openMenu(vm: HyperVVirtualMachine, x: number, y: number) {
    menuOpener.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    setMenu({
      vm,
      x: Math.max(8, Math.min(x, window.innerWidth - 220)),
      y: Math.max(8, Math.min(y, window.innerHeight - 420)),
    });
  }

  function openConsole(vm: HyperVVirtualMachine) {
    setMenu(null);
    // Open synchronously from the user gesture so popup blockers can allow it.
    // A named window focuses an existing console without reloading its lease.
    const popup = window.open(
      "",
      `ipms-console-${tenantId}-${vm.id}`,
      "popup=yes,width=1120,height=840,resizable=yes,scrollbars=yes",
    );
    if (!popup) {
      setError(copy.console.popupBlocked);
      return;
    }
    if (popup.location.href === "about:blank") {
      popup.location.replace(
        `/${locale}/virtual/hyper-v/console/${vm.id}?tenant=${encodeURIComponent(tenantId)}`,
      );
    }
    popup.focus();
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
        className="panel inventory-panel hyperv-vm-inventory"
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
        {virtualMachines.length > 0 ? (
          <p className="hyperv-context-hint">{managementCopy.hint}</p>
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
                  <th>
                    <span className="sr-only">{managementCopy.actions}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {virtualMachines.map((vm) => (
                  <tr
                    key={vm.id}
                    className="hyperv-vm-row--actionable"
                    tabIndex={0}
                    onContextMenu={(event) => {
                      event.preventDefault();
                      event.currentTarget.focus();
                      openMenu(vm, event.clientX, event.clientY);
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
                    onDoubleClick={() => {
                      if (canConsole && vm.state === "running") {
                        void openConsole(vm);
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
                    <td>
                      <button
                        className="icon-button"
                        type="button"
                        aria-label={`${managementCopy.actions}: ${vm.name}`}
                        aria-haspopup="menu"
                        aria-expanded={menu?.vm.id === vm.id}
                        onDoubleClick={(event) => event.stopPropagation()}
                        onClick={(event) => {
                          event.stopPropagation();
                          const bounds =
                            event.currentTarget.getBoundingClientRect();
                          openMenu(vm, bounds.right - 220, bounds.bottom + 4);
                        }}
                      >
                        <MoreHorizontal aria-hidden="true" size={18} />
                      </button>
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
          ref={menuElement}
          className="hyperv-context-menu"
          role="menu"
          aria-label={copy.actionMenu}
          style={{ left: menu.x, top: menu.y }}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.preventDefault();
              setMenu(null);
              menuOpener.current?.focus();
              return;
            }
            if (!["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key))
              return;
            event.preventDefault();
            const buttons = [
              ...event.currentTarget.querySelectorAll<HTMLButtonElement>(
                "button:not(:disabled)",
              ),
            ];
            const current =
              document.activeElement instanceof HTMLButtonElement
                ? buttons.indexOf(document.activeElement)
                : -1;
            const next =
              event.key === "Home"
                ? 0
                : event.key === "End"
                  ? buttons.length - 1
                  : (current +
                      (event.key === "ArrowDown" ? 1 : -1) +
                      buttons.length) %
                    buttons.length;
            buttons[next]?.focus();
          }}
        >
          <strong>{menu.vm.name}</strong>
          {(Object.keys(managementCopy.sections) as ManagementSection[]).map(
            (section) => (
              <button
                key={section}
                type="button"
                role="menuitem"
                onClick={() => {
                  setManagement({ vm: menu.vm, section });
                  setMenu(null);
                }}
              >
                {section === "settings" ? (
                  <Settings aria-hidden="true" size={16} />
                ) : section === "checkpoints" ? (
                  <Camera aria-hidden="true" size={16} />
                ) : (
                  <ChevronRight aria-hidden="true" size={16} />
                )}
                <span>{managementCopy.sections[section]}</span>
              </button>
            ),
          )}
          {canConsole && menu.vm.state === "running" ? (
            <button
              type="button"
              role="menuitem"
              disabled={busy}
              onClick={() => void openConsole(menu.vm)}
            >
              <MonitorUp aria-hidden="true" size={16} />
              <span>{copy.console.open}</span>
            </button>
          ) : null}
          {canManage
            ? availableActions(menu.vm).map((action) => (
                <button
                  key={action}
                  type="button"
                  role="menuitem"
                  className={
                    action === "stop"
                      ? "hyperv-context-menu__danger"
                      : undefined
                  }
                  disabled={busy}
                  onClick={() => requestAction(menu.vm, action)}
                >
                  {actionIcon(action)}
                  <span>{copy.actions[action]}</span>
                </button>
              ))
            : null}
        </div>
      ) : null}
      {management ? (
        <HyperVManagementDialog
          key={`${tenantId}:${management.vm.id}`}
          virtualMachine={management.vm}
          initialSection={management.section}
          tenantId={tenantId}
          csrfToken={csrfToken}
          canManageCheckpoints={canManageCheckpoints}
          canConfigure={canConfigure}
          onClose={() => {
            setManagement(null);
            menuOpener.current?.focus();
            router.refresh();
          }}
        />
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
