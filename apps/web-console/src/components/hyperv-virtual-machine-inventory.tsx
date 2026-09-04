import { Boxes, Cpu, MemoryStick, Play, Power } from "lucide-react";

import { StatusPill } from "@/components/status-pill";
import type { HyperVVirtualMachine } from "@/lib/server-hyperv";

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
  states: Record<string, string>;
};

function formatMemory(bytes: number | null) {
  if (bytes === null) return "—";
  return `${Math.round(bytes / 1024 ** 3)} GiB`;
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
}: {
  copy: Copy;
  virtualMachines: HyperVVirtualMachine[];
}) {
  const running = virtualMachines.filter((vm) => vm.state === "running").length;
  const stopped = virtualMachines.filter((vm) => vm.state === "stopped").length;
  const memory = virtualMachines.reduce(
    (total, vm) => total + (vm.memory_bytes ?? 0),
    0,
  );
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
                  <tr key={vm.id}>
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
    </>
  );
}
