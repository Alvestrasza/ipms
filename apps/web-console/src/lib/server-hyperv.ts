import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type HyperVVirtualMachine = {
  id: string;
  tenant_id: string;
  host_id: string;
  host_fqdn: string;
  host_hostname: string;
  source_id: string;
  name: string;
  state:
    | "running"
    | "stopped"
    | "starting"
    | "stopping"
    | "paused"
    | "pausing"
    | "suspended"
    | "saving"
    | "resuming"
    | "quiesced"
    | "offline"
    | "unknown";
  vcpu_count: number | null;
  memory_bytes: number | null;
  uptime_seconds: number | null;
  configuration_version: string;
  ip_addresses: string[];
  observed_at: string;
};

export async function getHyperVVirtualMachines(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/hyper-v/virtual-machines/`,
      { cache: "no-store", headers },
    );
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      virtualMachines: response.ok
        ? ((await response.json()) as HyperVVirtualMachine[])
        : [],
    };
  } catch {
    return { sessionValid: true, available: false, virtualMachines: [] };
  }
}
