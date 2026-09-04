import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import type { HyperVVirtualMachine } from "./hyperv-types";

export type { HyperVVirtualMachine } from "./hyperv-types";

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
