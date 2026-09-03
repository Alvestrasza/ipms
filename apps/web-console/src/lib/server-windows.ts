import "server-only";

import { cookies } from "next/headers";

import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import type {
  WindowsServer,
  WindowsServerRoleSummary,
} from "./windows-server-types";

export type { WindowsServer } from "./windows-server-types";

export async function getWindowsServers(
  tenantId: string,
  serverType: "physical" | "virtual",
  role?: string,
) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  const query = new URLSearchParams({ server_type: serverType });
  if (role) query.set("role", role);
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/windows-servers/?${query}`,
      { cache: "no-store", headers },
    );
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      servers: response.ok ? ((await response.json()) as WindowsServer[]) : [],
    };
  } catch {
    return { sessionValid: true, available: false, servers: [] };
  }
}

export async function getWindowsServerRoles(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/windows-server-roles/`,
      { cache: "no-store", headers },
    );
    return response.ok
      ? ((await response.json()) as WindowsServerRoleSummary[])
      : [];
  } catch {
    return [];
  }
}

export async function getWindowsServer(tenantId: string, id: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/windows-servers/${encodeURIComponent(id)}/`,
      { cache: "no-store", headers },
    );
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      notFound: response.status === 404,
      server: response.ok ? ((await response.json()) as WindowsServer) : null,
    };
  } catch {
    return {
      sessionValid: true,
      available: false,
      notFound: false,
      server: null,
    };
  }
}
