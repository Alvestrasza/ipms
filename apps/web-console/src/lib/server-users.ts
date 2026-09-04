import "server-only";

import { cookies } from "next/headers";

import type { TenantRole } from "./auth-types";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export type ManagedTenantUser = {
  membership_id: string;
  username: string;
  display_name: string;
  email: string;
  role: TenantRole;
  is_active: boolean;
  membership_active: boolean;
  expires_at: string | null;
  last_login: string | null;
  authentication_source: "local" | "oidc" | "hybrid";
  manageable: boolean;
};

export async function getManagedTenantUsers(tenantId: string) {
  const cookie = (await cookies()).toString();
  const headers = controlPlaneHeaders({ cookie, "X-IPMS-Tenant-ID": tenantId });
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}/api/v1/auth/users/`, {
      cache: "no-store",
      headers,
    });
    return {
      sessionValid: ![401, 403].includes(response.status),
      available: response.ok,
      users: response.ok
        ? ((await response.json()) as ManagedTenantUser[])
        : [],
    };
  } catch {
    return { sessionValid: true, available: false, users: [] };
  }
}
