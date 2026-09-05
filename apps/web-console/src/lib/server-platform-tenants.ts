import "server-only";
import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import type { PlatformTenant } from "./platform-tenant-types";

export async function getPlatformTenants() {
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/platform/tenants/`,
      {
        cache: "no-store",
        headers: controlPlaneHeaders({ cookie: (await cookies()).toString() }),
        signal: AbortSignal.timeout(15_000),
      },
    );
    if (!response.ok)
      return {
        sessionValid: response.status !== 401,
        available: false,
        tenants: [] as PlatformTenant[],
      };
    const body = await response.json();
    if (!Array.isArray(body.results)) throw new Error();
    return {
      sessionValid: true,
      available: true,
      tenants: body.results as PlatformTenant[],
    };
  } catch {
    return {
      sessionValid: true,
      available: false,
      tenants: [] as PlatformTenant[],
    };
  }
}
