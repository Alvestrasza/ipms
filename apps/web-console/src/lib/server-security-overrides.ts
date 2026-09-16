/**
 * File Name: server-security-overrides.ts
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Load authorized tenant override configuration without exposing credentials.
 */
import "server-only";
import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import { isOverrideList } from "./security-override-types";
export async function getSecurityOverrides(tenantId: string) {
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/security/overrides/`,
      {
        cache: "no-store",
        headers: controlPlaneHeaders({
          cookie: (await cookies()).toString(),
          "X-IPMS-Tenant-ID": tenantId,
        }),
        signal: AbortSignal.timeout(15000),
      },
    );
    const payload: unknown = response.ok ? await response.json() : null;
    return {
      data: isOverrideList(payload) ? payload.results : null,
      status: response.status,
    };
  } catch {
    return { data: null, status: 503 };
  }
}
