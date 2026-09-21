/**
 * File Name: server-hgs.ts
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Read validated HGS plans in the authenticated tenant scope.
 */
import "server-only";
import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import { isHgsOverview } from "./hgs-types";

export async function getHgsOverview(tenantId: string) {
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}/api/v1/hgs/`, {
      cache: "no-store",
      headers: controlPlaneHeaders({
        cookie: (await cookies()).toString(),
        "X-IPMS-Tenant-ID": tenantId,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const payload: unknown = response.ok ? await response.json() : null;
    return {
      data: isHgsOverview(payload, tenantId) ? payload : null,
      sessionValid: response.status !== 401,
      forbidden: response.status === 403,
    };
  } catch {
    return { data: null, sessionValid: true, forbidden: false };
  }
}
