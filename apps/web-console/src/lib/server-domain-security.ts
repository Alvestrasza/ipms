/**
 * File Name: server-domain-security.ts
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Load domain administration through the authenticated tenant API.
 */
import "server-only";
import { cookies } from "next/headers";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";
import { isDomainSecurityCatalog } from "./domain-security-validation";

export async function getDomainSecuritySettings(tenantId: string) {
  try {
    const response = await fetch(
      `${CONTROL_PLANE_URL}/api/v1/security/domain-settings/`,
      {
        cache: "no-store",
        headers: controlPlaneHeaders({
          cookie: (await cookies()).toString(),
          "X-IPMS-Tenant-ID": tenantId,
        }),
        signal: AbortSignal.timeout(15_000),
      },
    );
    const payload: unknown = response.ok ? await response.json() : null;
    return {
      data: isDomainSecurityCatalog(payload) ? payload : null,
      sessionValid: response.status !== 401,
      forbidden: response.status === 403,
    };
  } catch {
    return { data: null, sessionValid: true, forbidden: false };
  }
}
