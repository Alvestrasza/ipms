/**
 * File Name: server-collections.ts
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Load tenant collection state through the authenticated control plane.
 */
import "server-only";
import { cookies } from "next/headers";
import {
  isDeviceCollectionCatalog,
  isPolicyCollectionCatalog,
} from "./collection-types";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

async function read<T>(
  tenantId: string,
  path: string,
  validate: (value: unknown) => value is T,
) {
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}${path}`, {
      cache: "no-store",
      headers: controlPlaneHeaders({
        cookie: (await cookies()).toString(),
        "X-IPMS-Tenant-ID": tenantId,
      }),
      signal: AbortSignal.timeout(15_000),
    });
    const payload: unknown = response.ok ? await response.json() : null;
    return {
      data: validate(payload) ? payload : null,
      sessionValid: response.status !== 401,
      forbidden: response.status === 403,
    };
  } catch {
    return { data: null, sessionValid: true, forbidden: false };
  }
}

export const getDeviceCollections = (tenantId: string) =>
  read(
    tenantId,
    "/api/v1/security/device-collections/",
    isDeviceCollectionCatalog,
  );
export const getPolicyCollections = (tenantId: string) =>
  read(
    tenantId,
    "/api/v1/security/policy-collections/",
    isPolicyCollectionCatalog,
  );
