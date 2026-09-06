import "server-only";
import { cookies } from "next/headers";
import type { AccountIdentity } from "./account-security";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export async function getAccountIdentity() {
  const cookie = (await cookies()).toString();
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}/api/v1/auth/account/`, {
      cache: "no-store",
      headers: controlPlaneHeaders({ cookie }),
      signal: AbortSignal.timeout(15_000),
    });
    return {
      sessionValid: response.status !== 401,
      account: response.ok
        ? ((await response.json()) as AccountIdentity)
        : null,
    };
  } catch {
    return { sessionValid: true, account: null };
  }
}
