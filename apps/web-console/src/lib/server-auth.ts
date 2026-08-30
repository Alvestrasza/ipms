import "server-only";

import { cookies } from "next/headers";

import type { IpmsSession } from "./auth-types";
import {
  CONTROL_PLANE_URL,
  controlPlaneHeaders,
} from "./control-plane-request";

export async function getServerSession(): Promise<IpmsSession | null> {
  const cookieStore = await cookies();
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}/api/v1/auth/session/`, {
      cache: "no-store",
      headers: controlPlaneHeaders({ cookie: cookieStore.toString() }),
    });
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as IpmsSession;
  } catch {
    return null;
  }
}
