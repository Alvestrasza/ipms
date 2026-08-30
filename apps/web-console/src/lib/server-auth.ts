import "server-only";

import { cookies } from "next/headers";

import type { IpmsSession } from "./auth-types";

const CONTROL_PLANE_URL = (
  process.env.IPMS_CONTROL_PLANE_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

export async function getServerSession(): Promise<IpmsSession | null> {
  const cookieStore = await cookies();
  try {
    const response = await fetch(`${CONTROL_PLANE_URL}/api/v1/auth/session/`, {
      cache: "no-store",
      headers: { cookie: cookieStore.toString() },
    });
    if (!response.ok) {
      return null;
    }
    return (await response.json()) as IpmsSession;
  } catch {
    return null;
  }
}
