import { cookies } from "next/headers";
import type { NextRequest } from "next/server";
import { isTrustedPortalOrigin } from "@/lib/portal-origin";
import { TENANT_COOKIE } from "@/lib/tenant-selection";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function POST(request: NextRequest) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const origin = request.headers.get("origin");
  if (!isTrustedPortalOrigin(origin, process.env.IPMS_PUBLIC_ORIGIN)) {
    return Response.json({ error: "forbidden" }, { status: 403 });
  }

  let tenantId = "";
  try {
    const body = (await request.json()) as { tenantId?: unknown };
    if (typeof body.tenantId === "string") tenantId = body.tenantId;
  } catch {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  if (!UUID_PATTERN.test(tenantId)) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const cookieStore = await cookies();
  cookieStore.set(TENANT_COOKIE, tenantId, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  });
  return new Response(null, { status: 204 });
}
