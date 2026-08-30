import { cookies } from "next/headers";
import type { NextRequest } from "next/server";

import { isLocale, LOCALE_COOKIE } from "@/i18n/config";

function requestOrigin(request: NextRequest) {
  const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0];
  const forwardedProtocol = request.headers
    .get("x-forwarded-proto")
    ?.split(",")[0];
  const host = forwardedHost?.trim() || request.headers.get("host");
  const protocol =
    forwardedProtocol?.trim() || request.nextUrl.protocol.replace(":", "");
  return host ? `${protocol}://${host}` : request.nextUrl.origin;
}

export async function POST(request: NextRequest) {
  if (!request.headers.get("content-type")?.startsWith("application/json")) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const origin = request.headers.get("origin");
  if (origin && origin !== requestOrigin(request)) {
    return Response.json({ error: "forbidden" }, { status: 403 });
  }

  let locale: unknown;
  try {
    ({ locale } = (await request.json()) as { locale?: unknown });
  } catch {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  if (!isLocale(locale)) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const cookieStore = await cookies();
  cookieStore.set(LOCALE_COOKIE, locale.toLowerCase(), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  return new Response(null, { status: 204 });
}
