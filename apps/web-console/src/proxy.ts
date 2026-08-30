import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

import {
  isLocale,
  LOCALE_COOKIE,
  type Locale,
  localeFromAcceptLanguage,
} from "@/i18n/config";

function pathnameLocale(pathname: string): Locale | null {
  const segment = pathname.split("/")[1];
  return isLocale(segment) ? (segment.toLowerCase() as Locale) : null;
}

function preferredLocale(request: NextRequest): Locale {
  const cookieLocale = request.cookies.get(LOCALE_COOKIE)?.value;
  if (isLocale(cookieLocale)) return cookieLocale.toLowerCase() as Locale;
  return localeFromAcceptLanguage(request.headers.get("accept-language"));
}

function applySecurityHeaders(response: NextResponse, policy: string) {
  response.headers.set("Content-Security-Policy", policy);
  response.headers.set("Referrer-Policy", "same-origin");
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  response.headers.set("X-Content-Type-Options", "nosniff");
  return response;
}

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const isDevelopment = process.env.NODE_ENV === "development";
  const policy = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDevelopment ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'${isDevelopment ? " 'unsafe-inline'" : ""}`,
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(isDevelopment ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", policy);

  const { pathname } = request.nextUrl;
  const locale = pathnameLocale(pathname);
  const firstSegment = pathname.split("/")[1];

  if (!locale || firstSegment !== locale) {
    const selectedLocale = locale ?? preferredLocale(request);
    const url = request.nextUrl.clone();
    const pathWithoutLocale = locale
      ? pathname.slice(firstSegment.length + 1)
      : pathname;
    url.pathname =
      pathWithoutLocale === "/"
        ? `/${selectedLocale}`
        : `/${selectedLocale}${pathWithoutLocale}`;
    const redirect = applySecurityHeaders(NextResponse.redirect(url), policy);
    redirect.cookies.set(LOCALE_COOKIE, selectedLocale, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
    redirect.headers.set("Cache-Control", "private, no-store");
    redirect.headers.set("Vary", "Accept-Language, Cookie");
    return redirect;
  }

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.cookies.set(LOCALE_COOKIE, locale, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  response.headers.set("Content-Language", locale);
  return applySecurityHeaders(response, policy);
}

export const config = {
  matcher: [
    {
      source: "/((?!api|_next|.*\\..*).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
