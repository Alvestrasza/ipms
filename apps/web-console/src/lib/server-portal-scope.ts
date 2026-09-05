import "server-only";
import { redirect } from "next/navigation";
import type { Locale } from "@/i18n/config";
import {
  type AuthenticatedSession,
  type IpmsSession,
  portalScope,
} from "./auth-types";

/** Always run before starting any tenant inventory or administration fetch. */
export function requireTenantScope(
  session: IpmsSession | null,
  locale: Locale,
): asserts session is AuthenticatedSession {
  const scope = portalScope(session);
  if (scope === "anonymous") redirect(`/${locale}/login`);
  if (scope === "platform") redirect(`/${locale}/administration/tenants`);
  if (scope === "no-tenant") redirect(`/${locale}/access-unavailable`);
}
