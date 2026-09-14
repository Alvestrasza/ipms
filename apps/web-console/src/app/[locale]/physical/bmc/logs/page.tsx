/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Present BMC history under Logs and preserve compatible query navigation.
 */
import type { Route } from "next";
import { redirect } from "next/navigation";
import { resolveLocale } from "@/i18n/server";
import { type LogSearchParams, preservedLogQuery } from "@/lib/job-log-types";

export default async function LegacyBmcLogsPage({
  searchParams,
}: {
  searchParams: Promise<LogSearchParams>;
}) {
  const locale = await resolveLocale();
  const query = preservedLogQuery(await searchParams);
  redirect(
    `/${locale}/logs/bmc/communication${query ? `?${query}` : ""}` as Route,
  );
}
