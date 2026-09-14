/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Expose baseline scan and pilot-import history without mutation controls.
 */
import type { Metadata } from "next";
import { LogsPage } from "@/components/logs-page";
import { getJobLogsCopy } from "@/i18n/job-logs-copy";
import { resolveLocale } from "@/i18n/server";
import type { LogSearchParams } from "@/lib/job-log-types";
export async function generateMetadata(): Promise<Metadata> {
  return { title: getJobLogsCopy(await resolveLocale()).baselinesTitle };
}
export default function BaselineLogsPage({
  searchParams,
}: {
  searchParams: Promise<LogSearchParams>;
}) {
  return <LogsPage scope="baselines" searchParams={searchParams} />;
}
