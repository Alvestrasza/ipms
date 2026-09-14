/**
 * File Name: page.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Expose the tenant Agent operation history.
 */
import type { Metadata } from "next";
import { LogsPage } from "@/components/logs-page";
import { getJobLogsCopy } from "@/i18n/job-logs-copy";
import { resolveLocale } from "@/i18n/server";
import type { LogSearchParams } from "@/lib/job-log-types";
export async function generateMetadata(): Promise<Metadata> {
  return { title: getJobLogsCopy(await resolveLocale()).agentsTitle };
}
export default function AgentLogsPage({
  searchParams,
}: {
  searchParams: Promise<LogSearchParams>;
}) {
  return <LogsPage scope="agents" searchParams={searchParams} />;
}
