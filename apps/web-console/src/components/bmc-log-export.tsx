/**
 * File Name: bmc-log-export.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Export BMC metadata with shared bounded-log feedback.
 */
import type { Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import { getJobLogsCopy } from "@/i18n/job-logs-copy";
import { LogsExport } from "./logs-export";

export function BmcLogExport({
  tenantId,
  queryString,
  copy,
  locale,
  disabled,
}: {
  tenantId: string;
  queryString: string;
  copy: Dictionary["bmcLogs"];
  locale: Locale;
  disabled?: boolean;
}) {
  return (
    <LogsExport
      key={`${tenantId}:${queryString}`}
      tenantId={tenantId}
      queryString={queryString}
      scope="bmc-communication"
      disabled={disabled}
      copy={{
        ...getJobLogsCopy(locale),
        exportCsv: copy.exportCsv,
        exporting: copy.exporting,
        exportError: copy.exportError,
      }}
    />
  );
}
