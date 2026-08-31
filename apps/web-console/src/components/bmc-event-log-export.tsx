"use client";

import { Download, LoaderCircle } from "lucide-react";
import { useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";

export function BmcEventLogExport({
  tenantId,
  queryString,
  copy,
}: {
  tenantId: string;
  queryString: string;
  copy: Dictionary["bmcEvents"];
}) {
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");

  async function exportCsv() {
    setExporting(true);
    setError("");
    try {
      const suffix = queryString ? `?${queryString}` : "";
      const response = await fetch(`/api/v1/bmc-event-logs/export/${suffix}`, {
        credentials: "same-origin",
        headers: { "X-IPMS-Tenant-ID": tenantId },
      });
      if (!response.ok) {
        setError(copy.exportError);
        return;
      }
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = "ipms-bmc-event-logs.csv";
      link.click();
      URL.revokeObjectURL(url);
    } catch {
      setError(copy.exportError);
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="log-export">
      <button
        className="outline-button"
        type="button"
        onClick={exportCsv}
        disabled={exporting}
      >
        {exporting ? (
          <LoaderCircle className="spin" aria-hidden="true" size={15} />
        ) : (
          <Download aria-hidden="true" size={15} />
        )}
        {exporting ? copy.exporting : copy.exportCsv}
      </button>
      {error ? (
        <span className="form-error" role="alert">
          {error}
        </span>
      ) : null}
    </div>
  );
}
