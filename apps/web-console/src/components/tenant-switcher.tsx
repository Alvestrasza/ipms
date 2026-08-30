"use client";

import { Building2, ChevronDown } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { useLocale } from "@/i18n/locale-provider";
import type { TenantSummary } from "@/lib/auth-types";

export function TenantSwitcher({
  tenants,
  selectedTenantId,
}: {
  tenants: TenantSummary[];
  selectedTenantId: string;
}) {
  const router = useRouter();
  const { dictionary } = useLocale();
  const [tenantId, setTenantId] = useState(selectedTenantId);

  async function selectTenant(value: string) {
    setTenantId(value);
    try {
      const response = await fetch("/api/tenant-selection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenantId: value }),
      });
      if (!response.ok) {
        setTenantId(selectedTenantId);
        return;
      }
      router.refresh();
    } catch {
      setTenantId(selectedTenantId);
    }
  }

  return (
    <label className="tenant-switcher">
      <span className="sr-only">{dictionary.shell.activeTenant}</span>
      <Building2 aria-hidden="true" size={17} />
      <select
        value={tenantId}
        onChange={(event) => void selectTenant(event.target.value)}
        disabled={tenants.length < 2}
      >
        {tenants.map((tenant) => (
          <option key={tenant.id} value={tenant.id}>
            {tenant.display_name}
          </option>
        ))}
      </select>
      <ChevronDown
        className="tenant-switcher__chevron"
        aria-hidden="true"
        size={15}
      />
    </label>
  );
}
