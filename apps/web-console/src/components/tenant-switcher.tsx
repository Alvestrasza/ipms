"use client";

import { Building2, ChevronDown } from "lucide-react";
import { useState } from "react";

const previewTenants = ["A-Corp Development", "Research Lab"];

export function TenantSwitcher() {
  const [tenant, setTenant] = useState(previewTenants[0]);

  return (
    <label className="tenant-switcher">
      <span className="sr-only">Active tenant</span>
      <Building2 aria-hidden="true" size={17} />
      <select
        value={tenant}
        onChange={(event) => setTenant(event.target.value)}
      >
        {previewTenants.map((option) => (
          <option key={option}>{option}</option>
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
