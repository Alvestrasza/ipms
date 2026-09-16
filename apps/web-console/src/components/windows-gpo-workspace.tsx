/**
 * File Name: windows-gpo-workspace.tsx
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Centralize managed Windows GPO import, link and activation actions.
 */
"use client";
import type { Route } from "next";
import Link from "next/link";
import { useState } from "react";
import type { Locale } from "@/i18n/config";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import { getWindowsGpoCopy } from "@/i18n/windows-gpo-copy";
import type { DomainSecurityCatalog } from "@/lib/domain-security-types";
import type { SecurityOverride } from "@/lib/security-override-types";
import { DomainGpoImports } from "./domain-gpo-imports";
import styles from "./domain-security-administration.module.css";

type Props = {
  catalog: DomainSecurityCatalog | null;
  overrides: SecurityOverride[] | null;
  tenantId: string;
  csrfToken: string;
  locale: Locale;
  preferredBaselineId?: string;
  initialSource?: "baseline" | "override";
};

export function WindowsGpoWorkspace({
  catalog,
  overrides,
  tenantId,
  csrfToken,
  locale,
  preferredBaselineId,
  initialSource = "baseline",
}: Props) {
  const c = getWindowsGpoCopy(locale);
  const [domainId, setDomainId] = useState(catalog?.results[0]?.id ?? "");
  const [source, setSource] = useState(initialSource);
  const eligibleOverrides =
    overrides?.filter((item) => item.enabled && item.entries.length > 0) ?? [];
  const [overrideId, setOverrideId] = useState(eligibleOverrides[0]?.id ?? "");
  const domain = catalog?.results.find((item) => item.id === domainId);
  const selectedOverride = eligibleOverrides.find(
    (item) => item.id === overrideId,
  );

  if (!catalog || !overrides)
    return (
      <section className={styles.panel}>
        <p role="alert">{c.unavailable}</p>
      </section>
    );

  return (
    <div className={styles.content}>
      <section className={styles.panel} aria-label={c.title}>
        <div className={styles.header}>
          <h2>{c.title}</h2>
          <Link
            className={styles.button}
            href={`/${locale}/administration/security/domains` as Route}
          >
            {c.configure}
          </Link>
        </div>
        {catalog.results.length ? (
          <div className={styles.grantGrid}>
            <label className={styles.field}>
              {c.domain}
              <select
                value={domainId}
                onChange={(event) => setDomainId(event.target.value)}
              >
                {catalog.results.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.domain_name}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.field}>
              {c.source}
              <select
                value={source}
                onChange={(event) =>
                  setSource(event.target.value as "baseline" | "override")
                }
              >
                <option value="baseline">{c.baseline}</option>
                <option value="override">{c.override}</option>
              </select>
            </label>
            {source === "override" ? (
              <label className={styles.field}>
                {c.overrideSelection}
                <select
                  value={overrideId}
                  onChange={(event) => setOverrideId(event.target.value)}
                >
                  {eligibleOverrides.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
          </div>
        ) : (
          <p>{c.noDomains}</p>
        )}
        {source === "override" && !selectedOverride ? (
          <p>{c.noOverrides}</p>
        ) : null}
      </section>
      {domain && (source === "baseline" || selectedOverride) ? (
        <DomainGpoImports
          key={`${domain.id}:${domain.revision}:${source}:${selectedOverride?.id ?? preferredBaselineId ?? ""}`}
          settings={domain}
          catalog={catalog}
          tenantId={tenantId}
          csrfToken={csrfToken}
          canImport
          configurationDirty={false}
          preferredBaselineId={
            source === "baseline" ? preferredBaselineId : undefined
          }
          locale={locale}
          copy={getDomainSecurityCopy(locale)}
          override={source === "override" ? selectedOverride : undefined}
        />
      ) : null}
    </div>
  );
}
