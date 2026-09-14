/**
 * File Name: security-baseline-administration.tsx
 * Version: v0.1.0
 * Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Apply reversible tenant baseline visibility changes with confirmed responses.
 */
"use client";

import { ArrowRight, Eye, EyeOff, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { documentLocale, type Locale } from "@/i18n/config";
import type { SecurityCopy } from "@/i18n/security-copy";
import type {
  SecurityBaselineSetting,
  SecurityBaselineSettings,
  SecurityBaselineVisibility,
} from "@/lib/security-types";
import styles from "./security-baseline-administration.module.css";

function isVisibility(value: unknown): value is SecurityBaselineVisibility {
  if (typeof value !== "object" || value === null) return false;
  const result = value as Record<string, unknown>;
  return (
    typeof result.id === "string" &&
    typeof result.hidden === "boolean" &&
    (result.updated_at === null ||
      (typeof result.updated_at === "string" &&
        Number.isFinite(Date.parse(result.updated_at))))
  );
}

export function SecurityBaselineAdministration({
  initialSettings,
  csrfToken,
  tenantId,
  locale,
  copy,
}: {
  initialSettings: SecurityBaselineSettings | null;
  csrfToken: string;
  tenantId: string;
  locale: Locale;
  copy: SecurityCopy;
}) {
  const [settings, setSettings] = useState(initialSettings);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [uncertainId, setUncertainId] = useState<string | null>(null);
  const [error, setError] = useState(
    initialSettings ? "" : copy.admin.unavailable,
  );
  const [notice, setNotice] = useState("");
  const mounted = useRef(false);
  const activeRequest = useRef<AbortController | null>(null);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeRequest.current?.abort();
      activeRequest.current = null;
    };
  }, []);

  async function setVisibility(baseline: SecurityBaselineSetting) {
    if (!mounted.current || activeRequest.current || uncertainId || !settings)
      return;
    const controller = new AbortController();
    const hidden = !baseline.hidden;
    activeRequest.current = controller;
    setBusyId(baseline.id);
    setError("");
    setNotice("");
    const current = () =>
      mounted.current && activeRequest.current === controller;
    try {
      const response = await fetch(
        `/api/v1/security/baseline-settings/${encodeURIComponent(baseline.id)}/`,
        {
          method: "PATCH",
          credentials: "same-origin",
          cache: "no-store",
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(15_000),
          ]),
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({ hidden }),
        },
      );
      if (!response.ok) {
        throw new Error(
          response.status === 401
            ? copy.admin.sessionExpired
            : response.status === 403
              ? copy.admin.permission
              : response.status === 400
                ? copy.admin.invalid
                : copy.admin.actionFailed,
        );
      }
      const payload: unknown = await response.json();
      if (
        !isVisibility(payload) ||
        payload.id !== baseline.id ||
        payload.hidden !== hidden
      ) {
        throw new Error(copy.admin.actionFailed);
      }
      if (!current()) return;
      setSettings((previous) =>
        previous
          ? {
              ...previous,
              results: previous.results.map((entry) =>
                entry.id === payload.id ? { ...entry, ...payload } : entry,
              ),
            }
          : previous,
      );
      setNotice(
        (hidden ? copy.admin.hiddenNotice : copy.admin.shownNotice).replace(
          "{name}",
          baseline.name,
        ),
      );
    } catch (caught) {
      if (!current()) return;
      const known = [
        copy.admin.sessionExpired,
        copy.admin.permission,
        copy.admin.invalid,
        copy.admin.actionFailed,
      ];
      setUncertainId(baseline.id);
      setError(
        caught instanceof Error && known.includes(caught.message)
          ? caught.message
          : copy.admin.actionFailed,
      );
    } finally {
      if (current()) {
        activeRequest.current = null;
        setBusyId(null);
      }
    }
  }

  const hiddenCount =
    settings?.results.filter((entry) => entry.hidden).length ?? 0;
  const date = (value: string | null) =>
    value
      ? new Intl.DateTimeFormat(documentLocale(locale), {
          dateStyle: "medium",
          timeStyle: "short",
          timeZone: "UTC",
        }).format(new Date(value))
      : copy.admin.default;

  return (
    <div className={styles.content}>
      <div className={styles.toolbar}>
        <p>
          <EyeOff size={18} aria-hidden="true" />
          {copy.admin.boundary}
        </p>
        <div className={styles.actions}>
          <a
            className={styles.button}
            href={`/${locale}/security/baseline`}
            aria-disabled={Boolean(busyId)}
            onClick={(event) => {
              if (busyId) event.preventDefault();
            }}
          >
            {copy.admin.overview}
            <ArrowRight size={15} aria-hidden="true" />
          </a>
          <button
            className={styles.button}
            type="button"
            onClick={() => window.location.reload()}
            disabled={Boolean(busyId)}
          >
            <RefreshCw size={15} aria-hidden="true" />
            {copy.reload}
          </button>
        </div>
      </div>
      {error ? (
        <p className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className={styles.notice} role="status">
          {notice}
        </p>
      ) : null}
      {settings ? (
        <section
          className={styles.panel}
          aria-labelledby="baseline-settings-heading"
          aria-busy={Boolean(busyId)}
        >
          <header className={styles.header}>
            <h2 id="baseline-settings-heading">{copy.admin.table}</h2>
            <p>
              {copy.admin.visible}:{" "}
              {uncertainId ? "—" : settings.results.length - hiddenCount}
              <span aria-hidden="true"> · </span>
              {copy.admin.hidden}: {uncertainId ? "—" : hiddenCount}
            </p>
          </header>
          {settings.results.length === 0 ? (
            <div className={styles.empty}>
              <p>{copy.admin.empty}</p>
            </div>
          ) : (
            <div className={styles.tableScroll}>
              <table>
                <caption className="sr-only">{copy.admin.table}</caption>
                <thead>
                  <tr>
                    <th scope="col">{copy.baseline}</th>
                    <th scope="col">{copy.targetRelease}</th>
                    <th scope="col">{copy.applicable}</th>
                    <th scope="col">{copy.admin.visibility}</th>
                    <th scope="col">{copy.admin.updated}</th>
                    <th scope="col">{copy.admin.action}</th>
                  </tr>
                </thead>
                <tbody>
                  {settings.results.map((baseline) => (
                    <tr key={baseline.id}>
                      <th scope="row">
                        <span className={styles.baseline}>
                          <ShieldCheck size={18} aria-hidden="true" />
                          {baseline.name}
                        </span>
                        <small>{baseline.package_name}</small>
                      </th>
                      <td>
                        <span>{copy.targets[baseline.target]}</span>
                        <small>{baseline.release}</small>
                      </td>
                      <td>{baseline.summary.applicable}</td>
                      <td>
                        <span
                          className={styles.visibility}
                          data-hidden={baseline.hidden}
                        >
                          {uncertainId === baseline.id
                            ? copy.admin.uncertain
                            : baseline.hidden
                              ? copy.admin.hidden
                              : copy.admin.visible}
                        </span>
                      </td>
                      <td>
                        {uncertainId === baseline.id
                          ? "—"
                          : date(baseline.updated_at)}
                      </td>
                      <td>
                        <button
                          className={styles.button}
                          type="button"
                          disabled={Boolean(busyId) || Boolean(uncertainId)}
                          onClick={() => void setVisibility(baseline)}
                          aria-label={`${baseline.hidden ? copy.admin.show : copy.admin.hide}: ${baseline.name}`}
                        >
                          {busyId === baseline.id ? (
                            <RefreshCw size={15} aria-hidden="true" />
                          ) : baseline.hidden ? (
                            <Eye size={15} aria-hidden="true" />
                          ) : (
                            <EyeOff size={15} aria-hidden="true" />
                          )}
                          {busyId === baseline.id
                            ? copy.admin.saving
                            : baseline.hidden
                              ? copy.admin.show
                              : copy.admin.hide}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className={styles.meta}>
            {copy.catalogRevision}: {settings.catalog_revision}
          </p>
        </section>
      ) : null}
    </div>
  );
}
