/**
 * File Name: domain-gpo-imports.tsx
 * Version: v0.1.0 | Created: 2026-09-14 | Modified: 2026-09-14
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Request exact-job local approval for disabled, unlinked pilot GPO imports.
 */
"use client";

import { RefreshCw } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import type { Locale } from "@/i18n/config";
import type { DomainSecurityCopy } from "@/i18n/domain-security-copy";
import {
  type DomainSecurityCatalog,
  type DomainSecuritySettings,
  type DomainGpoImports as Imports,
  SECURITY_TIERS,
  type SecurityTier,
} from "@/lib/domain-security-types";
import {
  isDomainGpoImports,
  isGpoImportJob,
} from "@/lib/domain-security-validation";
import styles from "./domain-security-administration.module.css";

export function DomainGpoImports({
  settings,
  catalog,
  tenantId,
  csrfToken,
  canImport,
  configurationDirty,
  preferredBaselineId,
  locale,
  copy,
}: {
  settings: DomainSecuritySettings;
  catalog: DomainSecurityCatalog;
  tenantId: string;
  csrfToken: string;
  canImport: boolean;
  configurationDirty: boolean;
  preferredBaselineId?: string;
  locale: Locale;
  copy: DomainSecurityCopy;
}) {
  const [imports, setImports] = useState<Imports | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [stale, setStale] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [receiptId, setReceiptId] = useState<string | null>(null);
  const [systemId, setSystemId] = useState("");
  const [baselineId, setBaselineId] = useState(
    settings.baseline_order.includes(preferredBaselineId ?? "")
      ? (preferredBaselineId ?? "")
      : "",
  );
  const [backupId, setBackupId] = useState("");
  const [tier, setTier] = useState<SecurityTier>("0");
  const [target, setTarget] = useState("ALL");
  const [version, setVersion] = useState("1.0.0");
  const activeRequest = useRef<AbortController | null>(null);
  const loadRequest = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const lastRequest = useRef<{ signature: string; key: string } | null>(null);
  const endpoint = `/api/v1/security/domain-settings/${encodeURIComponent(settings.id)}/gpo-imports/`;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      activeRequest.current?.abort();
      loadRequest.current?.abort();
    };
  }, []);

  const refresh = useCallback(async () => {
    if (activeRequest.current) return;
    loadRequest.current?.abort();
    const controller = new AbortController();
    loadRequest.current = controller;
    const current = () => mounted.current && loadRequest.current === controller;
    setLoading(true);
    try {
      const response = await fetch(endpoint, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { "X-IPMS-Tenant-ID": tenantId },
        signal: AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(15_000),
        ]),
      });
      const payload: unknown = response.ok ? await response.json() : null;
      if (!current()) return;
      if (!isDomainGpoImports(payload)) {
        setImports(null);
        setError(
          response.status === 401
            ? copy.sessionExpired
            : response.status === 403
              ? copy.permission
              : copy.importsUnavailable,
        );
        return;
      }
      setImports(payload);
      setUncertain(false);
      setError("");
    } catch {
      if (current()) {
        setImports(null);
        setError(copy.importsUnavailable);
      }
    } finally {
      if (current()) {
        loadRequest.current = null;
        setLoading(false);
      }
    }
  }, [
    endpoint,
    tenantId,
    copy.importsUnavailable,
    copy.permission,
    copy.sessionExpired,
  ]);

  useEffect(() => {
    void refresh();
    return () => {
      loadRequest.current?.abort();
      loadRequest.current = null;
    };
  }, [refresh]);

  const eligibleExecutors =
    imports?.executors.filter(
      (executor) =>
        executor.eligible &&
        executor.domain_name.toLowerCase() ===
          settings.domain_name.toLowerCase(),
    ) ?? [];
  const executor = systemId
    ? eligibleExecutors.find((item) => item.system_id === systemId)
    : eligibleExecutors[0];
  const baselines = settings.baseline_order.flatMap((id) => {
    const option = catalog.baseline_options.find((item) => item.id === id);
    return option ? [option] : [];
  });
  const baseline =
    baselines.find((item) => item.id === baselineId) ?? baselines[0];
  const component =
    baseline?.components.find((item) => item.id === backupId) ??
    baseline?.components.find((item) => item.available);
  const busy = loading || submitting;
  const canRequest =
    canImport &&
    !configurationDirty &&
    !busy &&
    !uncertain &&
    !stale &&
    Boolean(executor && component?.available);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (
      !canRequest ||
      activeRequest.current ||
      !executor ||
      !baseline ||
      !component
    )
      return;
    const document = {
      revision: settings.revision,
      system_id: executor.system_id,
      baseline_id: baseline.id,
      backup_id: component.id,
      tier,
      target: target.trim(),
      version: version.trim(),
    };
    const signature = JSON.stringify(document);
    if (lastRequest.current?.signature !== signature)
      lastRequest.current = { signature, key: crypto.randomUUID() };
    const controller = new AbortController();
    activeRequest.current = controller;
    setSubmitting(true);
    setError("");
    setNotice("");
    setReceiptId(null);
    const current = () =>
      mounted.current && activeRequest.current === controller;
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        signal: AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(20_000),
        ]),
        body: JSON.stringify({
          ...document,
          idempotency_key: lastRequest.current.key,
        }),
      });
      if (!current()) return;
      if (!response.ok) {
        if (response.status === 409) setStale(true);
        if (response.status >= 500) setUncertain(true);
        setError(
          response.status === 401
            ? copy.sessionExpired
            : response.status === 403
              ? copy.permission
              : response.status === 409
                ? copy.conflict
                : response.status === 400
                  ? copy.importInvalid
                  : copy.importUncertain,
        );
        return;
      }
      const payload: unknown = await response.json();
      if (
        !isGpoImportJob(payload) ||
        payload.baseline_id !== baseline.id ||
        payload.backup_id !== component.id ||
        payload.tier !== tier
      )
        throw new Error("invalid_receipt");
      if (!current()) return;
      setImports((previous) =>
        previous
          ? {
              ...previous,
              results: [
                payload,
                ...previous.results.filter((item) => item.id !== payload.id),
              ],
            }
          : previous,
      );
      setNotice(copy.importReceived);
      setReceiptId(payload.id);
    } catch {
      if (current()) {
        setUncertain(true);
        setError(copy.importUncertain);
      }
    } finally {
      if (current()) {
        activeRequest.current = null;
        setSubmitting(false);
      }
    }
  }

  const logsQuery = new URLSearchParams({
    kind: "gpo_import",
    domain: settings.domain_name,
    ...(baseline ? { baseline: baseline.id } : {}),
  });

  return (
    <section
      className={styles.panel}
      aria-labelledby="gpo-imports-heading"
      aria-busy={busy}
    >
      <div className={styles.header}>
        <h2 id="gpo-imports-heading">{copy.importsTitle}</h2>
        <button
          className={styles.button}
          type="button"
          disabled={busy}
          onClick={() => void refresh()}
        >
          <RefreshCw size={16} aria-hidden="true" />
          {copy.importsRefresh}
        </button>
      </div>
      <p className={styles.notice}>{copy.importBoundary}</p>
      {configurationDirty ? (
        <p className={styles.hint}>{copy.saveFirst}</p>
      ) : null}
      {error ? (
        <p className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <div className={styles.success} role="status">
          <p>{notice}</p>
          {receiptId ? (
            <Link
              href={
                `/${locale}/logs/baselines?job=${encodeURIComponent(receiptId)}` as Route
              }
            >
              {copy.openImportLog}
            </Link>
          ) : null}
        </div>
      ) : null}
      {canImport && imports ? (
        <form className={styles.importForm} onSubmit={submit}>
          <div className={styles.formGrid}>
            <label className={styles.field}>
              {copy.executor}
              <select
                name="system_id"
                value={executor?.system_id ?? ""}
                onChange={(event) => setSystemId(event.target.value)}
                disabled={busy || configurationDirty}
              >
                {!executor ? <option value="">{copy.noExecutor}</option> : null}
                {eligibleExecutors.map((item) => (
                  <option key={item.system_id} value={item.system_id}>
                    {item.hostname} · {item.agent_version}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.field}>
              {copy.baseline}
              <select
                name="baseline_id"
                value={baseline?.id ?? ""}
                onChange={(event) => {
                  setBaselineId(event.target.value);
                  setBackupId("");
                }}
                disabled={busy || configurationDirty}
              >
                {baselines.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.field}>
              {copy.component}
              <select
                name="backup_id"
                value={component?.id ?? ""}
                onChange={(event) => setBackupId(event.target.value)}
                disabled={busy || configurationDirty}
              >
                {!component ? (
                  <option value="">{copy.unavailableComponent}</option>
                ) : null}
                {baseline?.components.map((item) => (
                  <option
                    key={item.id}
                    value={item.id}
                    disabled={!item.available}
                  >
                    {item.name}
                    {item.available ? "" : ` · ${copy.unavailableComponent}`}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.field}>
              {copy.tier}
              <select
                name="tier"
                value={tier}
                onChange={(event) =>
                  setTier(event.target.value as SecurityTier)
                }
                disabled={busy || configurationDirty}
              >
                {SECURITY_TIERS.map((item) => (
                  <option key={item} value={item}>
                    Tier {item}
                  </option>
                ))}
              </select>
            </label>
            <label className={styles.field}>
              {copy.target}
              <input
                name="target"
                value={target}
                required
                maxLength={32}
                pattern="[A-Za-z0-9][A-Za-z0-9_\-]{0,31}"
                onChange={(event) => setTarget(event.target.value)}
                disabled={busy || configurationDirty}
              />
            </label>
            <label className={styles.field}>
              {copy.version}
              <input
                name="version"
                value={version}
                required
                maxLength={14}
                pattern="[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}"
                onChange={(event) => setVersion(event.target.value)}
                disabled={busy || configurationDirty}
              />
            </label>
          </div>
          <p className={styles.hint}>{copy.executorHint}</p>
          {executor ? (
            <p className={styles.hint}>
              {executor.domain_name} · {executor.dc_fqdn}
            </p>
          ) : null}
          <button
            className={styles.primaryButton}
            type="submit"
            disabled={!canRequest}
          >
            {submitting ? copy.requesting : copy.importAction}
          </button>
        </form>
      ) : null}
      <p className={styles.hint}>
        <Link href={`/${locale}/logs/baselines?${logsQuery}` as Route}>
          {copy.importLogs}
        </Link>
      </p>
    </section>
  );
}
