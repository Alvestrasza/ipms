/**
 * File Name: domain-gpo-imports.tsx
 * Version: v0.4.0 | Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Prepare snapshot-bound import/link requests in one action while keeping activation separately approved.
 */
"use client";
import { RefreshCw } from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";
import type { Locale } from "@/i18n/config";
import type { DomainSecurityCopy } from "@/i18n/domain-security-copy";
import { getGpoProductionCopy } from "@/i18n/gpo-production-copy";
import type {
  DomainSecurityCatalog,
  DomainSecuritySettings,
  GpoImportExecutor,
  GpoImportJob,
  SecurityTier,
} from "@/lib/domain-security-types";
import {
  isDomainGpoImports,
  isGpoImportJob,
} from "@/lib/domain-security-validation";
import {
  GPO_OPERATIONS,
  type GpoOperation,
  isManagedGpo,
  type ManagedGpo,
} from "@/lib/gpo-production-types";
import styles from "./gpo-production.module.css";
import { GpoStateReview } from "./gpo-state-review";

type Props = {
  settings: DomainSecuritySettings;
  catalog: DomainSecurityCatalog;
  tenantId: string;
  csrfToken: string;
  canImport: boolean;
  configurationDirty: boolean;
  preferredBaselineId?: string;
  locale: Locale;
  copy: DomainSecurityCopy;
};
type Listing = {
  results: ManagedGpo[];
  executors: GpoImportExecutor[];
  jobs: GpoImportJob[];
};
function listing(v: unknown): v is Listing {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  return (
    Array.isArray(r.results) &&
    r.results.length <= 10000 &&
    r.results.every(isManagedGpo) &&
    isDomainGpoImports({ results: r.jobs, executors: r.executors })
  );
}
export function DomainGpoImports(props: Props) {
  return (
    <ProductionWorkflow
      key={`${props.tenantId}:${props.settings.id}:${props.settings.revision}:${props.csrfToken}:${props.canImport}`}
      {...props}
    />
  );
}
function ProductionWorkflow({
  settings,
  catalog,
  tenantId,
  csrfToken,
  canImport,
  configurationDirty,
  preferredBaselineId,
  locale,
  copy,
}: Props) {
  const c = getGpoProductionCopy(locale);
  const endpoint = `/api/v1/security/domain-settings/${encodeURIComponent(settings.id)}`;
  const [data, setData] = useState<Listing | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [policyId, setPolicyId] = useState("");
  const [systemId, setSystemId] = useState("");
  const [baselineId, setBaselineId] = useState(preferredBaselineId ?? "");
  const [backupId, setBackupId] = useState("");
  const [tier, setTier] = useState<SecurityTier>("0");
  const [target, setTarget] = useState("ALL");
  const [version, setVersion] = useState("1.0.0");
  const [adoptJobId, setAdoptJobId] = useState("");
  const [operation, setOperation] = useState<GpoOperation>(
    "import_and_link_managed_gpo",
  );
  const [automaticRequest, setAutomaticRequest] = useState(false);
  const writeStarted = useRef(false);
  const [inspectionId, setInspectionId] = useState("");
  const [receiptId, setReceiptId] = useState("");
  const [management, setManagement] = useState(false);
  const [recovery, setRecovery] = useState(false);
  const [domainRootConfirmed, setDomainRootConfirmed] = useState(false);
  const mounted = useRef(false);
  const mutation = useRef<AbortController | null>(null);
  const read = useRef<AbortController | null>(null);
  const pending = useRef<{
    signature: string;
    id: string;
    kind: "inspect" | "write";
  } | null>(null);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      mutation.current?.abort();
      read.current?.abort();
    };
  }, []);
  const refresh = useCallback(async () => {
    if (mutation.current) return;
    read.current?.abort();
    const controller = new AbortController();
    read.current = controller;
    const current = () => mounted.current && read.current === controller;
    setLoading(true);
    try {
      const response = await fetch(`${endpoint}/managed-gpos/`, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { "X-IPMS-Tenant-ID": tenantId },
        signal: AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(15000),
        ]),
      });
      const payload: unknown = response.ok ? await response.json() : null;
      if (!current()) return;
      if (!listing(payload)) {
        setData(null);
        setError(c.unavailable);
        return;
      }
      setData(payload);
      setError("");
      const existing =
        pending.current &&
        payload.jobs.find((j) => j.id === pending.current?.id);
      if (
        existing &&
        existing.operation ===
          (pending.current?.kind === "inspect"
            ? "inspect_managed_gpo"
            : operation)
      ) {
        if (pending.current?.kind === "inspect") {
          setInspectionId(existing.id);
          if (existing.managed_id) setPolicyId(existing.managed_id);
        } else {
          setReceiptId(existing.id);
          setAutomaticRequest(false);
          setNotice(c.prepared);
        }
        pending.current = null;
      }
    } catch {
      if (current()) {
        setData(null);
        setError(c.unavailable);
      }
    } finally {
      if (current()) {
        read.current = null;
        setLoading(false);
      }
    }
  }, [endpoint, tenantId, c.unavailable, c.prepared, operation]);
  useEffect(() => {
    void refresh();
    return () => read.current?.abort();
  }, [refresh]);
  const policy = data?.results.find((p) => p.id === policyId);
  const inspection = data?.jobs.find((j) => j.id === inspectionId);
  const checking =
    inspection?.operation === "inspect_managed_gpo" &&
    ["queued", "running"].includes(inspection.status);
  useEffect(() => {
    if (!checking || busy) return;
    const timer = setInterval(() => void refresh(), 4000);
    return () => clearInterval(timer);
  }, [checking, busy, refresh]);
  const baselines = settings.baseline_order.flatMap((id) => {
    const b = catalog.baseline_options.find((b) => b.id === id);
    return b ? [b] : [];
  });
  const baseline = baselines.find((b) => b.id === baselineId) ?? baselines[0];
  const component =
    baseline?.components.find((b) => b.id === backupId) ??
    baseline?.components.find((b) => b.available);
  const executors =
    data?.executors.filter(
      (e) =>
        e.eligible &&
        e.domain_name.toLowerCase() === settings.domain_name.toLowerCase() &&
        /^\d+\.\d+\.\d+$/.test(e.agent_version) &&
        (Number(e.agent_version.split(".")[0]) > 0 ||
          Number(e.agent_version.split(".")[1]) > 2 ||
          (Number(e.agent_version.split(".")[1]) === 2 &&
            Number(e.agent_version.split(".")[2]) >=
              (operation === "import_and_link_managed_gpo" ? 36 : 35))),
    ) ?? [];
  const executor =
    executors.find((e) => e.system_id === systemId) ?? executors[0];
  const resetInspection = () => {
    setAutomaticRequest(false);
    writeStarted.current = false;
    setInspectionId("");
    setReceiptId("");
    setManagement(false);
    setRecovery(false);
    setDomainRootConfirmed(false);
    setNotice("");
  };
  const selectPolicy = (id: string) => {
    resetInspection();
    setPolicyId(id);
    setAdoptJobId("");
    const selected = data?.results.find((p) => p.id === id);
    if (selected) {
      setBaselineId(selected.baseline_id);
      setBackupId(selected.backup_id);
      setTier(selected.tier);
      setTarget(selected.target);
      setVersion(selected.version);
      setOperation(
        selected.state === "active"
          ? "import_managed_gpo"
          : "import_and_link_managed_gpo",
      );
    } else setOperation("import_and_link_managed_gpo");
  };
  const legacy =
    data?.jobs.filter(
      (j) =>
        !j.managed_id &&
        j.status === "staged" &&
        j.gpo_guid &&
        j.baseline_id === baseline?.id &&
        j.backup_id === component?.id &&
        j.tier === tier,
    ) ?? [];
  const disabled = busy || loading || !canImport || configurationDirty;
  const lockedSelection =
    disabled || pending.current !== null || automaticRequest;
  const domainRootAction =
    component?.scope === "domain" && operation !== "import_managed_gpo";
  const domainRootDn = settings.domain_name
    .split(".")
    .map((part) => `DC=${part}`)
    .join(",");
  const actionSelection = {
    revision: settings.revision,
    system_id: executor?.system_id ?? "",
    baseline_id: baseline?.id ?? "",
    backup_id: component?.id ?? "",
    tier,
    target,
    version,
    operation,
    managed_id: policy?.id ?? null,
    adopt_job_id: adoptJobId || null,
    domain_root_confirmed: domainRootAction && domainRootConfirmed,
  };
  async function submit(kind: "inspect" | "write") {
    if (disabled || mutation.current || !data) return;
    const body =
      kind === "inspect"
        ? actionSelection
        : {
            preflight_id: inspectionId,
            safety_review: {
              management_access:
                operation === "activate_managed_gpo" && management,
              recovery_access: operation === "activate_managed_gpo" && recovery,
            },
          };
    const signature = JSON.stringify({ kind, body });
    if (pending.current && pending.current.signature !== signature) {
      setError(c.uncertain);
      return;
    }
    const key = pending.current?.id ?? crypto.randomUUID();
    pending.current = { signature, id: key, kind };
    read.current?.abort();
    read.current = null;
    const controller = new AbortController();
    mutation.current = controller;
    setBusy(true);
    setError("");
    setNotice("");
    const current = () => mounted.current && mutation.current === controller;
    try {
      const response = await fetch(
        `${endpoint}/${kind === "inspect" ? "gpo-preflights" : "managed-gpos"}/`,
        {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({ ...body, idempotency_key: key }),
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(20000),
          ]),
        },
      );
      const payload: unknown = response.ok ? await response.json() : null;
      if (!current()) return;
      if (!response.ok) {
        if (response.status < 500) {
          pending.current = null;
          resetInspection();
        }
        setError(response.status >= 500 ? c.uncertain : c.rejected);
        return;
      }
      if (
        !isGpoImportJob(payload) ||
        payload.id !== key ||
        (kind === "inspect"
          ? payload.operation !== "inspect_managed_gpo"
          : payload.operation !== operation)
      )
        throw new Error("invalid_receipt");
      pending.current = null;
      setData((old) =>
        old
          ? { ...old, jobs: [payload, ...old.jobs.filter((j) => j.id !== key)] }
          : old,
      );
      if (kind === "inspect") {
        setInspectionId(payload.id);
        if (payload.managed_id) setPolicyId(payload.managed_id);
        setReceiptId("");
        setNotice(c.preparing);
      } else {
        setReceiptId(payload.id);
        setAutomaticRequest(false);
        setNotice(c.prepared);
      }
    } catch {
      if (current()) setError(c.uncertain);
    } finally {
      if (current()) {
        mutation.current = null;
        setBusy(false);
        setLoading(false);
      }
    }
  }
  const canInspect =
    !disabled &&
    executor &&
    baseline &&
    component?.available &&
    (!domainRootAction || domainRootConfirmed) &&
    (operation === "import_managed_gpo" ||
      operation === "import_and_link_managed_gpo" ||
      policy?.gpo_guid) &&
    (component.scope !== "domain" || tier === "0") &&
    (operation !== "activate_managed_gpo" || (management && recovery)) &&
    /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/.test(target) &&
    /^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(version);
  const fresh =
    inspection?.can_prepare &&
    inspection.preflight_state &&
    inspection.inspection_expires_at &&
    Date.parse(inspection.inspection_expires_at) > Date.now();
  const completeInspection = useEffectEvent(() => {
    void submit("write");
  });
  useEffect(() => {
    if (
      !automaticRequest ||
      busy ||
      loading ||
      pending.current ||
      writeStarted.current ||
      !inspection ||
      receiptId
    )
      return;
    if (checking) return;
    if (!fresh) {
      setAutomaticRequest(false);
      return;
    }
    writeStarted.current = true;
    completeInspection();
  }, [automaticRequest, busy, loading, inspection, receiptId, checking, fresh]);
  const canCreate =
    !receiptId &&
    !busy &&
    !loading &&
    Boolean(data) &&
    (pending.current !== null || (!automaticRequest && canInspect));
  const logsUrl = (id: string) =>
    `/${locale}/logs/baselines?job=${encodeURIComponent(id)}` as Route;
  return (
    <section
      className={styles.panel}
      aria-label={c.title}
      aria-busy={busy || loading}
    >
      <div className={styles.heading}>
        <h3>{c.title}</h3>
        <button
          type="button"
          className="outline-button"
          disabled={busy || loading}
          onClick={() => void refresh()}
        >
          <RefreshCw size={16} aria-hidden /> {c.refresh}
        </button>
      </div>
      <p>{c.description}</p>
      {configurationDirty ? <p>{copy.saveFirst}</p> : null}
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
      <form
        className={styles.form}
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          if (!canCreate) return;
          if (pending.current) {
            void submit(pending.current.kind);
            return;
          }
          setAutomaticRequest(true);
          writeStarted.current = false;
          void submit("inspect");
        }}
      >
        <div className={styles.fields}>
          <label>
            {c.policy}
            <select
              value={policyId}
              disabled={lockedSelection}
              onChange={(e) => selectPolicy(e.target.value)}
            >
              <option value="">{c.create}</option>
              {data?.results.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.state === "active"
                    ? p.active_display_name
                      ? `${p.active_display_name} · ${c.states.active}`
                      : c.activeUnverified
                    : `${p.display_name} · ${c.states[p.state]}`}
                  {p.state === "active" &&
                  p.active_display_name !== p.display_name
                    ? ` · ${c.states.prepared}: ${p.display_name}`
                    : ""}
                </option>
              ))}
            </select>
          </label>
          <label>
            {c.operation}
            <select
              value={operation}
              disabled={lockedSelection}
              onChange={(e) => {
                resetInspection();
                setOperation(e.target.value as GpoOperation);
              }}
            >
              {GPO_OPERATIONS.filter(
                (op) => op !== "import_managed_gpo" || Boolean(policy),
              ).map((op) => (
                <option
                  key={op}
                  value={op}
                  disabled={
                    (op !== "import_managed_gpo" &&
                      op !== "import_and_link_managed_gpo" &&
                      !policy?.gpo_guid) ||
                    (op === "import_and_link_managed_gpo" &&
                      policy?.state === "active")
                  }
                >
                  {c.actions[op]}
                </option>
              ))}
            </select>
          </label>
          <label>
            {c.executor}
            <select
              value={executor?.system_id ?? ""}
              disabled={lockedSelection}
              onChange={(e) => {
                resetInspection();
                setSystemId(e.target.value);
              }}
            >
              {!executors.length ? (
                <option value="">
                  {operation === "import_and_link_managed_gpo"
                    ? c.noExecutor
                    : c.noLegacyExecutor}
                </option>
              ) : (
                executors.map((e) => (
                  <option key={e.system_id} value={e.system_id}>
                    {e.hostname} · {e.agent_version}
                  </option>
                ))
              )}
            </select>
          </label>
          <label>
            {c.baseline}
            <select
              value={baseline?.id ?? ""}
              disabled={lockedSelection || Boolean(policy)}
              onChange={(e) => {
                resetInspection();
                setBaselineId(e.target.value);
                setBackupId("");
                setAdoptJobId("");
              }}
            >
              {baselines.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {c.component}
            <select
              value={component?.id ?? ""}
              disabled={lockedSelection || Boolean(policy)}
              onChange={(e) => {
                resetInspection();
                setBackupId(e.target.value);
                setAdoptJobId("");
              }}
            >
              {baseline?.components.map((c) => (
                <option key={c.id} value={c.id} disabled={!c.available}>
                  {c.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            {c.tier}
            <select
              value={tier}
              disabled={lockedSelection || Boolean(policy)}
              onChange={(e) => {
                resetInspection();
                setTier(e.target.value as SecurityTier);
                setAdoptJobId("");
              }}
            >
              {["0", "1", "2"].map((t) => (
                <option key={t} value={t}>
                  Tier {t}
                </option>
              ))}
            </select>
          </label>
          <label>
            {c.target}
            <input
              value={target}
              maxLength={32}
              pattern="[A-Za-z0-9][A-Za-z0-9_-]{0,31}"
              required
              disabled={lockedSelection || Boolean(policy)}
              onChange={(e) => {
                resetInspection();
                setTarget(e.target.value);
              }}
            />
          </label>
          <label>
            {c.version}
            <input
              value={version}
              maxLength={14}
              pattern="[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}"
              required
              disabled={
                lockedSelection ||
                (operation !== "import_managed_gpo" &&
                  operation !== "import_and_link_managed_gpo")
              }
              onChange={(e) => {
                resetInspection();
                setVersion(e.target.value);
              }}
            />
          </label>
          {!policy && legacy.length ? (
            <label>
              {c.adopt}
              <select
                value={adoptJobId}
                disabled={lockedSelection}
                onChange={(e) => {
                  resetInspection();
                  setAdoptJobId(e.target.value);
                }}
              >
                <option value="">{c.noAdopt}</option>
                {legacy.map((j) => (
                  <option key={j.id} value={j.id}>
                    {j.display_name ?? j.pilot_display_name}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>
        {component?.scope === "domain" ? <p>{c.domainBoundary}</p> : null}
        {domainRootAction ? (
          <div className={styles.checks}>
            <p>
              {c.domainRoot}: <strong>{domainRootDn}</strong>
            </p>
            <label>
              <input
                type="checkbox"
                checked={domainRootConfirmed}
                disabled={lockedSelection}
                onChange={(event) => {
                  resetInspection();
                  setDomainRootConfirmed(event.target.checked);
                }}
              />
              {c.confirmDomainRoot}
            </label>
          </div>
        ) : null}
        {operation === "activate_managed_gpo" ? (
          <div className={styles.checks}>
            <p>{c.activation}</p>
            <label>
              <input
                type="checkbox"
                checked={management}
                disabled={lockedSelection || Boolean(receiptId)}
                onChange={(event) => setManagement(event.target.checked)}
              />
              {c.management}
            </label>
            <label>
              <input
                type="checkbox"
                checked={recovery}
                disabled={lockedSelection || Boolean(receiptId)}
                onChange={(event) => setRecovery(event.target.checked)}
              />
              {c.recovery}
            </label>
          </div>
        ) : null}
        {operation === "link_managed_gpo" ? (
          <p>{c.linkBoundary}</p>
        ) : operation === "deactivate_managed_gpo" ? (
          <p>{c.deactivateBoundary}</p>
        ) : null}
        <div className={styles.actions}>
          <button
            type="submit"
            className="primary-button"
            disabled={!canCreate}
          >
            {pending.current ? c.retry : c.prepare}
          </button>
          <span>{c.createHint}</span>
        </div>
      </form>
      {checking ? <p role="status">{c.preparing}</p> : null}
      {inspection && !checking && inspection.status !== "inspected" ? (
        <p role="alert">
          {copy.states[inspection.status]} {inspection.error_code}
        </p>
      ) : null}
      {inspection?.preflight_state ? (
        <>
          <GpoStateReview
            state={inspection.preflight_state}
            displayName={
              inspection.display_name ?? inspection.pilot_display_name
            }
            locale={locale}
          />
          {!fresh && !receiptId ? <p role="alert">{c.expiry}</p> : null}
          <div className={styles.actions}>
            {receiptId ? (
              <Link className="outline-button" href={logsUrl(receiptId)}>
                {c.logs}
              </Link>
            ) : null}
          </div>
        </>
      ) : null}
    </section>
  );
}
