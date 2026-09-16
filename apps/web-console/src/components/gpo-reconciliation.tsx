/**
 * File Name: gpo-reconciliation.tsx
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Request read-only directory observations and explicitly accept their exact digest.
 */
"use client";
import {
  useCallback,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";
import { documentLocale, type Locale } from "@/i18n/config";
import {
  getReconciliationCopy,
  reconciliationApiError,
  reconciliationReason,
} from "@/i18n/gpo-reconciliation-copy";
import {
  isReconciliationProjection,
  type ReconciliationProjection,
} from "@/lib/gpo-reconciliation-types";
import type { GpoImportLogDetail } from "@/lib/job-log-types";
import styles from "./gpo-production.module.css";

type Props = {
  job: GpoImportLogDetail;
  tenantId: string;
  csrfToken: string;
  locale: Locale;
  onAccepted: () => void;
};
type Pending =
  | { kind: "request"; id: string }
  | { kind: "accept"; id: string; digest: string };
export function GpoReconciliation(props: Props) {
  return (
    <Reconciliation
      key={`${props.tenantId}:${props.job.id}:${props.job.input_digest}:${props.csrfToken}`}
      {...props}
    />
  );
}
function Reconciliation({
  job,
  tenantId,
  csrfToken,
  locale,
  onAccepted,
}: Props) {
  const c = getReconciliationCopy(locale);
  const formatter = new Intl.DateTimeFormat(documentLocale(locale), {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  });
  const endpoint = `/api/v1/security/gpo-imports/${job.id}/reconciliations/`;
  const [data, setData] = useState<ReconciliationProjection | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [now, setNow] = useState(Date.now);
  const pending = useRef<Pending | null>(null);
  const read = useRef<AbortController | null>(null);
  const write = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  const delivered = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      read.current?.abort();
      write.current?.abort();
    };
  }, []);
  const refresh = useCallback(async () => {
    if (write.current) return;
    read.current?.abort();
    const controller = new AbortController();
    read.current = controller;
    setBusy(true);
    const current = () => mounted.current && read.current === controller;
    try {
      const response = await fetch(endpoint, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { "X-IPMS-Tenant-ID": tenantId },
        signal: AbortSignal.any([
          controller.signal,
          AbortSignal.timeout(15000),
        ]),
      });
      const payload: unknown = await response.json().catch(() => null);
      if (!current()) return;
      if (!response.ok || !isReconciliationProjection(payload)) {
        setData(null);
        setError(
          response.ok
            ? c.unavailable
            : reconciliationApiError(response.status, payload, locale),
        );
        return;
      }
      setData(payload);
      setError("");
      const expected = pending.current;
      if (
        expected &&
        payload.latest?.id === expected.id &&
        (expected.kind === "request" ||
          ["accept_requested", "accepted"].includes(payload.latest.status))
      )
        pending.current = null;
    } catch {
      if (current()) {
        setData(null);
        setError(c.unavailable);
      }
    } finally {
      if (current()) {
        read.current = null;
        setBusy(false);
      }
    }
  }, [endpoint, tenantId, c.unavailable, locale]);
  useEffect(() => {
    void refresh();
    return () => read.current?.abort();
  }, [refresh]);
  const status = data?.latest?.status;
  useEffect(() => {
    if (status !== "requested" && status !== "accept_requested") return;
    const timer = setInterval(() => void refresh(), 4000);
    return () => clearInterval(timer);
  }, [status, refresh]);
  const accepted = useEffectEvent(onAccepted);
  useEffect(() => {
    if (
      status === "accepted" &&
      job.status !== "reconciled" &&
      !delivered.current
    ) {
      delivered.current = true;
      accepted();
    }
  }, [status, job.status]);
  async function submit(kind: "request" | "accept") {
    if (busy || write.current || !data) return;
    const previous = pending.current;
    if (previous && previous.kind !== kind) return;
    if (
      !previous &&
      (kind === "request" ? !data.can_request : !data.latest?.can_accept)
    )
      return;
    const action: Pending =
      previous ??
      (kind === "request"
        ? { kind, id: crypto.randomUUID() }
        : {
            kind,
            id: data.latest?.id ?? "",
            digest: data.latest?.observation_digest ?? "",
          });
    if (
      action.kind === "accept" &&
      (!/^[0-9a-f]{64}$/.test(action.digest) ||
        data.latest?.status !== "observed" ||
        Date.parse(data.latest.expires_at) <= Date.now())
    )
      return;
    pending.current = action;
    read.current?.abort();
    read.current = null;
    const controller = new AbortController();
    write.current = controller;
    const current = () => mounted.current && write.current === controller;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(
        action.kind === "request"
          ? endpoint
          : `${endpoint}${action.id}/accept/`,
        {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-IPMS-Tenant-ID": tenantId,
            "X-CSRFToken": csrfToken,
          },
          body: JSON.stringify(
            action.kind === "request"
              ? { idempotency_key: action.id, input_digest: job.input_digest }
              : { observation_digest: action.digest },
          ),
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(20000),
          ]),
        },
      );
      const payload: unknown = await response.json().catch(() => null);
      if (!current()) return;
      if (!response.ok) {
        if (response.status < 500) {
          pending.current = null;
          setData(null);
        }
        setError(
          response.status >= 500
            ? c.uncertain
            : reconciliationApiError(response.status, payload, locale),
        );
        return;
      }
      if (
        !isReconciliationProjection(payload) ||
        payload.latest?.id !== action.id
      )
        throw new Error("invalid_reconciliation_receipt");
      pending.current = null;
      setData(payload);
    } catch {
      if (current()) setError(c.uncertain);
    } finally {
      if (current()) {
        write.current = null;
        setBusy(false);
      }
    }
  }
  const latest = data?.latest;
  useEffect(() => {
    if (!latest) return;
    setNow(Date.now());
    const timer = setTimeout(
      () => setNow(Date.now()),
      Math.max(
        0,
        Math.min(86400000, Date.parse(latest.expires_at) - Date.now() + 10),
      ),
    );
    return () => clearTimeout(timer);
  }, [latest]);
  const observation = latest?.observation;
  const expectedTargets = job.review?.target_ous ?? [];
  const before = job.review?.expected_state?.gpo;
  const after = observation?.state?.gpo;
  const fields = [
    "guid",
    "name",
    "computer_enabled",
    "user_enabled",
    "computer_ds",
    "computer_sysvol",
    "user_ds",
    "user_sysvol",
  ] as const;
  const text = (value: unknown) =>
    value === undefined || value === null
      ? c.unknown
      : typeof value === "boolean"
        ? value
          ? c.yes
          : c.no
        : String(value);
  const fresh = latest && Date.parse(latest.expires_at) > now;
  const canAccept =
    !busy &&
    !pending.current &&
    latest?.status === "observed" &&
    latest.can_accept &&
    fresh;
  return (
    <section className={styles.panel} aria-label={c.title} aria-busy={busy}>
      <div className={styles.heading}>
        <h4>{c.title}</h4>
        <button
          type="button"
          className="outline-button"
          disabled={busy}
          onClick={() => void refresh()}
        >
          {c.refresh}
        </button>
      </div>
      <p>{c.boundary}</p>
      <p>{c.content}</p>
      {error ? <p role="alert">{error}</p> : null}
      {latest ? <p role="status">{c.statuses[latest.status]}</p> : null}
      {latest ? (
        <dl className={styles.metadata}>
          <div>
            <dt>{c.requestedAt}</dt>
            <dd>
              <time dateTime={latest.requested_at}>
                {formatter.format(new Date(latest.requested_at))}
              </time>
            </dd>
          </div>
          <div>
            <dt>{c.expiresAt}</dt>
            <dd>
              <time dateTime={latest.expires_at}>
                {formatter.format(new Date(latest.expires_at))}
              </time>
            </dd>
          </div>
        </dl>
      ) : null}
      {pending.current ? (
        <button
          className="primary-button"
          type="button"
          disabled={busy || !data}
          onClick={() => {
            if (pending.current) void submit(pending.current.kind);
          }}
        >
          {c.retry}
        </button>
      ) : (
        <button
          className="primary-button"
          type="button"
          disabled={busy || !data?.can_request}
          onClick={() => void submit("request")}
        >
          {c.request}
        </button>
      )}
      {data && !data.can_request && data.request_blocked_reason ? (
        <p>{reconciliationReason(data.request_blocked_reason, locale)}</p>
      ) : null}
      {observation ? (
        <>
          <h5>{c.observed}</h5>
          <dl className={styles.metadata}>
            <div>
              <dt>GPO GUID</dt>
              <dd>{observation.gpo_guid || c.unknown}</dd>
            </div>
            <div>
              <dt>{c.presence}</dt>
              <dd>{c.presenceValues[observation.gpo_presence]}</dd>
            </div>
            <div>
              <dt>{c.complete}</dt>
              <dd>{text(observation.forest_complete)}</dd>
            </div>
            <div>
              <dt>{c.acl}</dt>
              <dd>{text(observation.acl_consistent)}</dd>
            </div>
            <div>
              <dt>{c.quiescent}</dt>
              <dd>{text(observation.quiescent)}</dd>
            </div>
          </dl>
          <h5>{c.expected}</h5>
          <ul className={styles.targets}>
            {expectedTargets.map((dn) => (
              <li key={dn}>
                {dn}
                {observation.forest_complete &&
                !observation.forest_links.some(
                  (link) => link.dn.toLowerCase() === dn.toLowerCase(),
                )
                  ? ` — ${c.missing}`
                  : ""}
              </li>
            ))}
          </ul>
          {!expectedTargets.length ? <p>{c.none}</p> : null}
          <h5>{c.actual}</h5>
          <ul className={styles.targets}>
            {observation.forest_links.map((link) => (
              <li key={`${link.domain}:${link.dn}:${link.guid}`}>
                {link.dn} · {link.kind} · {c.order}: {link.order} · {c.enabled}:{" "}
                {text(link.enabled)} · {c.enforced}: {text(link.enforced)}
                {!expectedTargets.some(
                  (dn) => dn.toLowerCase() === link.dn.toLowerCase(),
                )
                  ? ` — ${c.extra}`
                  : ""}
              </li>
            ))}
          </ul>
          {!observation.forest_links.length ? (
            <p>{observation.forest_complete ? c.none : c.incompleteLinks}</p>
          ) : null}
          <table className={styles.comparison}>
            <caption>{c.observed}</caption>
            <thead>
              <tr>
                <th>{c.field}</th>
                <th>{c.before}</th>
                <th>{c.after}</th>
              </tr>
            </thead>
            <tbody>
              {fields.map((field) => (
                <tr key={field}>
                  <th>{c.fields[field]}</th>
                  <td>
                    {before === null
                      ? c.presenceValues.absent
                      : text(before?.[field])}
                  </td>
                  <td>{text(after?.[field])}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
      {latest &&
      latest.issues.length + (observation?.issues.length ?? 0) > 0 ? (
        <div>
          <h5>{c.issues}</h5>
          <ul>
            {[
              ...new Set([...latest.issues, ...(observation?.issues ?? [])]),
            ].map((issue) => (
              <li key={issue}>{reconciliationReason(issue, locale)}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {latest?.status === "observed" ? (
        <>
          <p>{c.acceptance}</p>
          <button
            className="primary-button"
            type="button"
            disabled={!canAccept}
            onClick={() => void submit("accept")}
          >
            {c.accept}
          </button>
          {!canAccept && !busy && (latest.accept_blocked_reason || !fresh) ? (
            <p>
              {reconciliationReason(
                !fresh ? "observation_stale" : latest.accept_blocked_reason,
                locale,
              )}
            </p>
          ) : null}
        </>
      ) : null}
      <p>{c.retained}</p>
    </section>
  );
}
