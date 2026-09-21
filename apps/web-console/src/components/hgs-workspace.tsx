/**
 * File Name: hgs-workspace.tsx
 * Version: v0.1.0 | Created: 2026-09-19 | Modified: 2026-09-19
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Review and operate exact HGS deployment plans without replaying uncertain writes.
 */
"use client";

import {
  type FormEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import type { Locale } from "@/i18n/config";
import { getHgsCopy, hgsLabel } from "@/i18n/hgs-copy";
import {
  canExecuteHgsPlan,
  canResolveHgsPlan,
  type HgsAttestation,
  type HgsDeployment,
  type HgsOverview,
  type HgsProfile,
  hgsRecoveryReviewKey,
  isHgsDeployment,
  isHgsFeatureSource,
  isHgsOverview,
  shouldPollHgsPlan,
} from "@/lib/hgs-types";
import styles from "./hgs-workspace.module.css";

class HgsRequestError extends Error {
  uncertain: boolean;
  constructor(message: string, uncertain = false) {
    super(message);
    this.uncertain = uncertain;
  }
}

export function HgsWorkspace({
  initial,
  tenantId,
  csrfToken,
  canManage,
  locale,
}: {
  initial: HgsOverview | null;
  tenantId: string;
  csrfToken: string;
  canManage: boolean;
  locale: Locale;
}) {
  const c = getHgsCopy(locale);
  const [catalog, setCatalog] = useState(initial);
  const [selectedId, setSelectedId] = useState(
    initial?.deployments[0]?.id ?? "",
  );
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const requestEpoch = useRef(0);
  const [error, setError] = useState(initial ? "" : c.unavailable);
  const [notice, setNotice] = useState("");
  const [uncertain, setUncertain] = useState(false);
  const [loadFailed, setLoadFailed] = useState(!initial);
  const [reviewed, setReviewed] = useState<{
    id: string;
    digest: string;
  } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [recoveryReview, setRecoveryReview] = useState("");
  const [profile, setProfile] = useState<HgsProfile>("vtpm");
  const [mode, setMode] = useState<HgsAttestation>("host_key");
  const [nodeIds, setNodeIds] = useState<string[]>([]);
  const selected =
    catalog?.deployments.find((item) => item.id === selectedId) ?? null;
  const mayManage =
    canManage && catalog?.can_manage && catalog.tenant_purpose === "hgs";
  const locked = busy || uncertain || loadFailed;
  const shouldPoll = shouldPollHgsPlan(selected);

  const request = useCallback(
    async (
      path: string,
      body?: Record<string, unknown>,
      signal?: AbortSignal,
    ) => {
      let response: Response;
      let payload: unknown;
      try {
        response = await fetch(`/api/v1/hgs/${path}`, {
          method: body ? "POST" : "GET",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
          signal: signal
            ? AbortSignal.any([signal, AbortSignal.timeout(15_000)])
            : AbortSignal.timeout(15_000),
        });
        payload = await response.json();
      } catch {
        throw new HgsRequestError(body ? c.uncertain : c.unavailable, !!body);
      }
      if (!response.ok) {
        const code =
          payload &&
          typeof payload === "object" &&
          "error" in payload &&
          payload.error &&
          typeof payload.error === "object" &&
          "code" in payload.error
            ? String(payload.error.code)
            : "";
        const message =
          response.status === 401 || response.status === 403
            ? c.forbidden
            : response.status === 400
              ? c.invalid
              : response.status === 409 ||
                  [
                    "hgs_plan_expired",
                    "hgs_plan_changed",
                    "hgs_readiness_stale",
                  ].includes(code)
                ? c.changed
                : c.failed;
        throw new HgsRequestError(
          response.status >= 500 && body ? c.uncertain : message,
          response.status >= 500 && !!body,
        );
      }
      return payload;
    },
    [csrfToken, tenantId, c],
  );

  const mergePlan = useCallback((plan: HgsDeployment) => {
    setCatalog((old) =>
      old
        ? {
            ...old,
            deployments: [
              plan,
              ...old.deployments.filter((item) => item.id !== plan.id),
            ],
          }
        : old,
    );
  }, []);

  async function perform(work: () => Promise<void>) {
    if (pending.current) return;
    pending.current = true;
    requestEpoch.current += 1;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await work();
    } catch (caught) {
      setError(caught instanceof HgsRequestError ? caught.message : c.failed);
      if (caught instanceof HgsRequestError && caught.uncertain) {
        setUncertain(true);
        setReviewed(null);
        setRecoveryReview("");
      }
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }

  async function refresh() {
    const payload = await request("");
    if (!isHgsOverview(payload, tenantId)) {
      setLoadFailed(true);
      throw new HgsRequestError(c.unavailable);
    }
    setCatalog(payload);
    setUncertain(false);
    setLoadFailed(false);
    setReviewed(null);
    setRecoveryReview("");
    if (
      selectedId &&
      !payload.deployments.some((item) => item.id === selectedId)
    )
      setSelectedId("");
  }

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 15_000);
    return () => window.clearInterval(timer);
  }, []);

  // Only the selected, active deployment is polled, and only while its page is visible.
  useEffect(() => {
    if (!shouldPoll) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      if (controller.signal.aborted) return;
      if (document.visibilityState === "visible" && !pending.current) {
        const epoch = requestEpoch.current;
        try {
          const payload = await request(
            `deployments/${selectedId}/`,
            undefined,
            controller.signal,
          );
          if (controller.signal.aborted) return;
          if (!isHgsDeployment(payload, tenantId) || payload.id !== selectedId)
            throw new HgsRequestError(c.unavailable);
          if (epoch === requestEpoch.current && !pending.current) {
            mergePlan(payload);
            setLoadFailed(false);
          }
        } catch {
          if (
            !controller.signal.aborted &&
            epoch === requestEpoch.current &&
            !pending.current
          ) {
            setLoadFailed(true);
            setError(c.unavailable);
          }
        }
      }
      if (!controller.signal.aborted)
        timer = setTimeout(() => void poll(), 5_000);
    };
    timer = setTimeout(() => void poll(), 5_000);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [selectedId, shouldPoll, request, tenantId, mergePlan, c.unavailable]);

  async function action(
    kind: "inspect" | "execute" | "cancel" | "reconcile" | "resolve",
  ) {
    if (!selected || !mayManage || locked) return;
    if (
      kind === "execute" &&
      !canExecuteHgsPlan(
        selected,
        reviewed?.id === selected.id ? reviewed.digest : "",
        Date.now(),
      )
    )
      return;
    if (kind === "resolve" && !canResolveHgsPlan(selected, recoveryReview))
      return;
    const payload = await request(
      `deployments/${selected.id}/${kind}/`,
      kind === "execute"
        ? { plan_digest: selected.plan_digest, confirm: true }
        : kind === "resolve" && selected.reconciliation
          ? {
              plan_digest: selected.plan_digest,
              job_id: selected.reconciliation.job_id,
              observation_digest: selected.reconciliation.observation_digest,
              confirm: true,
            }
          : {},
    );
    if (!isHgsDeployment(payload, tenantId) || payload.id !== selected.id)
      throw new HgsRequestError(c.uncertain, true);
    mergePlan(payload);
    setReviewed(null);
    setRecoveryReview("");
    setNotice(
      {
        inspect: c.inspectionQueued,
        execute: c.executionQueued,
        cancel: c.stopped,
        reconcile: c.reconciled,
        resolve: c.resolved,
      }[kind],
    );
  }

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!mayManage || locked || !nodeIds.length) return;
    const fields = new FormData(event.currentTarget);
    if (
      !isHgsFeatureSource(String(fields.get("feature_source") ?? "").trim())
    ) {
      setError(c.sourceInvalid);
      return;
    }
    const body: Record<string, unknown> = {
      profile,
      attestation_mode: mode,
      node_ids: nodeIds,
      allow_reboot: fields.get("allow_reboot") === "on",
    };
    for (const name of [
      "name",
      "domain_name",
      "service_name",
      "feature_source",
      "signing_thumbprint",
      "encryption_thumbprint",
      "dsrm_secret_ref",
      "join_secret_ref",
      "primary_server",
    ])
      body[name] = String(fields.get(name) ?? "").trim();
    await perform(async () => {
      const payload = await request("deployments/", body);
      if (!isHgsDeployment(payload, tenantId))
        throw new HgsRequestError(c.uncertain, true);
      mergePlan(payload);
      setSelectedId(payload.id);
      setReviewed(null);
      setNotice(c.created);
    });
  }

  const timestamp = (value: string | null) =>
    value
      ? `${new Intl.DateTimeFormat(locale, {
          dateStyle: "medium",
          timeStyle: "short",
          timeZone: "UTC",
        }).format(new Date(value))} UTC`
      : c.noObservation;
  const showCode = (code: string) => hgsLabel(c.reasons, code);
  const eligibleReview =
    selected && canExecuteHgsPlan(selected, selected.plan_digest, now);

  return (
    <div className={styles.workspace}>
      <section className={styles.panel}>
        <div className={styles.heading}>
          <strong>{c.singleAppliance}</strong>
          <button
            type="button"
            className="outline-button"
            disabled={busy}
            onClick={() => void perform(refresh)}
          >
            {c.refresh}
          </button>
        </div>
        <p className={styles.muted}>{c.boundary}</p>
      </section>
      {notice ? (
        <p role="status" className="preview-notice preview-notice--live">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="form-error">
          {error}
        </p>
      ) : null}
      {uncertain && error !== c.uncertain ? (
        <p role="alert">{c.uncertain}</p>
      ) : null}
      {catalog?.tenant_purpose === "infrastructure" ? (
        <section className={styles.panel}>
          <p>{c.tenantRequired}</p>
        </section>
      ) : null}
      {catalog?.tenant_purpose === "hgs" ? (
        <>
          {!mayManage ? <p>{c.readOnly}</p> : null}
          <section className={styles.panel}>
            <div className={styles.heading}>
              <label className={styles.field}>
                {c.deployments}
                <select
                  value={selectedId}
                  disabled={busy}
                  onChange={(event) => {
                    setSelectedId(event.target.value);
                    setReviewed(null);
                    setRecoveryReview("");
                  }}
                >
                  <option value="">{mayManage ? c.newPlan : c.empty}</option>
                  {catalog.deployments.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name} — {c.states[item.status]}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          </section>
          {!selected && mayManage ? (
            <section className={styles.panel}>
              <h2>{c.newPlan}</h2>
              <form
                onSubmit={(event) => void create(event)}
                autoComplete="off"
                className={styles.stack}
              >
                <fieldset disabled={locked} className={styles.fieldset}>
                  <div className={styles.fields}>
                    <label className={styles.field}>
                      {c.name}
                      <input name="name" required maxLength={128} />
                    </label>
                    <label className={styles.field}>
                      {c.profile}
                      <select
                        value={profile}
                        onChange={(event) => {
                          const value = event.target.value as HgsProfile;
                          setProfile(value);
                          if (value === "shielded") setMode("tpm");
                        }}
                      >
                        <option value="vtpm">{c.profiles.vtpm}</option>
                        <option value="shielded">{c.profiles.shielded}</option>
                      </select>
                    </label>
                    <label className={styles.field}>
                      {c.attestation}
                      <select
                        value={mode}
                        onChange={(event) =>
                          setMode(event.target.value as HgsAttestation)
                        }
                      >
                        <option
                          value="host_key"
                          disabled={profile === "shielded"}
                        >
                          {c.modes.host_key}
                        </option>
                        <option value="tpm">{c.modes.tpm}</option>
                      </select>
                    </label>
                    <label className={styles.field}>
                      {c.domain}
                      <input
                        name="domain_name"
                        required
                        maxLength={253}
                        placeholder="hgs.example.test"
                      />
                    </label>
                    <label className={styles.field}>
                      {c.service}
                      <input
                        name="service_name"
                        required
                        maxLength={63}
                        placeholder="hgs"
                      />
                    </label>
                    <label className={styles.field}>
                      {c.featureSource}
                      <input
                        name="feature_source"
                        required
                        maxLength={240}
                        placeholder={"D:\\Sources\\SxS"}
                      />
                    </label>
                  </div>
                  <p className={styles.muted}>{c.profileHelp}</p>
                  <p className={styles.muted}>{c.attestationHelp}</p>
                  <p className={styles.muted}>{c.sourceHelp}</p>
                  <div className={styles.fields}>
                    <label className={styles.field}>
                      {c.signing}
                      <input
                        name="signing_thumbprint"
                        required
                        minLength={40}
                        maxLength={40}
                        pattern="[A-Fa-f0-9]{40}"
                        spellCheck={false}
                      />
                    </label>
                    <label className={styles.field}>
                      {c.encryption}
                      <input
                        name="encryption_thumbprint"
                        required
                        minLength={40}
                        maxLength={40}
                        pattern="[A-Fa-f0-9]{40}"
                        spellCheck={false}
                      />
                    </label>
                    <label className={styles.field}>
                      {c.dsrm}
                      <input
                        name="dsrm_secret_ref"
                        required
                        maxLength={64}
                        pattern="[A-Za-z0-9_-]+"
                        spellCheck={false}
                      />
                    </label>
                    <label className={styles.field}>
                      {c.join}
                      <input
                        name="join_secret_ref"
                        required={nodeIds.length > 1}
                        maxLength={64}
                        pattern="[A-Za-z0-9_-]*"
                        spellCheck={false}
                      />
                    </label>
                  </div>
                  <p className={styles.muted}>{c.certificatesHelp}</p>
                  <p className={styles.muted}>{c.secretHelp}</p>
                  <fieldset className={styles.nodePicker}>
                    <legend>{c.nodes}</legend>
                    <p className={styles.muted}>{c.nodesHelp}</p>
                    {!catalog.systems.length ? <p>{c.noSystems}</p> : null}
                    {catalog.systems.map((item) => (
                      <label key={item.id} className={styles.nodeOption}>
                        <input
                          type="checkbox"
                          checked={nodeIds.includes(item.id)}
                          disabled={
                            !item.eligible ||
                            (nodeIds.length >= 8 && !nodeIds.includes(item.id))
                          }
                          onChange={(event) =>
                            setNodeIds((old) =>
                              event.target.checked
                                ? [...old, item.id]
                                : old.filter((id) => id !== item.id),
                            )
                          }
                        />
                        <span>
                          <strong>{item.hostname}</strong>{" "}
                          <span className={styles.muted}>
                            {c.agent} {item.agent_version}
                          </span>
                          {!item.eligible ? (
                            <span className={styles.reason}>
                              {showCode(item.reason)}
                            </span>
                          ) : null}
                        </span>
                      </label>
                    ))}
                    {nodeIds.length ? (
                      <div>
                        <strong>{c.selection}</strong>
                        <ol>
                          {nodeIds.map((id, index) => (
                            <li key={id}>
                              {
                                catalog.systems.find((item) => item.id === id)
                                  ?.hostname
                              }{" "}
                              — {index === 0 ? c.primary : c.additional}
                            </li>
                          ))}
                        </ol>
                      </div>
                    ) : null}
                  </fieldset>
                  {nodeIds.length > 1 ? (
                    <label className={styles.field}>
                      {c.primaryServer}
                      <input
                        name="primary_server"
                        required
                        maxLength={45}
                        spellCheck={false}
                      />
                      <span className={styles.muted}>{c.primaryHelp}</span>
                    </label>
                  ) : null}
                  <label className={styles.check}>
                    <input type="checkbox" name="allow_reboot" />
                    {c.allowReboot}
                  </label>
                </fieldset>
                <div>
                  <button
                    type="submit"
                    className="primary-button"
                    disabled={locked || !nodeIds.length}
                  >
                    {c.create}
                  </button>
                </div>
              </form>
            </section>
          ) : null}
          {selected ? (
            <section
              className={`${styles.panel} ${styles.stack}`}
              aria-labelledby="hgs-plan-title"
            >
              <div className={styles.heading}>
                <h2 id="hgs-plan-title">
                  {c.plan}: {selected.name}
                </h2>
                <span className={styles.status}>
                  {c.states[selected.status]}
                </span>
              </div>
              <dl className={styles.facts}>
                <div>
                  <dt>{c.profile}</dt>
                  <dd>{c.profiles[selected.profile]}</dd>
                </div>
                <div>
                  <dt>{c.attestation}</dt>
                  <dd>{c.modes[selected.attestation_mode]}</dd>
                </div>
                <div>
                  <dt>{c.domain}</dt>
                  <dd>{selected.domain_name}</dd>
                </div>
                <div>
                  <dt>{c.service}</dt>
                  <dd>{selected.service_name}</dd>
                </div>
                <div>
                  <dt>{c.expires}</dt>
                  <dd>{timestamp(selected.plan_expires_at)}</dd>
                </div>
                <div>
                  <dt>{c.approvalExpires}</dt>
                  <dd>
                    {selected.approval_expires_at
                      ? timestamp(selected.approval_expires_at)
                      : c.noApproval}
                  </dd>
                </div>
                <div>
                  <dt>{c.featureSource}</dt>
                  <dd>{selected.config.feature_source}</dd>
                </div>
                <div>
                  <dt>{c.allowReboot}</dt>
                  <dd>{selected.config.allow_reboot ? c.yes : c.no}</dd>
                </div>
                <div>
                  <dt>{c.signing}</dt>
                  <dd>{selected.config.signing_thumbprint}</dd>
                </div>
                <div>
                  <dt>{c.encryption}</dt>
                  <dd>{selected.config.encryption_thumbprint}</dd>
                </div>
                <div>
                  <dt>{c.dsrm}</dt>
                  <dd>{selected.config.dsrm_secret_ref}</dd>
                </div>
                <div>
                  <dt>{c.join}</dt>
                  <dd>{selected.config.join_secret_ref || "—"}</dd>
                </div>
                {selected.config.primary_server ? (
                  <div>
                    <dt>{c.primaryServer}</dt>
                    <dd>{selected.config.primary_server}</dd>
                  </div>
                ) : null}
              </dl>
              <div>
                <strong>{c.digest}</strong>
                <p className={styles.digest}>{selected.plan_digest}</p>
              </div>
              <p className={styles.muted}>{c.profileHelp}</p>
              {Date.parse(selected.plan_expires_at) <= now &&
              ["draft", "ready", "blocked"].includes(selected.status) ? (
                <p role="alert">{c.expired}</p>
              ) : null}
              {selected.status === "ready" && !eligibleReview ? (
                <p role="alert">{c.stale}</p>
              ) : null}
              {selected.status === "reconciliation_required" ? (
                <p role="alert">{c.reconciliation}</p>
              ) : null}
              {selected.blockers.length ? (
                <div>
                  <p>{c.blocked}</p>
                  <ul>
                    {[...new Set(selected.blockers)].map((code) => (
                      <li key={code}>{showCode(code)}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
              <h3>{c.nodes}</h3>
              <div className={styles.nodes}>
                {selected.nodes.map((node) => (
                  <article key={node.id} className={styles.node}>
                    <strong>{node.hostname}</strong>
                    <p>
                      {node.role === "primary" ? c.primary : c.additional} ·{" "}
                      {hgsLabel(c.states, node.status)}
                    </p>
                    <p className={styles.muted}>
                      {c.observed}: {timestamp(node.observed_at)}
                    </p>
                    {node.blockers.length ? (
                      <ul>
                        {[...new Set(node.blockers)].map((code) => (
                          <li key={code}>{showCode(code)}</li>
                        ))}
                      </ul>
                    ) : null}
                  </article>
                ))}
              </div>
              <h3>{c.steps}</h3>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{c.operation}</th>
                      <th>{c.target}</th>
                      <th>{c.change}</th>
                      <th>{c.reboot}</th>
                      <th>{c.status}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selected.steps.map((step) => (
                      <tr key={step.id}>
                        <td>{hgsLabel(c.operations, step.operation)}</td>
                        <td>{step.hostname}</td>
                        <td>{step.mutates ? c.yes : c.no}</td>
                        <td>{step.requires_reboot ? c.yes : c.no}</td>
                        <td>{hgsLabel(c.states, step.status)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {mayManage ? (
                <div className={styles.stack}>
                  {selected.status === "reconciliation_required" &&
                  selected.reconciliation?.can_resolve ? (
                    <div className={styles.stack}>
                      <strong>{c.recoveryEvidence}</strong>
                      <code className={styles.digest}>
                        {selected.reconciliation.observation_digest}
                      </code>
                      <label className={styles.check}>
                        <input
                          type="checkbox"
                          disabled={locked}
                          checked={
                            recoveryReview === hgsRecoveryReviewKey(selected)
                          }
                          onChange={(event) =>
                            setRecoveryReview(
                              event.target.checked
                                ? hgsRecoveryReviewKey(selected)
                                : "",
                            )
                          }
                        />
                        {c.recoveryReview}
                      </label>
                    </div>
                  ) : null}
                  {selected.status === "reconciliation_required" &&
                  selected.reconciliation?.reason ? (
                    <p>{showCode(selected.reconciliation.reason)}</p>
                  ) : null}
                  {selected.status === "ready" ? (
                    <label className={styles.check}>
                      <input
                        type="checkbox"
                        disabled={locked || !eligibleReview}
                        checked={
                          reviewed?.id === selected.id &&
                          reviewed.digest === selected.plan_digest
                        }
                        onChange={(event) =>
                          setReviewed(
                            event.target.checked
                              ? {
                                  id: selected.id,
                                  digest: selected.plan_digest,
                                }
                              : null,
                          )
                        }
                      />
                      {c.review}
                    </label>
                  ) : null}
                  <div className={styles.actions}>
                    {selected.status === "reconciliation_required" &&
                    selected.reconciliation?.can_resolve ? (
                      <button
                        type="button"
                        className="primary-button"
                        disabled={
                          locked || !canResolveHgsPlan(selected, recoveryReview)
                        }
                        onClick={() => void perform(() => action("resolve"))}
                      >
                        {c.resolve}
                      </button>
                    ) : null}
                    {["draft", "blocked", "ready"].includes(selected.status) ? (
                      <button
                        type="button"
                        className="outline-button"
                        disabled={locked}
                        onClick={() => void perform(() => action("inspect"))}
                      >
                        {c.inspect}
                      </button>
                    ) : null}
                    {selected.status === "ready" ? (
                      <button
                        type="button"
                        className="primary-button"
                        disabled={
                          locked ||
                          !canExecuteHgsPlan(
                            selected,
                            reviewed?.id === selected.id ? reviewed.digest : "",
                            now,
                          )
                        }
                        onClick={() => void perform(() => action("execute"))}
                      >
                        {c.execute}
                      </button>
                    ) : null}
                    {selected.status === "reconciliation_required" ? (
                      <button
                        type="button"
                        className="outline-button"
                        disabled={locked}
                        onClick={() => void perform(() => action("reconcile"))}
                      >
                        {c.reconcile}
                      </button>
                    ) : null}
                    {!["succeeded", "failed", "cancelled"].includes(
                      selected.status,
                    ) ? (
                      <button
                        type="button"
                        className="outline-button"
                        disabled={locked}
                        onClick={() => void perform(() => action("cancel"))}
                      >
                        {c.cancel}
                      </button>
                    ) : null}
                  </div>
                  <p className={styles.muted}>{c.cancelHelp}</p>
                </div>
              ) : null}
              <h3>{c.jobs}</h3>
              {!selected.jobs.length ? (
                <p className={styles.muted}>{c.noJobs}</p>
              ) : (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>{c.operation}</th>
                        <th>{c.target}</th>
                        <th>{c.status}</th>
                        <th>{c.result}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selected.jobs.map((job) => (
                        <tr key={job.id}>
                          <td>{hgsLabel(c.operations, job.operation)}</td>
                          <td>
                            {selected.nodes.find(
                              (node) => node.id === job.node_id,
                            )?.hostname ?? c.unknown}
                          </td>
                          <td>{hgsLabel(c.states, job.status)}</td>
                          <td>{job.result_code || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}
