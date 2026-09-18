/**
 * File Name: policy-collections.tsx
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Compose ordered GPO policies and orchestrate their multi-domain rollout.
 */
"use client";
import { useCallback, useEffect, useState } from "react";
import {
  type CollectionCopy,
  collectionApiError,
  collectionCondition,
  collectionStatus,
} from "@/i18n/collection-copy";
import {
  isPolicyCollection,
  isPolicyCollectionDeployment,
  isPolicyCollectionPreview,
  type PolicyCollection,
  type PolicyCollectionCatalog,
  type PolicyCollectionDeployment,
  type PolicyCollectionPreview,
} from "@/lib/collection-types";
import type {
  DomainSecurityCatalog,
  SecurityTier,
} from "@/lib/domain-security-types";
import type { SecurityOverride } from "@/lib/security-override-types";
import styles from "./collections.module.css";

type EntryDraft = {
  _key: string;
  source: "baseline" | "override";
  baseline_id: string;
  backup_id: string;
  target: string;
  version: string;
  override_id: string | null;
};
type BindingDraft = {
  domain_id: string;
  tier: SecurityTier;
  target_ous: string[];
};
type Props = {
  initial: PolicyCollectionCatalog;
  domains: DomainSecurityCatalog;
  overrides: SecurityOverride[];
  tenantId: string;
  csrfToken: string;
  canManage: boolean;
  copy: CollectionCopy;
};

export function PolicyCollections({
  initial,
  domains,
  overrides,
  tenantId,
  csrfToken,
  canManage,
  copy: c,
}: Props) {
  const [catalog, setCatalog] = useState(initial);
  const [selectedId, setSelectedId] = useState(initial.results[0]?.id ?? "");
  const selected = catalog.results.find((row) => row.id === selectedId) ?? null;
  const [editing, setEditing] = useState<PolicyCollection | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [entries, setEntries] = useState<EntryDraft[]>([]);
  const [bindings, setBindings] = useState<BindingDraft[]>([]);
  const [preview, setPreview] = useState<PolicyCollectionPreview | null>(null);
  const [deployments, setDeployments] = useState<PolicyCollectionDeployment[]>(
    [],
  );
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const firstBaseline = domains.baseline_options.find((baseline) =>
    baseline.components.some((component) => component.available),
  );
  const defaultEntry = (): EntryDraft | null => {
    const component = firstBaseline?.components.find((item) => item.available);
    return firstBaseline && component
      ? {
          _key: crypto.randomUUID(),
          source: "baseline",
          baseline_id: firstBaseline.id,
          backup_id: component.id,
          target: "ALL",
          version: "1.0.0",
          override_id: null,
        }
      : null;
  };
  function reset() {
    setEditing(null);
    setName("");
    setDescription("");
    setEntries([]);
    setBindings([]);
    setError("");
  }
  function edit(row: PolicyCollection) {
    setSelectedId(row.id);
    setEditing(row);
    setName(row.name);
    setDescription(row.description);
    setEntries(
      row.entries.map((entry) => ({
        _key: crypto.randomUUID(),
        source: entry.source,
        baseline_id: entry.baseline_id,
        backup_id: entry.backup_id,
        target: entry.target,
        version: entry.version,
        override_id: entry.override_id,
      })),
    );
    setBindings(
      row.bindings.map((binding) => ({
        domain_id: binding.domain_id,
        tier: binding.tier,
        target_ous: [...binding.target_ous],
      })),
    );
    setNotice("");
    setError("");
  }
  const loadStatus = useCallback(
    async (collectionId: string) => {
      if (!collectionId) return;
      try {
        const [previewResponse, deploymentsResponse] = await Promise.all([
          fetch(
            `/api/v1/security/policy-collections/${collectionId}/preview/`,
            {
              cache: "no-store",
              credentials: "same-origin",
              headers: { "X-IPMS-Tenant-ID": tenantId },
              signal: AbortSignal.timeout(10_000),
            },
          ),
          fetch(
            `/api/v1/security/policy-collections/${collectionId}/deployments/`,
            {
              cache: "no-store",
              credentials: "same-origin",
              headers: { "X-IPMS-Tenant-ID": tenantId },
              signal: AbortSignal.timeout(10_000),
            },
          ),
        ]);
        const previewPayload: unknown = previewResponse.ok
          ? await previewResponse.json()
          : null;
        const deploymentPayload: unknown = deploymentsResponse.ok
          ? await deploymentsResponse.json()
          : null;
        if (isPolicyCollectionPreview(previewPayload))
          setPreview(previewPayload);
        if (
          typeof deploymentPayload === "object" &&
          deploymentPayload !== null &&
          "results" in deploymentPayload &&
          Array.isArray(deploymentPayload.results) &&
          deploymentPayload.results.every(isPolicyCollectionDeployment)
        )
          setDeployments(deploymentPayload.results);
      } catch {
        /* Preserve the last confirmed projection during a transient read failure. */
      }
    },
    [tenantId],
  );
  useEffect(() => {
    setPreview(null);
    setDeployments([]);
    if (!selectedId) return;
    void loadStatus(selectedId);
    const timer = window.setInterval(() => void loadStatus(selectedId), 4000);
    return () => window.clearInterval(timer);
  }, [selectedId, loadStatus]);
  function selectSource(
    index: number,
    source: "baseline" | "override",
    id: string,
  ) {
    setEntries((current) =>
      current.map((entry, i) => {
        if (i !== index) return entry;
        if (source === "override") {
          const override =
            overrides.find((row) => row.id === id) ?? overrides[0];
          return override
            ? {
                ...entry,
                source,
                baseline_id: override.baseline_id,
                backup_id: override.backup_id,
                override_id: override.id,
              }
            : entry;
        }
        const baseline =
          domains.baseline_options.find((row) => row.id === id) ??
          firstBaseline;
        const component = baseline?.components.find((item) => item.available);
        return baseline && component
          ? {
              ...entry,
              source,
              baseline_id: baseline.id,
              backup_id: component.id,
              override_id: null,
            }
          : entry;
      }),
    );
  }
  async function save() {
    if (
      !canManage ||
      !name.trim() ||
      !entries.length ||
      !bindings.length ||
      busy
    )
      return;
    setBusy(true);
    setError("");
    setNotice("");
    const body = {
      name: name.trim(),
      description,
      entries: entries.map(({ _key: _unused, ...entry }) => entry),
      bindings,
      ...(editing ? { expected_revision: editing.revision } : {}),
    };
    try {
      const response = await fetch(
        editing
          ? `/api/v1/security/policy-collections/${editing.id}/`
          : "/api/v1/security/policy-collections/",
        {
          method: editing ? "PUT" : "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(20_000),
        },
      );
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        setError(collectionApiError(payload, c));
        return;
      }
      if (!isPolicyCollection(payload)) throw new Error("save_failed");
      setCatalog((current) => ({
        results: [
          payload,
          ...current.results.filter((row) => row.id !== payload.id),
        ].sort((a, b) => a.name.localeCompare(b.name)),
      }));
      setSelectedId(payload.id);
      reset();
      setNotice(c.saved);
    } catch {
      setError(c.uncertain);
    } finally {
      setBusy(false);
    }
  }
  async function remove(row: PolicyCollection) {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(
        `/api/v1/security/policy-collections/${row.id}/`,
        {
          method: "DELETE",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({ expected_revision: row.revision }),
          signal: AbortSignal.timeout(20_000),
        },
      );
      if (!response.ok) {
        setError(
          collectionApiError(await response.json().catch(() => null), c),
        );
        return;
      }
      const next = catalog.results.filter((item) => item.id !== row.id);
      setCatalog({ results: next });
      setSelectedId(next[0]?.id ?? "");
      if (editing?.id === row.id) reset();
      setNotice(c.deleted);
    } catch {
      setError(c.uncertain);
    } finally {
      setBusy(false);
    }
  }
  async function deploy() {
    if (!selected || !preview?.ready || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(
        `/api/v1/security/policy-collections/${selected.id}/deployments/`,
        {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({
            expected_revision: selected.revision,
            idempotency_key: crypto.randomUUID(),
          }),
          signal: AbortSignal.timeout(20_000),
        },
      );
      const payload: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        setError(collectionApiError(payload, c));
        return;
      }
      if (!isPolicyCollectionDeployment(payload))
        throw new Error("deploy_failed");
      setDeployments((current) => [
        payload,
        ...current.filter((row) => row.id !== payload.id),
      ]);
      setNotice(c.submitted);
    } catch {
      setError(c.uncertain);
    } finally {
      setBusy(false);
    }
  }
  const availableDomains = domains.results.filter(
    (domain) => !bindings.some((binding) => binding.domain_id === domain.id),
  );
  return (
    <div className={styles.stack}>
      <div className={styles.layout}>
        <section className={`${styles.panel} ${styles.stack}`}>
          <div className={styles.between}>
            <h2>{c.policyTitle}</h2>
            <span className={styles.status}>{catalog.results.length}</span>
          </div>
          {catalog.results.length ? (
            <ul className={styles.list}>
              {catalog.results.map((row) => (
                <li
                  key={row.id}
                  className={`${styles.card} ${selectedId === row.id ? styles.selected : ""}`}
                >
                  <button
                    className={styles.button}
                    type="button"
                    onClick={() => setSelectedId(row.id)}
                  >
                    <strong>{row.name}</strong>
                  </button>
                  <div className={styles.muted}>
                    {row.entries.length} GPO · {row.bindings.length} Domain
                  </div>
                  <div className={styles.row}>
                    {canManage ? (
                      <button
                        className={styles.button}
                        type="button"
                        onClick={() => edit(row)}
                      >
                        {c.edit}
                      </button>
                    ) : null}
                    {canManage ? (
                      <button
                        className={`${styles.button} ${styles.danger}`}
                        type="button"
                        onClick={() => void remove(row)}
                      >
                        {c.delete}
                      </button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p>{c.noCollections}</p>
          )}
        </section>
        <section className={`${styles.panel} ${styles.stack}`}>
          <h2>{editing ? c.update : c.newPolicy}</h2>
          <div className={styles.grid}>
            <label className={styles.field}>
              {c.name}
              <input
                maxLength={100}
                value={name}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
            <label className={styles.field}>
              {c.description}
              <textarea
                maxLength={500}
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </label>
          </div>
          <div className={styles.stack}>
            <div className={styles.between}>
              <strong>{c.orderedPolicies}</strong>
              <button
                className={styles.button}
                type="button"
                onClick={() => {
                  const entry = defaultEntry();
                  if (entry) setEntries((current) => [...current, entry]);
                }}
              >
                {c.addPolicy}
              </button>
            </div>
            {entries.map((entry, index) => {
              const baseline = domains.baseline_options.find(
                (row) => row.id === entry.baseline_id,
              );
              return (
                <div
                  className={`${styles.card} ${styles.policy} ${styles.stack}`}
                  key={entry._key}
                >
                  <div className={styles.grid}>
                    <label className={styles.field}>
                      {c.source}
                      <select
                        value={entry.source}
                        onChange={(event) =>
                          selectSource(
                            index,
                            event.target.value as "baseline" | "override",
                            event.target.value === "override"
                              ? (overrides[0]?.id ?? "")
                              : (firstBaseline?.id ?? ""),
                          )
                        }
                      >
                        <option value="baseline">{c.baseline}</option>
                        <option value="override" disabled={!overrides.length}>
                          {c.override}
                        </option>
                      </select>
                    </label>
                    {entry.source === "baseline" ? (
                      <label className={styles.field}>
                        {c.baseline}
                        <select
                          value={entry.baseline_id}
                          onChange={(event) =>
                            selectSource(index, "baseline", event.target.value)
                          }
                        >
                          {domains.baseline_options
                            .filter((row) =>
                              row.components.some((item) => item.available),
                            )
                            .map((row) => (
                              <option value={row.id} key={row.id}>
                                {row.name}
                              </option>
                            ))}
                        </select>
                      </label>
                    ) : (
                      <label className={styles.field}>
                        {c.override}
                        <select
                          value={entry.override_id ?? ""}
                          onChange={(event) =>
                            selectSource(index, "override", event.target.value)
                          }
                        >
                          {overrides.map((row) => (
                            <option value={row.id} key={row.id}>
                              {row.name}
                            </option>
                          ))}
                        </select>
                      </label>
                    )}
                    {entry.source === "baseline" ? (
                      <label className={styles.field}>
                        {c.component}
                        <select
                          value={entry.backup_id}
                          onChange={(event) =>
                            setEntries((current) =>
                              current.map((item, i) =>
                                i === index
                                  ? { ...item, backup_id: event.target.value }
                                  : item,
                              ),
                            )
                          }
                        >
                          {baseline?.components
                            .filter((item) => item.available)
                            .map((component) => (
                              <option value={component.id} key={component.id}>
                                {component.name}
                              </option>
                            ))}
                        </select>
                      </label>
                    ) : null}
                    <label className={styles.field}>
                      {c.targetAlias}
                      <input
                        value={entry.target}
                        onChange={(event) =>
                          setEntries((current) =>
                            current.map((item, i) =>
                              i === index
                                ? { ...item, target: event.target.value }
                                : item,
                            ),
                          )
                        }
                      />
                    </label>
                    <label className={styles.field}>
                      {c.version}
                      <input
                        value={entry.version}
                        onChange={(event) =>
                          setEntries((current) =>
                            current.map((item, i) =>
                              i === index
                                ? { ...item, version: event.target.value }
                                : item,
                            ),
                          )
                        }
                      />
                    </label>
                  </div>
                  <div className={styles.row}>
                    <button
                      className={styles.button}
                      type="button"
                      disabled={index === 0}
                      onClick={() =>
                        setEntries((current) => {
                          const next = [...current];
                          [next[index - 1], next[index]] = [
                            next[index],
                            next[index - 1],
                          ];
                          return next;
                        })
                      }
                    >
                      {c.moveUp}
                    </button>
                    <button
                      className={styles.button}
                      type="button"
                      disabled={index === entries.length - 1}
                      onClick={() =>
                        setEntries((current) => {
                          const next = [...current];
                          [next[index + 1], next[index]] = [
                            next[index],
                            next[index + 1],
                          ];
                          return next;
                        })
                      }
                    >
                      {c.moveDown}
                    </button>
                    <button
                      className={`${styles.button} ${styles.danger}`}
                      type="button"
                      onClick={() =>
                        setEntries((current) =>
                          current.filter((_, i) => i !== index),
                        )
                      }
                    >
                      {c.remove}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
          <div className={styles.stack}>
            <div className={styles.between}>
              <strong>{c.domainBindings}</strong>
              <button
                className={styles.button}
                type="button"
                disabled={!availableDomains.length}
                onClick={() => {
                  const domain = availableDomains[0];
                  if (domain)
                    setBindings((current) => [
                      ...current,
                      { domain_id: domain.id, tier: "1", target_ous: [] },
                    ]);
                }}
              >
                {c.addDomain}
              </button>
            </div>
            <p className={styles.muted}>{c.rootHint}</p>
            {bindings.map((binding, index) => {
              const domain = domains.results.find(
                (row) => row.id === binding.domain_id,
              );
              const targets = domain?.tier_ous[binding.tier] ?? [];
              return (
                <div
                  className={`${styles.card} ${styles.stack}`}
                  key={binding.domain_id}
                >
                  <div className={styles.grid}>
                    <label className={styles.field}>
                      {c.addDomain}
                      <select
                        value={binding.domain_id}
                        onChange={(event) =>
                          setBindings((current) =>
                            current.map((item, i) =>
                              i === index
                                ? {
                                    domain_id: event.target.value,
                                    tier: item.tier,
                                    target_ous: [],
                                  }
                                : item,
                            ),
                          )
                        }
                      >
                        {domains.results
                          .filter(
                            (row) =>
                              row.id === binding.domain_id ||
                              !bindings.some(
                                (item) => item.domain_id === row.id,
                              ),
                          )
                          .map((row) => (
                            <option value={row.id} key={row.id}>
                              {row.domain_name}
                            </option>
                          ))}
                      </select>
                    </label>
                    <label className={styles.field}>
                      {c.tier}
                      <select
                        value={binding.tier}
                        onChange={(event) =>
                          setBindings((current) =>
                            current.map((item, i) =>
                              i === index
                                ? {
                                    ...item,
                                    tier: event.target.value as SecurityTier,
                                    target_ous: [],
                                  }
                                : item,
                            ),
                          )
                        }
                      >
                        <option value="0">0</option>
                        <option value="1">1</option>
                        <option value="2">2</option>
                      </select>
                    </label>
                  </div>
                  <div className={styles.checklist}>
                    {targets.map((target) => (
                      <label className={styles.check} key={target}>
                        <input
                          type="checkbox"
                          checked={binding.target_ous.includes(target)}
                          onChange={(event) =>
                            setBindings((current) =>
                              current.map((item, i) =>
                                i === index
                                  ? {
                                      ...item,
                                      target_ous: event.target.checked
                                        ? [...item.target_ous, target]
                                        : item.target_ous.filter(
                                            (value) => value !== target,
                                          ),
                                    }
                                  : item,
                              ),
                            )
                          }
                        />
                        <span className={styles.target}>{target}</span>
                      </label>
                    ))}
                  </div>
                  <button
                    className={`${styles.button} ${styles.danger}`}
                    type="button"
                    onClick={() =>
                      setBindings((current) =>
                        current.filter((_, i) => i !== index),
                      )
                    }
                  >
                    {c.remove}
                  </button>
                </div>
              );
            })}
          </div>
          {notice ? (
            <p role="status" className={styles.success}>
              {notice}
            </p>
          ) : null}
          {error ? (
            <p role="alert" className={styles.error}>
              {error}
            </p>
          ) : null}
          {canManage ? (
            <div className={styles.row}>
              <button
                className={`${styles.button} ${styles.primary}`}
                disabled={
                  busy ||
                  !name.trim() ||
                  !entries.length ||
                  !bindings.length ||
                  bindings.some((row) => !row.target_ous.length)
                }
                type="button"
                onClick={() => void save()}
              >
                {editing ? c.update : c.save}
              </button>
              {editing ? (
                <button className={styles.button} type="button" onClick={reset}>
                  {c.cancel}
                </button>
              ) : null}
            </div>
          ) : null}
        </section>
      </div>
      {selected ? (
        <section
          className={`${styles.panel} ${styles.stack}`}
          aria-label={c.preview}
        >
          <div className={styles.between}>
            <div>
              <h2>
                {c.preview}: {selected.name}
              </h2>
              <p className={styles.muted}>{c.activationHint}</p>
            </div>
            <button
              className={styles.button}
              type="button"
              onClick={() => void loadStatus(selected.id)}
            >
              {c.refreshPreview}
            </button>
          </div>
          {preview ? (
            <>
              <span
                className={`${styles.status} ${preview.ready ? styles.success : styles.error}`}
              >
                {preview.ready ? c.ready : c.blocked}
              </span>
              <ul className={styles.list}>
                {preview.items.map((item) => (
                  <li
                    className={styles.card}
                    key={`${item.domain_id}-${item.policy_index}`}
                  >
                    <div className={styles.between}>
                      <strong>
                        {item.domain_name} · T{item.tier} ·{" "}
                        {item.component_name}
                      </strong>
                      <span
                        className={`${styles.status} ${item.ready ? styles.success : styles.error}`}
                      >
                        {item.ready
                          ? c.ready
                          : `${c.blocked}: ${collectionCondition(item.blocker, c)}`}
                      </span>
                    </div>
                    <div className={styles.target}>
                      {item.target_ous.join(" · ")}
                    </div>
                    <div className={styles.muted}>
                      {c.executor}: {item.executor?.hostname ?? "-"}
                    </div>
                  </li>
                ))}
              </ul>
              {canManage ? (
                <button
                  className={`${styles.button} ${styles.primary}`}
                  type="button"
                  disabled={busy || !preview.ready}
                  onClick={() => void deploy()}
                >
                  {c.deploy}
                </button>
              ) : null}
            </>
          ) : (
            <p>{c.unavailable}</p>
          )}
          <h3>{c.deployments}</h3>
          {deployments.length ? (
            <ul className={styles.list}>
              {deployments.map((deployment) => (
                <li className={styles.card} key={deployment.id}>
                  <div className={styles.between}>
                    <strong>{collectionStatus(deployment.status, c)}</strong>
                    <span className={styles.muted}>
                      {new Date(deployment.requested_at).toLocaleString()}
                    </span>
                  </div>
                  {deployment.items.map((item) => (
                    <div className={styles.row} key={item.id}>
                      <span>
                        {item.domain_name} · {item.component_name}
                      </span>
                      <span className={styles.status}>
                        {collectionStatus(item.status, c)}
                      </span>
                      {item.error_code ? (
                        <span className={styles.error}>
                          {collectionCondition(item.error_code, c)}
                        </span>
                      ) : null}
                    </div>
                  ))}
                </li>
              ))}
            </ul>
          ) : (
            <p className={styles.muted}>—</p>
          )}
        </section>
      ) : null}
    </div>
  );
}
