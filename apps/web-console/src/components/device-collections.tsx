/**
 * File Name: device-collections.tsx
 * Version: v0.1.0 | Created: 2026-09-18 | Modified: 2026-09-18
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Manage direct and rule-based Windows device collections.
 */
"use client";
import { useState } from "react";
import {
  type CollectionCopy,
  collectionApiError,
} from "@/i18n/collection-copy";
import {
  type DeviceCollection,
  type DeviceCollectionCatalog,
  type DeviceRule,
  isDeviceCollection,
} from "@/lib/collection-types";
import styles from "./collections.module.css";

type Props = {
  initial: DeviceCollectionCatalog;
  tenantId: string;
  csrfToken: string;
  canManage: boolean;
  copy: CollectionCopy;
};
type RuleDraft = DeviceRule & { _key: string };
const emptyRule = (): RuleDraft => ({
  _key: crypto.randomUUID(),
  hostname_contains: "",
});

export function DeviceCollections({
  initial,
  tenantId,
  csrfToken,
  canManage,
  copy: c,
}: Props) {
  const [catalog, setCatalog] = useState(initial);
  const [editing, setEditing] = useState<DeviceCollection | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [members, setMembers] = useState<string[]>([]);
  const [rules, setRules] = useState<RuleDraft[]>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  function reset() {
    setEditing(null);
    setName("");
    setDescription("");
    setMembers([]);
    setRules([]);
    setError("");
  }
  function edit(row: DeviceCollection) {
    setEditing(row);
    setName(row.name);
    setDescription(row.description);
    setMembers([...row.static_system_ids]);
    setRules(row.rules.map((rule) => ({ ...rule, _key: crypto.randomUUID() })));
    setNotice("");
    setError("");
  }
  async function save() {
    if (!canManage || !name.trim() || busy) return;
    setBusy(true);
    setError("");
    setNotice("");
    const body = {
      name: name.trim(),
      description,
      static_system_ids: members,
      rules: rules
        .map(({ _key: _unused, ...rule }) =>
          Object.fromEntries(
            Object.entries(rule).filter(([, value]) => value?.trim()),
          ),
        )
        .filter((rule) => Object.keys(rule).length),
      ...(editing ? { expected_revision: editing.revision } : {}),
    };
    try {
      const response = await fetch(
        editing
          ? `/api/v1/security/device-collections/${editing.id}/`
          : "/api/v1/security/device-collections/",
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
      if (!isDeviceCollection(payload)) throw new Error("save_failed");
      setCatalog((current) => ({
        ...current,
        results: [
          payload,
          ...current.results.filter((row) => row.id !== payload.id),
        ].sort((a, b) => a.name.localeCompare(b.name)),
      }));
      reset();
      setNotice(c.saved);
    } catch {
      setError(c.uncertain);
    } finally {
      setBusy(false);
    }
  }
  async function remove(row: DeviceCollection) {
    if (!canManage || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await fetch(
        `/api/v1/security/device-collections/${row.id}/`,
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
      setCatalog((current) => ({
        ...current,
        results: current.results.filter((item) => item.id !== row.id),
      }));
      if (editing?.id === row.id) reset();
      setNotice(c.deleted);
    } catch {
      setError(c.uncertain);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className={styles.layout}>
      <section
        className={`${styles.panel} ${styles.stack}`}
        aria-label={c.deviceTitle}
      >
        <div className={styles.between}>
          <h2>{c.deviceTitle}</h2>
          <span className={styles.status}>{catalog.results.length}</span>
        </div>
        {catalog.results.length ? (
          <ul className={styles.list}>
            {catalog.results.map((row) => (
              <li
                className={`${styles.card} ${editing?.id === row.id ? styles.selected : ""}`}
                key={row.id}
              >
                <div className={styles.between}>
                  <div>
                    <strong>{row.name}</strong>
                    <div className={styles.muted}>{row.description}</div>
                  </div>
                  <span className={styles.status}>
                    {c.memberCount}: {row.member_count}
                  </span>
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
      <section
        className={`${styles.panel} ${styles.stack}`}
        aria-label={editing ? c.update : c.newDevice}
      >
        <h2>{editing ? c.update : c.newDevice}</h2>
        <div className={styles.grid}>
          <label className={styles.field}>
            {c.name}
            <input
              value={name}
              maxLength={100}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className={styles.field}>
            {c.description}
            <textarea
              value={description}
              maxLength={500}
              onChange={(event) => setDescription(event.target.value)}
            />
          </label>
        </div>
        <div className={styles.field}>
          <strong>{c.directMembers}</strong>
          <div className={styles.checklist}>
            {catalog.inventory.map((system) => (
              <label className={styles.check} key={system.id}>
                <input
                  type="checkbox"
                  checked={members.includes(system.id)}
                  onChange={(event) =>
                    setMembers((current) =>
                      event.target.checked
                        ? [...current, system.id]
                        : current.filter((id) => id !== system.id),
                    )
                  }
                />
                <span>
                  {system.hostname}
                  <small className={styles.muted}>
                    {" "}
                    · {system.domain_name || "-"} ·{" "}
                    {system.operating_system_role}
                  </small>
                </span>
              </label>
            ))}
          </div>
        </div>
        <div className={styles.stack}>
          <div className={styles.between}>
            <strong>{c.rules}</strong>
            <button
              className={styles.button}
              type="button"
              onClick={() => setRules((current) => [...current, emptyRule()])}
            >
              {c.addRule}
            </button>
          </div>
          {rules.map((rule, index) => (
            <div className={`${styles.card} ${styles.grid}`} key={rule._key}>
              <label className={styles.field}>
                {c.hostnameContains}
                <input
                  value={rule.hostname_contains ?? ""}
                  onChange={(event) =>
                    setRules((current) =>
                      current.map((item, i) =>
                        i === index
                          ? { ...item, hostname_contains: event.target.value }
                          : item,
                      ),
                    )
                  }
                />
              </label>
              <label className={styles.field}>
                {c.anyDomain}
                <input
                  value={rule.domain_name ?? ""}
                  onChange={(event) =>
                    setRules((current) =>
                      current.map((item, i) =>
                        i === index
                          ? { ...item, domain_name: event.target.value }
                          : item,
                      ),
                    )
                  }
                />
              </label>
              <label className={styles.field}>
                {c.serverType}
                <select
                  value={rule.server_type ?? ""}
                  onChange={(event) =>
                    setRules((current) =>
                      current.map((item, i) =>
                        i === index
                          ? { ...item, server_type: event.target.value }
                          : item,
                      ),
                    )
                  }
                >
                  <option value="">*</option>
                  <option value="physical">Physical</option>
                  <option value="virtual">Virtual</option>
                  <option value="unknown">Unknown</option>
                </select>
              </label>
              <label className={styles.field}>
                {c.role}
                <select
                  value={rule.operating_system_role ?? ""}
                  onChange={(event) =>
                    setRules((current) =>
                      current.map((item, i) =>
                        i === index
                          ? {
                              ...item,
                              operating_system_role: event.target.value,
                            }
                          : item,
                      ),
                    )
                  }
                >
                  <option value="">*</option>
                  <option value="server">Server</option>
                  <option value="domain-controller">Domain Controller</option>
                  <option value="client">Client</option>
                  <option value="unknown">Unknown</option>
                </select>
              </label>
              <button
                className={`${styles.button} ${styles.danger}`}
                type="button"
                onClick={() =>
                  setRules((current) => current.filter((_, i) => i !== index))
                }
              >
                {c.remove}
              </button>
            </div>
          ))}
        </div>
        {notice ? (
          <p className={styles.success} role="status">
            {notice}
          </p>
        ) : null}
        {error ? (
          <p className={styles.error} role="alert">
            {error}
          </p>
        ) : null}
        {canManage ? (
          <div className={styles.row}>
            <button
              className={`${styles.button} ${styles.primary}`}
              disabled={busy || !name.trim()}
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
  );
}
