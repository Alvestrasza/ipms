/**
 * File Name: security-overrides.tsx
 * Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Edit sparse deviations from original settings and reuse managed GPO deployment.
 */
"use client";
import { type FormEvent, useEffect, useMemo, useRef, useState } from "react";
import type { Locale } from "@/i18n/config";
import { getDomainSecurityCopy } from "@/i18n/domain-security-copy";
import {
  getSecurityOverrideCopy,
  overrideReadonlyReason,
} from "@/i18n/security-override-copy";
import type { DomainSecurityCatalog } from "@/lib/domain-security-types";
import {
  isOverrideCatalog,
  isSecurityOverride,
  type OverrideCatalog,
  type OverrideEntry,
  parseOverrideInput,
  type SecurityOverride,
  sameOverrideValue,
} from "@/lib/security-override-types";
import { DomainGpoImports } from "./domain-gpo-imports";
import styles from "./security-overrides.module.css";

type Props = {
  initial: SecurityOverride[] | null;
  domains: DomainSecurityCatalog | null;
  tenantId: string;
  csrfToken: string;
  locale: Locale;
  canImport: boolean;
};
const inputValue = (v: unknown) =>
  Array.isArray(v)
    ? v.join("\n")
    : typeof v === "number" || typeof v === "string"
      ? String(v)
      : "";
const displayValue = (v: unknown) =>
  typeof v === "string" ? JSON.stringify(v) : JSON.stringify(v, null, 2);
export function SecurityOverrides(props: Props) {
  const c = getSecurityOverrideCopy(props.locale);
  const [items, setItems] = useState(props.initial);
  const [selectedId, setSelectedId] = useState(props.initial?.[0]?.id ?? "");
  const [locked, setLocked] = useState(false);
  const [notice, setNotice] = useState("");
  const selected = items?.find((i) => i.id === selectedId) ?? null;
  if (!items || !props.domains)
    return (
      <section className={styles.panel}>
        <p role="alert">{c.load}</p>
        <button type="button" onClick={() => window.location.reload()}>
          {c.reload}
        </button>
      </section>
    );
  return (
    <div className={styles.workspace}>
      {notice ? <p role="status">{notice}</p> : null}
      <section className={styles.panel}>
        <div className={styles.fields}>
          <label>
            {c.select}
            <select
              value={selectedId}
              disabled={locked}
              onChange={(e) => setSelectedId(e.target.value)}
            >
              <option value="">{c.create}</option>
              {items.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      </section>
      <OverrideEditor
        key={`${props.tenantId}:${selected?.id ?? "new"}:${selected?.revision ?? 0}`}
        {...props}
        domains={props.domains}
        selected={selected}
        onLocked={setLocked}
        onSaved={(item) => {
          setItems((old) => [
            ...(old ?? []).filter((i) => i.id !== item.id),
            item,
          ]);
          setSelectedId(item.id);
          setLocked(false);
          setNotice(c.saved);
        }}
      />
    </div>
  );
}
function OverrideEditor({
  selected,
  domains,
  tenantId,
  csrfToken,
  locale,
  canImport,
  onLocked,
  onSaved,
}: Omit<Props, "initial"> & {
  domains: DomainSecurityCatalog;
  selected: SecurityOverride | null;
  onLocked: (v: boolean) => void;
  onSaved: (v: SecurityOverride) => void;
}) {
  const c = getSecurityOverrideCopy(locale);
  const baselines = domains.baseline_options.filter((b) =>
    b.components.some((x) => x.available),
  );
  const [baselineId, setBaselineId] = useState(
    selected?.baseline_id ?? baselines[0]?.id ?? "",
  );
  const baseline = baselines.find((b) => b.id === baselineId);
  const [backupId, setBackupId] = useState(
    selected?.backup_id ??
      baseline?.components.find((x) => x.available)?.id ??
      "",
  );
  const [name, setName] = useState(selected?.name ?? "");
  const [enabled, setEnabled] = useState(selected?.enabled ?? true);
  const [inputs, setInputs] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      (selected?.entries ?? []).map((e) => [e.setting_id, inputValue(e.value)]),
    ),
  );
  const [catalog, setCatalog] = useState<OverrideCatalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [deploymentLocked, setDeploymentLocked] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [onlyChanged, setOnlyChanged] = useState(false);
  const [page, setPage] = useState(0);
  const [domainId, setDomainId] = useState(domains.results[0]?.id ?? "");
  const request = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      request.current?.abort();
    };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setCatalog(null);
    setError("");
    const query = new URLSearchParams({
      baseline_id: baselineId,
      backup_id: backupId,
    });
    void fetch(`/api/v1/security/override-catalog/?${query}`, {
      credentials: "same-origin",
      cache: "no-store",
      headers: { "X-IPMS-Tenant-ID": tenantId },
      signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
    })
      .then(async (response) => {
        const payload: unknown = response.ok ? await response.json() : null;
        if (controller.signal.aborted) return;
        if (
          !isOverrideCatalog(payload) ||
          payload.baseline_id !== baselineId ||
          payload.backup_id !== backupId
        ) {
          setError(c.load);
          return;
        }
        if (selected && payload.artifact_sha256 !== selected.artifact_sha256) {
          setError(c.mismatch);
          return;
        }
        setCatalog(payload);
      })
      .catch(() => {
        if (!controller.signal.aborted) setError(c.load);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [baselineId, backupId, tenantId, selected, c.load, c.mismatch]);
  const values = useMemo(() => {
    const entries: OverrideEntry[] = [];
    const invalid: string[] = [];
    for (const [id, text] of Object.entries(inputs)) {
      const setting = catalog?.settings.find((s) => s.setting_id === id);
      const value = setting ? parseOverrideInput(setting, text) : null;
      if (value === null) invalid.push(id);
      else if (!sameOverrideValue(value, setting?.baseline_value))
        entries.push({ setting_id: id, value });
    }
    entries.sort((a, b) => a.setting_id.localeCompare(b.setting_id));
    return { entries, invalid };
  }, [inputs, catalog]);
  const dirty =
    name !== (selected?.name ?? "") ||
    enabled !== (selected?.enabled ?? true) ||
    JSON.stringify(inputs) !==
      JSON.stringify(
        Object.fromEntries(
          (selected?.entries ?? []).map((e) => [
            e.setting_id,
            inputValue(e.value),
          ]),
        ),
      );
  useEffect(() => {
    onLocked(dirty || busy || uncertain || deploymentLocked);
    return () => onLocked(false);
  }, [dirty, busy, uncertain, deploymentLocked, onLocked]);
  const filtered =
    catalog?.settings.filter(
      (s) =>
        (!onlyChanged || Object.hasOwn(inputs, s.setting_id)) &&
        `${s.label} ${s.category} ${s.path} ${s.name}`
          .toLocaleLowerCase()
          .includes(search.toLocaleLowerCase()),
    ) ?? [];
  const pages = Math.max(1, Math.ceil(filtered.length / 30));
  const currentPage = Math.min(page, pages - 1);
  const reset = (id: string) =>
    setInputs((old) => {
      const next = { ...old };
      delete next[id];
      return next;
    });
  function discard() {
    setName(selected?.name ?? "");
    setEnabled(selected?.enabled ?? true);
    setInputs(
      Object.fromEntries(
        (selected?.entries ?? []).map((e) => [
          e.setting_id,
          inputValue(e.value),
        ]),
      ),
    );
    setError("");
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (
      !catalog ||
      busy ||
      uncertain ||
      values.invalid.length ||
      values.entries.length > 128 ||
      !name.trim()
    )
      return;
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError("");
    const body = selected
      ? {
          expected_revision: selected.revision,
          name: name.trim(),
          entries: values.entries,
          enabled,
        }
      : {
          name: name.trim(),
          baseline_id: baselineId,
          backup_id: backupId,
          entries: values.entries,
          enabled,
        };
    try {
      const response = await fetch(
        `/api/v1/security/overrides/${selected ? `${encodeURIComponent(selected.id)}/` : ""}`,
        {
          method: selected ? "PATCH" : "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify(body),
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(20000),
          ]),
        },
      );
      const payload: unknown = response.ok ? await response.json() : null;
      if (!mounted.current || controller.signal.aborted) return;
      if (!response.ok) {
        setUncertain(response.status >= 500);
        setError(response.status >= 500 ? c.uncertain : c.rejected);
        return;
      }
      if (
        !isSecurityOverride(payload) ||
        payload.baseline_id !== baselineId ||
        payload.backup_id !== backupId ||
        payload.artifact_sha256 !== catalog.artifact_sha256 ||
        (selected && payload.id !== selected.id)
      )
        throw new Error("invalid_receipt");
      onSaved(payload);
    } catch {
      if (mounted.current) {
        setUncertain(true);
        setError(c.uncertain);
      }
    } finally {
      if (mounted.current) {
        request.current = null;
        setBusy(false);
      }
    }
  }
  const domain = domains.results.find((d) => d.id === domainId);
  const locked = busy || uncertain || deploymentLocked;
  return (
    <>
      <section
        className={styles.panel}
        aria-label={c.title}
        aria-busy={loading || busy}
      >
        <form onSubmit={(event) => void save(event)}>
          <div className={styles.fields}>
            <label>
              {c.name}
              <input
                value={name}
                maxLength={80}
                required
                disabled={locked}
                onChange={(e) => setName(e.target.value)}
              />
            </label>
            <label>
              {c.baseline}
              <select
                value={baselineId}
                disabled={
                  locked || Boolean(selected) || Object.keys(inputs).length > 0
                }
                onChange={(e) => {
                  setBaselineId(e.target.value);
                  setBackupId(
                    baselines
                      .find((b) => b.id === e.target.value)
                      ?.components.find((x) => x.available)?.id ?? "",
                  );
                  setPage(0);
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
                value={backupId}
                disabled={
                  locked || Boolean(selected) || Object.keys(inputs).length > 0
                }
                onChange={(e) => {
                  setBackupId(e.target.value);
                  setPage(0);
                }}
              >
                {baseline?.components
                  .filter((x) => x.available)
                  .map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name}
                    </option>
                  ))}
              </select>
            </label>
          </div>
          <label className={styles.check}>
            <input
              type="checkbox"
              checked={enabled}
              disabled={locked}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            {c.enabled}
          </label>
          <p>{c.sparse}</p>
          <div className={styles.fields}>
            <label>
              {c.search}
              <input
                type="search"
                value={search}
                onChange={(e) => {
                  setSearch(e.target.value);
                  setPage(0);
                }}
              />
            </label>
          </div>
          <label className={styles.check}>
            <input
              type="checkbox"
              checked={onlyChanged}
              onChange={(e) => {
                setOnlyChanged(e.target.checked);
                setPage(0);
              }}
            />
            {c.changedOnly}
          </label>
          <p role="status">
            {c.count}: {values.entries.length} / 128
          </p>
          {loading ? <p role="status">{c.loading}</p> : null}
          <div className={styles.scroll}>
            <table className={styles.table}>
              <caption className="sr-only">{c.title}</caption>
              <thead>
                <tr>
                  <th scope="col">{c.setting}</th>
                  <th scope="col">{c.original}</th>
                  <th scope="col">{c.override}</th>
                </tr>
              </thead>
              <tbody>
                {filtered
                  .slice(currentPage * 30, (currentPage + 1) * 30)
                  .map((s) => {
                    const editing = Object.hasOwn(inputs, s.setting_id);
                    const invalid = values.invalid.includes(s.setting_id);
                    const valueLabel = `${c.override}: ${s.label}`;
                    return (
                      <tr
                        key={s.setting_id}
                        className={editing ? styles.changed : undefined}
                      >
                        <td>
                          <strong>{s.label}</strong>
                          <small>{s.category}</small>
                          <small>
                            {s.scope} · {s.kind}
                          </small>
                          {!s.editable ? (
                            <p>
                              {overrideReadonlyReason(
                                s.readonly_reason,
                                locale,
                              )}
                            </p>
                          ) : null}
                        </td>
                        <td>
                          {!s.editable &&
                          (displayValue(s.baseline_value)?.length ?? 0) >
                            200 ? (
                            <details>
                              <summary>{c.original}</summary>
                              <pre className={styles.value}>
                                {displayValue(s.baseline_value)}
                              </pre>
                            </details>
                          ) : (
                            <pre className={styles.value}>
                              {displayValue(s.baseline_value)}
                            </pre>
                          )}
                        </td>
                        <td>
                          {!s.editable ? (
                            "—"
                          ) : editing ? (
                            <>
                              {s.enum_options.length ? (
                                <select
                                  aria-label={valueLabel}
                                  value={inputs[s.setting_id]}
                                  disabled={locked}
                                  onChange={(e) =>
                                    setInputs((old) => ({
                                      ...old,
                                      [s.setting_id]: e.target.value,
                                    }))
                                  }
                                >
                                  {s.enum_options.map((o) => (
                                    <option
                                      key={JSON.stringify(o.value)}
                                      value={inputValue(o.value)}
                                    >
                                      {o.label}
                                    </option>
                                  ))}
                                </select>
                              ) : s.value_type === "string_list" ? (
                                <>
                                  <textarea
                                    aria-label={valueLabel}
                                    rows={3}
                                    value={inputs[s.setting_id]}
                                    aria-invalid={invalid}
                                    disabled={locked}
                                    onChange={(e) =>
                                      setInputs((old) => ({
                                        ...old,
                                        [s.setting_id]: e.target.value,
                                      }))
                                    }
                                  />
                                  <small>{c.listHint}</small>
                                </>
                              ) : (
                                <input
                                  aria-label={valueLabel}
                                  type={
                                    s.value_type === "integer"
                                      ? "number"
                                      : "text"
                                  }
                                  min={
                                    s.value_type === "integer"
                                      ? s.min
                                      : undefined
                                  }
                                  max={
                                    s.value_type === "integer"
                                      ? s.max
                                      : undefined
                                  }
                                  step={
                                    s.value_type === "integer" ? 1 : undefined
                                  }
                                  maxLength={s.max_length}
                                  value={inputs[s.setting_id]}
                                  aria-invalid={invalid}
                                  disabled={locked}
                                  onChange={(e) =>
                                    setInputs((old) => ({
                                      ...old,
                                      [s.setting_id]: e.target.value,
                                    }))
                                  }
                                />
                              )}
                              {invalid ? (
                                <p className={styles.error}>{c.invalid}</p>
                              ) : null}
                              <button
                                type="button"
                                className="outline-button"
                                disabled={locked}
                                onClick={() => reset(s.setting_id)}
                              >
                                {c.reset}
                              </button>
                            </>
                          ) : (
                            <button
                              type="button"
                              className="outline-button"
                              disabled={
                                locked || Object.keys(inputs).length >= 128
                              }
                              onClick={() =>
                                setInputs((old) => ({
                                  ...old,
                                  [s.setting_id]: inputValue(s.baseline_value),
                                }))
                              }
                            >
                              {c.edit}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
          {!loading && !filtered.length ? <p>{c.empty}</p> : null}
          <div className={styles.actions}>
            <button
              type="button"
              disabled={currentPage === 0}
              onClick={() => setPage(currentPage - 1)}
            >
              {c.previous}
            </button>
            <span>
              {currentPage + 1} / {pages}
            </span>
            <button
              type="button"
              disabled={currentPage + 1 >= pages}
              onClick={() => setPage(currentPage + 1)}
            >
              {c.next}
            </button>
          </div>
          {error ? (
            <p role="alert" className={styles.error}>
              {error}
            </p>
          ) : null}
          {uncertain ? (
            <button type="button" onClick={() => window.location.reload()}>
              {c.reload}
            </button>
          ) : null}
          <div className={styles.actions}>
            <button
              type="submit"
              className="primary-button"
              disabled={
                locked ||
                loading ||
                !catalog ||
                !dirty ||
                !name.trim() ||
                values.invalid.length > 0 ||
                values.entries.length > 128
              }
            >
              {c.save}
            </button>
            <button
              type="button"
              className="outline-button"
              disabled={locked || !dirty}
              onClick={discard}
            >
              {c.discard}
            </button>
          </div>
        </form>
      </section>
      {selected ? (
        <section className={styles.panel} aria-label={c.deployment}>
          <h2>{c.deployment}</h2>
          <p>{c.priority}</p>
          <p>{c.agent}</p>
          {dirty ? <p>{c.saveFirst}</p> : null}
          {!selected.enabled ? <p>{c.disabled}</p> : null}
          <div className={styles.fields}>
            <label>
              {c.domain}
              <select
                value={domainId}
                disabled={dirty || locked}
                onChange={(e) => setDomainId(e.target.value)}
              >
                {domains.results.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.domain_name}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {domain ? (
            <DomainGpoImports
              settings={domain}
              catalog={domains}
              tenantId={tenantId}
              csrfToken={csrfToken}
              canImport={canImport}
              configurationDirty={dirty || busy || uncertain}
              onWorkflowLocked={setDeploymentLocked}
              locale={locale}
              copy={getDomainSecurityCopy(locale)}
              override={selected}
            />
          ) : (
            <p>{c.noDomains}</p>
          )}
        </section>
      ) : null}
    </>
  );
}
