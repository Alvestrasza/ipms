/**
 * File Name: wsus-console.tsx
 * Version: v0.1.0
 * Created: 2026-09-13 | Modified: 2026-09-13
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Manage WSUS reception sources and inspect paged server comparison.
 */
"use client";

import type { Route } from "next";
import Link from "next/link";
import { type FormEvent, useRef, useState } from "react";
import type { Locale } from "@/i18n/config";
import type { WsusCopy } from "@/i18n/wsus-copy";
import type {
  WsusComparison,
  WsusServer,
  WsusServerUpdates,
  WsusSource,
} from "@/lib/wsus-types";
import { WsusComparisonView, WsusServerUpdatesView } from "./wsus-comparison";
import styles from "./wsus-console.module.css";
import { WsusEndpointFields } from "./wsus-endpoint-fields";

export function WsusConsole({
  initialSources,
  initialComparison,
  initialSourceId,
  initialObservedAt,
  available,
  tenantId,
  csrfToken,
  canManage,
  configurationOnly = false,
  locale,
  copy,
}: {
  initialSources: WsusSource[];
  initialComparison: WsusComparison | null;
  initialSourceId?: string;
  initialObservedAt: number;
  available: boolean;
  tenantId: string;
  csrfToken: string;
  canManage: boolean;
  configurationOnly?: boolean;
  locale: Locale;
  copy: WsusCopy;
}) {
  const [sources, setSources] = useState(initialSources);
  const [selectedId, setSelectedId] = useState(
    initialSourceId ?? initialSources[0]?.id ?? "",
  );
  const [comparison, setComparison] = useState(initialComparison);
  const [observedAt, setObservedAt] = useState(initialObservedAt);
  const [details, setDetails] = useState<{
    server: WsusServer;
    data: WsusServerUpdates;
  } | null>(null);
  const [token, setToken] = useState<{
    sourceId: string;
    value: string;
  } | null>(null);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(available ? "" : copy.unavailable);
  const [notice, setNotice] = useState("");
  const pending = useRef(false);
  const selected = sources.find((source) => source.id === selectedId);
  const manageSources = canManage && configurationOnly;
  const sourceQuery = selectedId
    ? `?source=${encodeURIComponent(selectedId)}`
    : "";

  const date = (value: string | null) => {
    if (!value) return copy.unknown;
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime())
      ? copy.unknown
      : new Intl.DateTimeFormat(locale, {
          dateStyle: "medium",
          timeStyle: "short",
          timeZone: "UTC",
        }).format(parsed);
  };

  async function request<T>(
    path: string,
    method = "GET",
    body?: Record<string, string | boolean | number>,
  ): Promise<T> {
    const response = await fetch(`/api/v1/update-sources/${path}`, {
      method,
      credentials: "same-origin",
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken,
        "X-IPMS-Tenant-ID": tenantId,
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (!response.ok)
      throw new Error(
        response.status === 401
          ? copy.sessionExpired
          : response.status === 403
            ? copy.permission
            : response.status === 400
              ? copy.invalid
              : method === "GET"
                ? copy.unavailable
                : copy.actionFailed,
      );
    return response.json() as Promise<T>;
  }

  async function perform(operation: () => Promise<void>, mutation = false) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await operation();
    } catch (caught) {
      const known = [
        copy.sessionExpired,
        copy.permission,
        copy.invalid,
        copy.unavailable,
        copy.actionFailed,
        copy.endpointInvalid,
      ];
      setError(
        caught instanceof Error && known.includes(caught.message)
          ? caught.message
          : mutation
            ? copy.actionFailed
            : copy.unavailable,
      );
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }

  async function loadComparison(sourceId: string, page = 1) {
    setComparison(null);
    setDetails(null);
    if (sourceId && !configurationOnly) {
      const result = await request<WsusComparison>(
        `${encodeURIComponent(sourceId)}/comparison/?page=${page}`,
      );
      if (result.source.id !== sourceId || !Array.isArray(result.results))
        throw new Error(copy.unavailable);
      setComparison(result);
      setObservedAt(Date.now());
    }
  }

  async function refresh() {
    setComparison(null);
    setDetails(null);
    const result = await request<WsusSource[]>("");
    if (!Array.isArray(result)) throw new Error(copy.unavailable);
    setSources(result);
    const nextId = result.some((source) => source.id === selectedId)
      ? selectedId
      : (result[0]?.id ?? "");
    if (nextId !== selectedId) setToken(null);
    setSelectedId(nextId);
    await loadComparison(nextId);
  }

  function selectSource(sourceId: string) {
    if (pending.current) return;
    setSelectedId(sourceId);
    setToken(null);
    setConfirmRotate(false);
    void perform(() => loadComparison(sourceId));
  }

  function createSource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!manageSources || pending.current) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const name = String(fields.get("name") ?? "").trim();
    const scope = String(fields.get("scope") ?? "").trim();
    const endpoint = endpointDocument(fields);
    if (
      !name ||
      name.length > 128 ||
      !scope ||
      scope.length > 255 ||
      !endpoint
    ) {
      setError(copy.invalid);
      return;
    }
    void perform(async () => {
      const result = await request<WsusSource & { token: string }>("", "POST", {
        name,
        scope,
        ...endpoint,
      });
      const { token: secret, ...source } = result;
      setSources((current) => [...current, source]);
      setSelectedId(source.id);
      setComparison(null);
      setDetails(null);
      setToken({ sourceId: source.id, value: secret });
      setConfirmRotate(false);
      setNotice(copy.saved);
      form.reset();
      await loadComparison(source.id);
    }, true);
  }

  function toggleSource() {
    if (!manageSources || !selected) return;
    void perform(async () => {
      const source = await request<WsusSource>(
        `${encodeURIComponent(selected.id)}/`,
        "PATCH",
        { enabled: !selected.enabled },
      );
      setSources((current) =>
        current.map((item) => (item.id === source.id ? source : item)),
      );
      setNotice(copy.saved);
      await loadComparison(source.id);
    }, true);
  }

  function rotateToken() {
    if (!manageSources || !selected || !confirmRotate) return;
    void perform(async () => {
      setToken(null);
      const result = await request<{ token: string }>(
        `${encodeURIComponent(selected.id)}/rotate-token/`,
        "POST",
      );
      setToken({ sourceId: selected.id, value: result.token });
      setConfirmRotate(false);
      setNotice(copy.saved);
    }, true);
  }

  function endpointDocument(fields: FormData) {
    const wsus_host = String(fields.get("wsus_host") ?? "").trim();
    const wsus_port = Number(fields.get("wsus_port"));
    if (
      !wsus_host ||
      wsus_host.length > 253 ||
      /[\s/?#@[\]]/.test(wsus_host) ||
      !Number.isInteger(wsus_port) ||
      wsus_port < 1 ||
      wsus_port > 65535
    )
      return null;
    return {
      wsus_host,
      wsus_port,
      wsus_use_ssl: fields.get("wsus_use_ssl") === "on",
    };
  }

  function saveEndpoint(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!manageSources || !selected || pending.current) return;
    const endpoint = endpointDocument(new FormData(event.currentTarget));
    if (!endpoint) {
      setError(copy.endpointInvalid);
      return;
    }
    void perform(async () => {
      const source = await request<WsusSource>(
        `${encodeURIComponent(selected.id)}/`,
        "PATCH",
        endpoint,
      );
      setSources((current) =>
        current.map((item) => (item.id === source.id ? source : item)),
      );
      setComparison(null);
      setDetails(null);
      setNotice(copy.endpointSaved);
    }, true);
  }

  function loadDetails(server: WsusServer, page = 1) {
    if (!selected || pending.current) return;
    void perform(async () => {
      setDetails(null);
      const data = await request<WsusServerUpdates>(
        `${encodeURIComponent(selected.id)}/servers/${encodeURIComponent(server.server_id)}/updates/?page=${page}`,
      );
      if (!Array.isArray(data.results)) throw new Error(copy.unavailable);
      setDetails({ server, data });
    });
  }

  return (
    <>
      <p className="preview-notice">
        {configurationOnly ? copy.configurationBoundary : copy.boundary}
      </p>
      <div className={styles.pageActions}>
        {configurationOnly ? (
          <Link
            className="outline-button"
            href={`/${locale}/updates/wsus${sourceQuery}` as Route}
          >
            {copy.openComparison}
          </Link>
        ) : canManage ? (
          <Link
            className="outline-button"
            href={
              `/${locale}/administration/updates/wsus${sourceQuery}` as Route
            }
          >
            {copy.configure}
          </Link>
        ) : null}
      </div>
      {error ? (
        <p role="alert" className="form-error">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p role="status" className="preview-notice preview-notice--live">
          {notice}
        </p>
      ) : null}
      {busy ? <p role="status">{copy.loading}</p> : null}
      {token ? (
        <section className={styles.token} aria-labelledby="wsus-token-heading">
          <h2 id="wsus-token-heading">{copy.token}</h2>
          <p>{copy.tokenHint}</p>
          <p>
            {copy.sourceId}: <code>{token.sourceId}</code>
          </p>
          <label className={styles.field} htmlFor="wsus-reception-token">
            {copy.token}
            <textarea
              id="wsus-reception-token"
              readOnly
              rows={2}
              value={token.value}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <div className={styles.actions}>
            <button
              type="button"
              className="outline-button"
              onClick={() => setToken(null)}
            >
              {copy.dismissToken}
            </button>
          </div>
        </section>
      ) : null}
      <section
        className={`inventory-panel ${styles.panel}`}
        aria-labelledby="wsus-sources-heading"
        aria-busy={busy}
      >
        <div className="panel__header">
          <h2 id="wsus-sources-heading">{copy.sources}</h2>
          <button
            className="outline-button"
            type="button"
            disabled={busy}
            onClick={() => void perform(refresh)}
          >
            {configurationOnly ? copy.reloadConfiguration : copy.reload}
          </button>
        </div>
        {sources.length ? (
          <div className={styles.source}>
            <label className={styles.field} htmlFor="wsus-source">
              {copy.source}
              <select
                id="wsus-source"
                aria-label={copy.source}
                value={selectedId}
                disabled={busy}
                onChange={(event) => selectSource(event.target.value)}
              >
                {sources.map((source) => (
                  <option key={source.id} value={source.id}>
                    {source.name} ·{" "}
                    {source.enabled ? copy.enabled : copy.disabled}
                  </option>
                ))}
              </select>
            </label>
            {selected ? (
              <>
                <dl className={styles.summary}>
                  <div>
                    <dt>{copy.sourceId}</dt>
                    <dd>{selected.id}</dd>
                  </div>
                  <div>
                    <dt>{copy.scope}</dt>
                    <dd>{selected.scope}</dd>
                  </div>
                  <div>
                    <dt>{copy.observed}</dt>
                    <dd>{date(selected.last_observed_at)}</dd>
                  </div>
                  <div>
                    <dt>{copy.received}</dt>
                    <dd>{date(selected.last_received_at)}</dd>
                  </div>
                </dl>
                {configurationOnly && selected.wsus_host === "" ? (
                  <p className="preview-notice">{copy.endpointNotConfigured}</p>
                ) : null}
                {!selected.enabled ? (
                  <p className="preview-notice">{copy.disabledHint}</p>
                ) : null}
                {manageSources ? (
                  <>
                    <form
                      className={styles.endpointForm}
                      key={`${selected.id}:${selected.wsus_host}:${selected.wsus_port}:${selected.wsus_use_ssl}`}
                      onSubmit={saveEndpoint}
                      aria-labelledby="wsus-server-settings-heading"
                    >
                      <h3 id="wsus-server-settings-heading">
                        {copy.endpointSettings}
                      </h3>
                      <WsusEndpointFields
                        prefix="wsus-edit"
                        copy={copy}
                        disabled={busy}
                        source={selected}
                      />
                      <p className={styles.endpointHint}>
                        {copy.endpointChangeHint}
                      </p>
                      <div className={styles.actions}>
                        <button
                          className="outline-button"
                          type="submit"
                          disabled={busy}
                        >
                          {copy.saveEndpoint}
                        </button>
                      </div>
                    </form>
                    <div className={styles.actions}>
                      <button
                        className="outline-button"
                        type="button"
                        disabled={busy}
                        onClick={toggleSource}
                      >
                        {selected.enabled ? copy.disable : copy.enable}
                      </button>
                      <button
                        className="outline-button"
                        type="button"
                        disabled={busy || confirmRotate}
                        onClick={() => setConfirmRotate(true)}
                      >
                        {copy.rotate}
                      </button>
                    </div>
                    {confirmRotate ? (
                      <div className={styles.confirmation}>
                        <p>{copy.rotateHint}</p>
                        <div className={styles.actions}>
                          <button
                            className="outline-button"
                            type="button"
                            disabled={busy}
                            onClick={rotateToken}
                          >
                            {copy.confirmRotate}
                          </button>
                          <button
                            className="outline-button"
                            type="button"
                            disabled={busy}
                            onClick={() => setConfirmRotate(false)}
                          >
                            {copy.cancel}
                          </button>
                        </div>
                      </div>
                    ) : null}
                  </>
                ) : null}
              </>
            ) : null}
          </div>
        ) : (
          <p className="table-empty">{copy.noSources}</p>
        )}
        {manageSources ? (
          <form
            className={styles.form}
            onSubmit={createSource}
            aria-labelledby="wsus-create-heading"
          >
            <h3 id="wsus-create-heading" className={styles.fullWidth}>
              {copy.create}
            </h3>
            <label className={styles.field} htmlFor="wsus-name">
              {copy.name}
              <input
                id="wsus-name"
                name="name"
                maxLength={128}
                required
                disabled={busy}
                autoComplete="off"
              />
            </label>
            <label className={styles.field} htmlFor="wsus-scope">
              {copy.scope}
              <input
                id="wsus-scope"
                name="scope"
                maxLength={255}
                required
                disabled={busy}
                autoComplete="off"
                aria-describedby="wsus-scope-hint"
                aria-label={copy.scope}
              />
              <small id="wsus-scope-hint">{copy.scopeHint}</small>
            </label>
            <WsusEndpointFields
              prefix="wsus-create"
              copy={copy}
              disabled={busy}
            />
            <button className="outline-button" type="submit" disabled={busy}>
              {copy.create}
            </button>
          </form>
        ) : null}
      </section>
      {!configurationOnly &&
      comparison &&
      comparison.source.id === selectedId ? (
        <WsusComparisonView
          data={comparison}
          copy={copy}
          busy={busy}
          date={date}
          observedAt={observedAt}
          onPage={(page) =>
            void perform(() => loadComparison(selectedId, page))
          }
          onDetails={loadDetails}
        />
      ) : null}
      {!configurationOnly && details ? (
        <WsusServerUpdatesView
          data={details.data}
          server={details.server}
          copy={copy}
          date={date}
          hasWsusClients={(comparison?.snapshot?.computer_count ?? 0) > 0}
          busy={busy}
          onPage={(page) => loadDetails(details.server, page)}
          onClose={() => setDetails(null)}
        />
      ) : null}
    </>
  );
}
