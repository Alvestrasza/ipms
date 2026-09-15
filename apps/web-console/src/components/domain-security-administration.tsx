/**
 * File Name: domain-security-administration.tsx
 * Version: v0.1.2 | Created: 2026-09-14 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Edit tenant domain plans with accessible ordering and explicit persistence.
 */
"use client";

import {
  ArrowDown,
  ArrowUp,
  GripVertical,
  Plus,
  RefreshCw,
} from "lucide-react";
import type { Route } from "next";
import Link from "next/link";
import { type FormEvent, useEffect, useId, useRef, useState } from "react";
import type { Locale } from "@/i18n/config";
import type { DomainSecurityCopy } from "@/i18n/domain-security-copy";
import {
  type DomainSecurityCatalog,
  type DomainSecuritySettings,
  SECURITY_TIERS,
  type SecurityTier,
} from "@/lib/domain-security-types";
import {
  domainSettingsErrorKey,
  isDomainSettings,
  previewGpoName,
} from "@/lib/domain-security-validation";
import { DomainGpoImports } from "./domain-gpo-imports";
import styles from "./domain-security-administration.module.css";
import {
  GpoApprovalPolicySettings,
  GpoDomainAuthorizationSettings,
} from "./gpo-approval-settings";

type Draft = {
  domain: string;
  ous: Record<SecurityTier, string>;
  template: string;
  order: string[];
};

function draftFrom(
  settings: DomainSecuritySettings | null,
  catalog: DomainSecurityCatalog,
): Draft {
  return {
    domain: settings?.domain_name ?? "",
    ous: {
      "0": settings?.tier_ous["0"].join("\n") ?? "",
      "1": settings?.tier_ous["1"].join("\n") ?? "",
      "2": settings?.tier_ous["2"].join("\n") ?? "",
    },
    template: settings?.gpo_name_template ?? catalog.default_name_template,
    order: settings
      ? [...settings.baseline_order]
      : catalog.baseline_options.map((option) => option.id),
  };
}

type WorkspaceProps = {
  initialCatalog: DomainSecurityCatalog | null;
  tenantId: string;
  csrfToken: string;
  canImport?: boolean;
  preferredBaselineId?: string;
  locale: Locale;
  copy: DomainSecurityCopy;
};

export function DomainSecurityAdministration(props: WorkspaceProps) {
  return <DomainSettingsWorkspace {...props} mode="domain" />;
}

export function BaselineGpoDeployment(props: WorkspaceProps) {
  return <DomainSettingsWorkspace {...props} mode="deployment" />;
}

function DomainSettingsWorkspace({
  initialCatalog,
  tenantId,
  csrfToken,
  canImport = false,
  preferredBaselineId,
  locale,
  copy,
  mode,
}: WorkspaceProps & { mode: "domain" | "deployment" }) {
  const [catalog, setCatalog] = useState(initialCatalog);
  const [selectedId, setSelectedId] = useState(
    initialCatalog?.results[0]?.id ?? "",
  );
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [authorizationLocked, setAuthorizationLocked] = useState(false);
  const [notice, setNotice] = useState("");
  const settings =
    catalog?.results.find((item) => item.id === selectedId) ?? null;
  const locked = dirty || busy || uncertain || authorizationLocked;

  function saved(value: DomainSecuritySettings) {
    setCatalog((previous) =>
      previous
        ? {
            ...previous,
            results: previous.results.some((item) => item.id === value.id)
              ? previous.results.map((item) =>
                  item.id === value.id ? value : item,
                )
              : [...previous.results, value],
          }
        : previous,
    );
    setSelectedId(value.id);
    setDirty(false);
    setNotice(copy.saved);
  }

  return (
    <div className={styles.content}>
      {mode === "domain" ? (
        <p className={styles.notice}>{copy.boundary}</p>
      ) : null}
      {notice ? (
        <p className={styles.success} role="status">
          {notice}
        </p>
      ) : null}
      {!catalog ? (
        <div className={styles.panel}>
          <p role="alert">
            {mode === "domain" ? copy.unavailable : copy.deploymentUnavailable}
          </p>
          <button
            className={styles.button}
            type="button"
            onClick={() => window.location.reload()}
          >
            <RefreshCw size={16} aria-hidden="true" />
            {copy.reload}
          </button>
        </div>
      ) : (
        <>
          {mode === "domain" ? (
            <GpoApprovalPolicySettings
              tenantId={tenantId}
              csrfToken={csrfToken}
              locale={locale}
            />
          ) : null}
          <section
            className={styles.panel}
            aria-labelledby="configured-domains-heading"
          >
            <div className={styles.header}>
              <h2 id="configured-domains-heading">
                {mode === "domain" ? copy.domains : copy.deploymentTitle}
              </h2>
              <div className={styles.actions}>
                {mode === "domain" ? (
                  <button
                    className={styles.button}
                    type="button"
                    disabled={locked}
                    onClick={() => {
                      setSelectedId("");
                      setNotice("");
                    }}
                  >
                    <Plus size={16} aria-hidden="true" />
                    {copy.add}
                  </button>
                ) : (
                  <Link
                    className={styles.button}
                    href={`/${locale}/administration/security/domains` as Route}
                  >
                    {copy.configureDomains}
                  </Link>
                )}
                <button
                  className={styles.button}
                  type="button"
                  disabled={busy}
                  onClick={() => window.location.reload()}
                >
                  <RefreshCw size={16} aria-hidden="true" />
                  {copy.reload}
                </button>
              </div>
            </div>
            {mode === "deployment" ? (
              catalog.results.length ? (
                <>
                  <label className={styles.field}>
                    {copy.policyDomain}
                    <select
                      value={selectedId}
                      disabled={locked}
                      onChange={(event) => {
                        setSelectedId(event.target.value);
                        setNotice("");
                      }}
                    >
                      {catalog.results.map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.domain_name}
                        </option>
                      ))}
                    </select>
                  </label>
                  <p className={styles.hint}>{copy.deploymentDescription}</p>
                  {settings ? (
                    <p className={styles.hint}>
                      {copy.revision}: {settings.revision}
                    </p>
                  ) : null}
                </>
              ) : (
                <p className={styles.hint}>{copy.deploymentEmpty}</p>
              )
            ) : catalog.results.length ? (
              <ul className={styles.domainList}>
                {catalog.results.map((item) => (
                  <li key={item.id}>
                    <button
                      type="button"
                      className={styles.domainButton}
                      aria-pressed={selectedId === item.id}
                      disabled={locked}
                      onClick={() => {
                        setSelectedId(item.id);
                        setNotice("");
                      }}
                    >
                      <strong>{item.domain_name}</strong>
                      <small>
                        {copy.revision} {item.revision}
                      </small>
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className={styles.hint}>{copy.empty}</p>
            )}
            {locked ? <p className={styles.hint}>{copy.discardHint}</p> : null}
          </section>
          {mode === "domain" ? (
            <DomainSettingsEditor
              key={`editor:${settings?.id ?? "new"}:${settings?.revision ?? 0}`}
              catalog={catalog}
              settings={settings}
              tenantId={tenantId}
              csrfToken={csrfToken}
              copy={copy}
              onSaved={saved}
              onDirty={setDirty}
              onBusy={setBusy}
              onUncertain={setUncertain}
            />
          ) : null}
          {mode === "deployment" && settings ? (
            <DomainGpoImports
              key={`imports:${settings.id}:${settings.revision}:${preferredBaselineId ?? ""}`}
              settings={settings}
              catalog={catalog}
              tenantId={tenantId}
              csrfToken={csrfToken}
              canImport={canImport}
              preferredBaselineId={preferredBaselineId}
              configurationDirty={locked}
              locale={locale}
              copy={copy}
            />
          ) : null}
          {mode === "domain" && settings ? (
            <GpoDomainAuthorizationSettings
              key={`authorization:${tenantId}:${settings.id}`}
              domainId={settings.id}
              domainName={settings.domain_name}
              tenantId={tenantId}
              csrfToken={csrfToken}
              locale={locale}
              onLocked={setAuthorizationLocked}
            />
          ) : null}
        </>
      )}
    </div>
  );
}

function DomainSettingsEditor({
  catalog,
  settings,
  tenantId,
  csrfToken,
  copy,
  onSaved,
  onDirty,
  onBusy,
  onUncertain,
}: {
  catalog: DomainSecurityCatalog;
  settings: DomainSecuritySettings | null;
  tenantId: string;
  csrfToken: string;
  copy: DomainSecurityCopy;
  onSaved: (settings: DomainSecuritySettings) => void;
  onDirty: (dirty: boolean) => void;
  onBusy: (busy: boolean) => void;
  onUncertain: (uncertain: boolean) => void;
}) {
  const formId = useId();
  const [draft, setDraft] = useState(() => draftFrom(settings, catalog));
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [error, setError] = useState("");
  const [moveNotice, setMoveNotice] = useState("");
  const request = useRef<AbortController | null>(null);
  const dragging = useRef<string | null>(null);
  const mounted = useRef(false);
  const dirty =
    JSON.stringify(draft) !== JSON.stringify(draftFrom(settings, catalog));
  const baselineById = new Map(
    catalog.baseline_options.map((item) => [item.id, item]),
  );

  useEffect(() => {
    onDirty(dirty);
  }, [dirty, onDirty]);
  useEffect(() => {
    onUncertain(uncertain);
  }, [uncertain, onUncertain]);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      request.current?.abort();
      onBusy(false);
    };
  }, [onBusy]);

  function move(id: string, targetIndex: number) {
    if (busy) return;
    const currentIndex = draft.order.indexOf(id);
    if (
      currentIndex < 0 ||
      targetIndex < 0 ||
      targetIndex >= draft.order.length ||
      currentIndex === targetIndex
    )
      return;
    const order = [...draft.order];
    order.splice(currentIndex, 1);
    order.splice(targetIndex, 0, id);
    setDraft((previous) => ({ ...previous, order }));
    setMoveNotice(
      copy.moved
        .replace("{name}", baselineById.get(id)?.name ?? id)
        .replace("{position}", String(targetIndex + 1))
        .replace("{total}", String(order.length)),
    );
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (request.current || uncertain || (settings && !dirty)) return;
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    onBusy(true);
    setError("");
    const current = () => mounted.current && request.current === controller;
    const paths = (value: string) =>
      value
        .split(/\r?\n/)
        .map((path) => path.trim())
        .filter(Boolean);
    try {
      const response = await fetch(
        `/api/v1/security/domain-settings/${settings ? `${encodeURIComponent(settings.id)}/` : ""}`,
        {
          method: settings ? "PUT" : "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(15_000),
          ]),
          body: JSON.stringify({
            domain_name: draft.domain.trim(),
            tier_ous: {
              "0": paths(draft.ous["0"]),
              "1": paths(draft.ous["1"]),
              "2": paths(draft.ous["2"]),
            },
            gpo_name_template: draft.template.trim(),
            baseline_order: draft.order,
            ...(settings ? { expected_revision: settings.revision } : {}),
          }),
        },
      );
      if (!current()) return;
      if (!response.ok) {
        const detail =
          response.status === 400
            ? domainSettingsErrorKey(await response.json().catch(() => null))
            : null;
        if (!current()) return;
        const message =
          response.status === 409
            ? copy.conflict
            : response.status === 401
              ? copy.sessionExpired
              : response.status === 403
                ? copy.permission
                : response.status === 400
                  ? detail
                    ? copy.validation[detail]
                    : copy.invalid
                  : copy.uncertain;
        setUncertain(response.status === 409 || response.status >= 500);
        setError(message);
        return;
      }
      const payload: unknown = await response.json();
      if (
        !isDomainSettings(payload) ||
        (settings && payload.id !== settings.id)
      )
        throw new Error("invalid_receipt");
      if (!current()) return;
      onSaved(payload);
    } catch {
      if (current()) {
        setUncertain(true);
        setError(copy.uncertain);
      }
    } finally {
      if (current()) {
        request.current = null;
        setBusy(false);
        onBusy(false);
      }
    }
  }

  return (
    <form className={styles.content} onSubmit={submit} aria-busy={busy}>
      <section
        className={styles.panel}
        aria-labelledby="domain-settings-heading"
      >
        <div className={styles.header}>
          <h2 id="domain-settings-heading">
            {settings ? copy.edit : copy.add}
          </h2>
          {dirty ? <span className={styles.badge}>{copy.unsaved}</span> : null}
        </div>
        <label className={styles.field}>
          {copy.domain}
          <input
            name="domain_name"
            type="text"
            required
            maxLength={253}
            list="discovered-security-domains"
            disabled={busy || Boolean(settings)}
            value={draft.domain}
            onChange={(event) =>
              setDraft({ ...draft, domain: event.target.value })
            }
            aria-describedby="domain-name-hint"
          />
        </label>
        <datalist id="discovered-security-domains">
          {catalog.discovered_domains.map((domain) => (
            <option value={domain} key={domain} />
          ))}
        </datalist>
        <p className={styles.hint} id="domain-name-hint">
          {copy.domainHint}
        </p>
        {settings ? (
          <p className={styles.hint}>
            {copy.revision}: {settings.revision}
          </p>
        ) : null}
      </section>
      <section className={styles.panel} aria-labelledby="tier-mappings-heading">
        <h2 id="tier-mappings-heading">{copy.mappings}</h2>
        <p className={styles.hint} id="tier-mappings-hint">
          {copy.mappingHint}
        </p>
        <div className={styles.tierGrid}>
          {SECURITY_TIERS.map((tier) => (
            <div className={styles.field} key={tier}>
              <label htmlFor={`${formId}-tier-${tier}-ous`}>
                Tier {tier} OUs
              </label>
              <textarea
                id={`${formId}-tier-${tier}-ous`}
                name={`tier_${tier}_ous`}
                rows={5}
                maxLength={24000}
                disabled={busy}
                value={draft.ous[tier]}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    ous: { ...draft.ous, [tier]: event.target.value },
                  })
                }
                aria-describedby="tier-mappings-hint"
                spellCheck={false}
              />
            </div>
          ))}
        </div>
        <p className={styles.badge}>{copy.unverified}</p>
        <p className={styles.hint}>{copy.verificationHint}</p>
      </section>
      <section
        className={styles.panel}
        aria-labelledby="domain-gpo-configuration-heading"
      >
        <h2 id="domain-gpo-configuration-heading">{copy.policyTitle}</h2>
        <p className={styles.hint}>{copy.policyDescription}</p>
        <section
          className={styles.configurationSection}
          aria-labelledby="gpo-naming-heading"
        >
          <h3 id="gpo-naming-heading">{copy.naming}</h3>
          <label className={styles.field}>
            {copy.nameTemplate}
            <input
              name="gpo_name_template"
              type="text"
              required
              maxLength={160}
              disabled={busy}
              value={draft.template}
              onChange={(event) =>
                setDraft({ ...draft, template: event.target.value })
              }
              aria-describedby="gpo-template-hint"
              spellCheck={false}
            />
          </label>
          <p className={styles.hint} id="gpo-template-hint">
            {copy.tokens}
          </p>
          <section
            className={styles.preview}
            aria-labelledby="gpo-name-preview-heading"
          >
            <h4 id="gpo-name-preview-heading">{copy.preview}</h4>
            <p className={styles.hint}>{copy.exampleHint}</p>
            <ul className={styles.previews}>
              {SECURITY_TIERS.map((tier) => {
                const confirmed =
                  settings?.gpo_name_template === draft.template
                    ? settings.name_previews.find((item) => item.tier === tier)
                    : null;
                return (
                  <li key={tier}>
                    <strong>Tier {tier}</strong>
                    <span>
                      {copy.production}:{" "}
                      <code>
                        {confirmed?.production ??
                          previewGpoName(draft.template, tier) ??
                          copy.invalidPreview}
                      </code>
                    </span>
                    {confirmed?.pilot ? (
                      <span>
                        {copy.pilot}: <code>{confirmed.pilot}</code>
                      </span>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </section>
        </section>
        <section
          className={styles.configurationSection}
          aria-labelledby="baseline-order-heading"
        >
          <h3 id="baseline-order-heading">{copy.order}</h3>
          <p className={styles.hint} id="baseline-order-hint">
            {copy.orderHint}
          </p>
          <ol
            className={styles.orderList}
            aria-label={copy.order}
            aria-describedby="baseline-order-hint"
          >
            {draft.order.map((id, index) => {
              const baseline = baselineById.get(id);
              const name = baseline?.name ?? id;
              return (
                <li
                  key={id}
                  data-baseline-id={id}
                  onDragOver={(event) => {
                    if (dragging.current && !busy) {
                      event.preventDefault();
                      event.dataTransfer.dropEffect = "move";
                    }
                  }}
                  onDrop={(event) => {
                    event.preventDefault();
                    if (dragging.current) move(dragging.current, index);
                    dragging.current = null;
                  }}
                >
                  <span className={styles.position} aria-hidden="true">
                    {index + 1}
                  </span>
                  <button
                    className={styles.dragHandle}
                    type="button"
                    draggable={!busy}
                    disabled={busy}
                    aria-label={`${copy.drag}: ${name}`}
                    onDragStart={(event) => {
                      dragging.current = id;
                      event.dataTransfer.effectAllowed = "move";
                      event.dataTransfer.setData("text/plain", id);
                    }}
                    onDragEnd={() => {
                      dragging.current = null;
                    }}
                  >
                    <GripVertical size={20} aria-hidden="true" />
                  </button>
                  <div className={styles.layerLabel}>
                    <strong>{name}</strong>
                    <small>
                      {baseline?.provider} · {baseline?.revision}
                    </small>
                  </div>
                  <div className={styles.actions}>
                    <button
                      className={styles.iconButton}
                      type="button"
                      disabled={busy || index === 0}
                      aria-label={`${copy.moveUp}: ${name}`}
                      onClick={() => move(id, index - 1)}
                    >
                      <ArrowUp size={17} aria-hidden="true" />
                    </button>
                    <button
                      className={styles.iconButton}
                      type="button"
                      disabled={busy || index === draft.order.length - 1}
                      aria-label={`${copy.moveDown}: ${name}`}
                      onClick={() => move(id, index + 1)}
                    >
                      <ArrowDown size={17} aria-hidden="true" />
                    </button>
                  </div>
                </li>
              );
            })}
          </ol>
          <p className={styles.hint}>{copy.providersHint}</p>
          <p role="status" aria-live="polite" className={styles.hint}>
            {moveNotice}
          </p>
        </section>
      </section>
      {error ? (
        <p className={styles.error} role="alert">
          {error}
        </p>
      ) : null}
      <div className={styles.actions}>
        <button
          className={styles.primaryButton}
          type="submit"
          disabled={busy || uncertain || (Boolean(settings) && !dirty)}
        >
          {busy ? copy.saving : copy.save}
        </button>
        <button
          className={styles.button}
          type="button"
          disabled={busy || !dirty}
          onClick={() => {
            setDraft(draftFrom(settings, catalog));
            setMoveNotice("");
          }}
        >
          {copy.reset}
        </button>
      </div>
    </form>
  );
}
