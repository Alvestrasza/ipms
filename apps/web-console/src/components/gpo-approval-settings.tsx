/**
 * File Name: gpo-approval-settings.tsx
 * Version: v0.1.0 | Created: 2026-09-15 | Modified: 2026-09-15
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Save explicit revision-protected approval rules and domain/Tier grants.
 */
"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { Locale } from "@/i18n/config";
import {
  type GpoApprovalCopy,
  getGpoApprovalCopy,
} from "@/i18n/gpo-approval-copy";
import { SECURITY_TIERS, type SecurityTier } from "@/lib/domain-security-types";
import {
  type GpoApprovalPolicy,
  type GpoDomainAuthorization,
  isGpoApprovalPolicy,
  isGpoDomainAuthorization,
} from "@/lib/gpo-approval-types";
import styles from "./domain-security-administration.module.css";

type ScopeProps = { tenantId: string; csrfToken: string; locale: Locale };

function useApprovalDocument<T extends { revision: number }>(
  endpoint: string,
  validate: (value: unknown) => value is T,
  { tenantId, csrfToken }: ScopeProps,
  copy: GpoApprovalCopy,
) {
  const [data, setData] = useState<T | null>(null);
  const [busy, setBusy] = useState(true);
  const [uncertain, setUncertain] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const request = useRef<AbortController | null>(null);
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      request.current?.abort();
    };
  }, []);

  const load = useCallback(async () => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    const current = () => mounted.current && request.current === controller;
    setBusy(true);
    setData(null);
    setError("");
    setNotice("");
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
      if (!validate(payload)) {
        setError(
          response.status === 401
            ? copy.sessionExpired
            : response.status === 403
              ? copy.permission
              : copy.unavailable,
        );
        return;
      }
      setData(payload);
      setUncertain(false);
    } catch {
      if (current()) setError(copy.unavailable);
    } finally {
      if (current()) {
        request.current = null;
        setBusy(false);
      }
    }
  }, [endpoint, tenantId, validate, copy]);

  useEffect(() => {
    void load();
    return () => {
      request.current?.abort();
      request.current = null;
    };
  }, [load]);

  async function save(changes: Record<string, unknown>, savedMessage: string) {
    if (!data || busy || uncertain || request.current) return;
    const controller = new AbortController();
    request.current = controller;
    const current = () => mounted.current && request.current === controller;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(endpoint, {
        method: "PUT",
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
        body: JSON.stringify({ expected_revision: data.revision, ...changes }),
      });
      const payload: unknown = response.ok ? await response.json() : null;
      if (!current()) return;
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) setData(null);
        setUncertain(response.status === 409 || response.status >= 500);
        setError(
          response.status === 401
            ? copy.sessionExpired
            : response.status === 403
              ? copy.permission
              : response.status === 409
                ? copy.conflict
                : response.status === 400
                  ? copy.invalid
                  : copy.uncertain,
        );
        return;
      }
      if (!validate(payload) || payload.revision < data.revision)
        throw new Error("invalid_receipt");
      setData(payload);
      setNotice(savedMessage);
    } catch {
      if (current()) {
        setUncertain(true);
        setError(copy.uncertain);
      }
    } finally {
      if (current()) {
        request.current = null;
        setBusy(false);
      }
    }
  }
  return { data, busy, uncertain, error, notice, load, save };
}

export function GpoApprovalPolicySettings(props: ScopeProps) {
  const copy = getGpoApprovalCopy(props.locale);
  const state = useApprovalDocument(
    "/api/v1/security/gpo-approval-policy/",
    isGpoApprovalPolicy,
    props,
    copy,
  );
  return (
    <section
      className={styles.panel}
      aria-labelledby="gpo-approval-policy-heading"
      aria-busy={state.busy}
    >
      <div className={styles.header}>
        <h2 id="gpo-approval-policy-heading">{copy.policyTitle}</h2>
        <button
          className={styles.button}
          type="button"
          disabled={state.busy}
          onClick={() => void state.load()}
        >
          {copy.reload}
        </button>
      </div>
      <p className={styles.hint}>{copy.policyDescription}</p>
      {state.data ? (
        <ApprovalPolicyForm
          key={state.data.revision}
          policy={state.data}
          busy={state.busy}
          uncertain={state.uncertain}
          copy={copy}
          onSave={(value) =>
            state.save({ four_eyes_required: value }, copy.savedPolicy)
          }
        />
      ) : state.busy ? (
        <p role="status">{copy.loading}</p>
      ) : null}
      {state.error ? (
        <p className={styles.error} role="alert">
          {state.error}
        </p>
      ) : null}
      {state.notice ? (
        <p className={styles.success} role="status">
          {state.notice}
        </p>
      ) : null}
    </section>
  );
}

function ApprovalPolicyForm({
  policy,
  busy,
  uncertain,
  copy,
  onSave,
}: {
  policy: GpoApprovalPolicy;
  busy: boolean;
  uncertain: boolean;
  copy: GpoApprovalCopy;
  onSave: (value: boolean) => Promise<void>;
}) {
  const [fourEyes, setFourEyes] = useState(policy.four_eyes_required);
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void onSave(fourEyes);
      }}
    >
      <label className={styles.checkField}>
        <input
          type="checkbox"
          checked={fourEyes}
          disabled={busy}
          onChange={(event) => setFourEyes(event.target.checked)}
          aria-describedby="gpo-four-eyes-hint"
        />
        {copy.fourEyes}
      </label>
      <p className={styles.hint} id="gpo-four-eyes-hint">
        {fourEyes ? copy.fourEyesHint : copy.selfApprovalHint}
      </p>
      <p className={styles.hint}>{copy.invalidationHint}</p>
      <p className={styles.hint}>
        {copy.revision}: {policy.revision}
      </p>
      <button
        className={styles.primaryButton}
        type="submit"
        disabled={busy || uncertain || fourEyes === policy.four_eyes_required}
      >
        {busy ? copy.saving : copy.savePolicy}
      </button>
    </form>
  );
}

export function GpoDomainAuthorizationSettings(
  props: ScopeProps & {
    domainId: string;
    domainName: string;
    onLocked: (locked: boolean) => void;
  },
) {
  const copy = getGpoApprovalCopy(props.locale);
  const endpoint = `/api/v1/security/domain-settings/${encodeURIComponent(props.domainId)}/gpo-authorization/`;
  const state = useApprovalDocument(
    endpoint,
    isGpoDomainAuthorization,
    props,
    copy,
  );
  return (
    <section
      className={styles.panel}
      aria-labelledby="gpo-authorization-heading"
      aria-busy={state.busy}
    >
      <div className={styles.header}>
        <h2 id="gpo-authorization-heading">{copy.authorizationTitle}</h2>
        <button
          className={styles.button}
          type="button"
          disabled={state.busy}
          onClick={() => void state.load()}
        >
          {copy.reload}
        </button>
      </div>
      <p className={styles.hint}>
        <strong>{props.domainName}</strong>
      </p>
      <p className={styles.hint}>{copy.authorizationHint}</p>
      {state.data ? (
        <DomainAuthorizationForm
          key={state.data.revision}
          document={state.data}
          busy={state.busy}
          uncertain={state.uncertain}
          copy={copy}
          onLocked={props.onLocked}
          onSave={(grants) => state.save({ grants }, copy.savedAuthorization)}
        />
      ) : state.busy ? (
        <p role="status">{copy.loading}</p>
      ) : null}
      {state.error ? (
        <p className={styles.error} role="alert">
          {state.error}
        </p>
      ) : null}
      {state.notice ? (
        <p className={styles.success} role="status">
          {state.notice}
        </p>
      ) : null}
    </section>
  );
}

function DomainAuthorizationForm({
  document,
  busy,
  uncertain,
  copy,
  onLocked,
  onSave,
}: {
  document: GpoDomainAuthorization;
  busy: boolean;
  uncertain: boolean;
  copy: GpoApprovalCopy;
  onLocked: (locked: boolean) => void;
  onSave: (grants: GpoDomainAuthorization["grants"]) => Promise<void>;
}) {
  const [grants, setGrants] = useState(document.grants);
  const normalize = (value: GpoDomainAuthorization["grants"]) =>
    value
      .map((grant) => ({
        user_id: grant.user_id,
        tiers: [...grant.tiers].sort(),
      }))
      .sort((left, right) => left.user_id.localeCompare(right.user_id));
  const dirty =
    JSON.stringify(normalize(grants)) !==
    JSON.stringify(normalize(document.grants));
  useEffect(() => {
    onLocked(dirty || busy || uncertain);
  }, [dirty, busy, uncertain, onLocked]);
  useEffect(() => () => onLocked(false), [onLocked]);
  function toggle(userId: string, tier: SecurityTier) {
    const selected =
      grants.find((grant) => grant.user_id === userId)?.tiers ?? [];
    const tiers = SECURITY_TIERS.filter((value) =>
      value === tier ? !selected.includes(tier) : selected.includes(value),
    );
    setGrants(
      [
        ...grants.filter((grant) => grant.user_id !== userId),
        ...(tiers.length ? [{ user_id: userId, tiers }] : []),
      ].sort((left, right) => left.user_id.localeCompare(right.user_id)),
    );
  }
  const members = [
    ...document.members,
    ...grants
      .filter(
        (grant) =>
          !document.members.some((member) => member.user_id === grant.user_id),
      )
      .map((grant) => ({
        user_id: grant.user_id,
        username: `${copy.inactiveMember} (${grant.user_id})`,
        role: null,
      })),
  ];
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void onSave(grants);
      }}
    >
      <div className={styles.grantGrid}>
        {members.map((member) => (
          <fieldset
            className={styles.grantMember}
            key={member.user_id}
            disabled={busy}
          >
            <legend>{member.username}</legend>
            <p className={styles.hint}>
              {member.role === "tenant_admin"
                ? copy.tenantAdmin
                : member.role === "approver"
                  ? copy.approver
                  : copy.inactiveMember}
            </p>
            <div className={styles.actions}>
              {SECURITY_TIERS.map((tier) => (
                <label key={tier} className={styles.checkField}>
                  <input
                    type="checkbox"
                    checked={grants.some(
                      (grant) =>
                        grant.user_id === member.user_id &&
                        grant.tiers.includes(tier),
                    )}
                    disabled={
                      !member.role &&
                      !grants.some(
                        (grant) =>
                          grant.user_id === member.user_id &&
                          grant.tiers.includes(tier),
                      )
                    }
                    aria-label={`Tier ${tier}: ${member.username}`}
                    onChange={() => toggle(member.user_id, tier)}
                  />
                  Tier {tier}
                </label>
              ))}
            </div>
          </fieldset>
        ))}
      </div>
      {!members.length ? <p className={styles.hint}>{copy.noMembers}</p> : null}
      <p className={styles.hint}>{copy.invalidationHint}</p>
      <p className={styles.hint}>
        {copy.revision}: {document.revision}
      </p>
      <div className={styles.actions}>
        <button
          className={styles.primaryButton}
          type="submit"
          disabled={busy || uncertain || !dirty}
        >
          {busy ? copy.saving : copy.saveAuthorization}
        </button>
        <button
          className={styles.button}
          type="button"
          disabled={busy || !dirty}
          onClick={() => setGrants(document.grants)}
        >
          {copy.discard}
        </button>
      </div>
    </form>
  );
}
