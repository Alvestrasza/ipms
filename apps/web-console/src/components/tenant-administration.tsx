/**
 * File Name: tenant-administration.tsx
 * Version: v0.2.76 | Created: 2026-09-19 | Modified: 2026-09-20
 * Author: Alice Endelgard | Organization: Alvestrasza Corporation
 * Purpose: Manage tenant metadata, identity bootstrap and tenant Agent readiness.
 */
"use client";

import {
  Building2,
  Download,
  KeyRound,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  UserPlus,
  X,
} from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import type { Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import type {
  AgentOnboardingStatus,
  PlatformTenant,
} from "@/lib/platform-tenant-types";

type Copy = Dictionary["platform"];
type Dialog =
  | { mode: "create" }
  | { mode: "edit"; tenant: PlatformTenant }
  | { mode: "administrator"; tenant: PlatformTenant }
  | { mode: "agent"; tenant: PlatformTenant }
  | { mode: "status"; tenant: PlatformTenant };

export function TenantAdministration({
  initialTenants,
  available,
  csrfToken,
  locale,
  copy,
}: {
  initialTenants: PlatformTenant[];
  available: boolean;
  csrfToken: string;
  locale: Locale;
  copy: Copy;
}) {
  const [tenants, setTenants] = useState(initialTenants);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [error, setError] = useState(available ? "" : copy.unavailable);
  const [notice, setNotice] = useState("");
  const [onboarding, setOnboarding] = useState<AgentOnboardingStatus | null>(
    null,
  );
  const modal = useRef<HTMLDialogElement | null>(null);
  useEffect(() => {
    if (!dialog) return;
    const element = modal.current;
    element?.showModal();
    return () => element?.close();
  }, [dialog]);

  async function request(
    path = "",
    method = "GET",
    body?: Record<string, string>,
  ) {
    const response = await fetch(`/api/v1/platform/tenants/${path}`, {
      method,
      credentials: "same-origin",
      cache: "no-store",
      signal: AbortSignal.timeout(15_000),
      headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const messages: Record<string, string> = {
        tenant_slug_unavailable: copy.slugUnavailable,
        tenant_administrator_already_initialized: copy.alreadyInitialized,
        username_unavailable: copy.usernameUnavailable,
        agent_pki_already_configured: copy.agentPkiAlready,
        gateway_dns_name_unavailable: copy.gatewayNameUnavailable,
        tenant_administrator_required: copy.adminRequired,
        tenant_inactive: copy.failed,
        agent_pki_recovery_unavailable: copy.recoveryUnavailable,
        agent_pki_recovery_not_confirmed: copy.recoveryNotConfirmed,
        invalid_request: copy.invalid,
        forbidden: copy.forbidden,
      };
      throw new Error(messages[payload?.error?.code] ?? copy.failed);
    }
    return payload;
  }
  async function refresh() {
    const payload = await request();
    if (!Array.isArray(payload?.results)) throw new Error(copy.unavailable);
    setTenants(payload.results);
  }
  async function loadOnboarding(tenant: PlatformTenant) {
    const payload = await request(`${tenant.id}/agent-onboarding/`);
    setOnboarding(payload as AgentOnboardingStatus);
    return payload as AgentOnboardingStatus;
  }
  async function openAgentOnboarding(tenant: PlatformTenant) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await loadOnboarding(tenant);
      setDialog({ mode: "agent", tenant });
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : copy.failed);
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }
  async function performAgent(
    operation: () => Promise<AgentOnboardingStatus>,
    success: string,
  ) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      setOnboarding(await operation());
      setNotice(success);
    } catch (caught) {
      const known = [
        copy.agentPkiAlready,
        copy.gatewayNameUnavailable,
        copy.adminRequired,
        copy.recoveryUnavailable,
        copy.recoveryNotConfirmed,
        copy.invalid,
        copy.forbidden,
        copy.failed,
      ];
      setError(
        caught instanceof Error && known.includes(caught.message)
          ? caught.message
          : copy.failed,
      );
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }
  async function downloadRecovery(tenant: PlatformTenant) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const response = await fetch(
        `/api/v1/platform/tenants/${tenant.id}/agent-onboarding/recovery/`,
        {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          signal: AbortSignal.timeout(15_000),
          headers: { "X-CSRFToken": csrfToken },
        },
      );
      if (!response.ok) throw new Error(copy.recoveryUnavailable);
      const bundle = await response.arrayBuffer();
      const expected = response.headers.get("X-IPMS-Recovery-SHA256") ?? "";
      const observed = Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", bundle)),
      )
        .map((value) => value.toString(16).padStart(2, "0"))
        .join("");
      if (!expected || observed !== expected) throw new Error(copy.failed);
      const disposition = response.headers.get("Content-Disposition") ?? "";
      const filename =
        disposition.match(/filename="([^"]+)"/)?.[1] ??
        `ipms-${tenant.slug}-agent-root-recovery.pem`;
      const url = URL.createObjectURL(
        new Blob([bundle], { type: "application/x-pem-file" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      URL.revokeObjectURL(url);
      await loadOnboarding(tenant);
      setNotice(copy.recoveryDownloaded);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : copy.failed);
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }
  async function verifyGateway(tenant: PlatformTenant) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const payload = await request(
        `${tenant.id}/agent-onboarding/verify-gateway/`,
        "POST",
        {},
      );
      const status = payload.onboarding as AgentOnboardingStatus;
      setOnboarding(status);
      if (
        payload.verification?.requested_tenant?.ready === true &&
        payload.verification?.all_tenants_preserved === true
      ) {
        setNotice(copy.gatewayVerified);
      } else {
        setError(copy.gatewayVerificationFailed);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : copy.failed);
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }
  async function perform(
    operation: () => Promise<unknown>,
    success = copy.saved,
    mutation = true,
  ) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await operation();
      if (mutation) {
        setDialog(null);
        setNotice(success);
        try {
          await refresh();
        } catch {
          setError(copy.refreshFailed);
        }
      }
    } catch (caught) {
      const known = [
        copy.slugUnavailable,
        copy.alreadyInitialized,
        copy.usernameUnavailable,
        copy.agentPkiAlready,
        copy.gatewayNameUnavailable,
        copy.adminRequired,
        copy.recoveryUnavailable,
        copy.recoveryNotConfirmed,
        copy.invalid,
        copy.forbidden,
        copy.failed,
        copy.unavailable,
      ];
      setError(
        caught instanceof Error && known.includes(caught.message)
          ? caught.message
          : copy.failed,
      );
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }
  function open(value: Dialog) {
    setError("");
    setNotice("");
    setDialog(value);
  }
  function close() {
    if (!pending.current) {
      setDialog(null);
      setOnboarding(null);
      setError("");
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dialog || dialog.mode === "status" || pending.current) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    try {
      if (dialog.mode === "agent") {
        await performAgent(
          async () =>
            (await request(`${dialog.tenant.id}/agent-onboarding/`, "POST", {
              gateway_dns_name: String(
                fields.get("gateway_dns_name") ?? "",
              ).trim(),
              recovery_passphrase: String(
                fields.get("recovery_passphrase") ?? "",
              ),
              recovery_passphrase_confirmation: String(
                fields.get("recovery_passphrase_confirmation") ?? "",
              ),
            })) as AgentOnboardingStatus,
          copy.pkiPrepared,
        );
      } else if (dialog.mode === "administrator") {
        await perform(
          () =>
            request(`${dialog.tenant.id}/initial-administrator/`, "POST", {
              username: String(fields.get("username") ?? "").trim(),
              initial_password: String(fields.get("initial_password") ?? ""),
              first_name: String(fields.get("first_name") ?? "").trim(),
              last_name: String(fields.get("last_name") ?? "").trim(),
              email: String(fields.get("email") ?? "").trim(),
            }),
          copy.administratorCreated,
        );
      } else {
        const document = {
          display_name: String(fields.get("display_name") ?? "").trim(),
          ...(dialog.mode === "create"
            ? {
                slug: String(fields.get("slug") ?? "").trim(),
                purpose: String(fields.get("purpose") ?? "infrastructure"),
              }
            : {}),
        };
        await perform(() =>
          request(
            dialog.mode === "create" ? "" : `${dialog.tenant.id}/`,
            dialog.mode === "create" ? "POST" : "PATCH",
            document,
          ),
        );
      }
    } finally {
      const password = form.elements.namedItem("initial_password");
      if (password instanceof HTMLInputElement) password.value = "";
      const recoveryPassphrase = form.elements.namedItem("recovery_passphrase");
      if (recoveryPassphrase instanceof HTMLInputElement)
        recoveryPassphrase.value = "";
      const recoveryConfirmation = form.elements.namedItem(
        "recovery_passphrase_confirmation",
      );
      if (recoveryConfirmation instanceof HTMLInputElement)
        recoveryConfirmation.value = "";
      fields.delete("initial_password");
      fields.delete("recovery_passphrase");
      fields.delete("recovery_passphrase_confirmation");
    }
  }
  function packageFailure(status: AgentOnboardingStatus) {
    const messages: Record<string, string> = {
      package_missing: copy.packageMissing,
      package_digest_mismatch: copy.packageDigestMismatch,
      package_unreadable: copy.packageUnreadable,
      package_version_invalid: copy.packageVersionInvalid,
      package_hgs_version_too_old: copy.packageHgsTooOld.replace(
        "{version}",
        status.package.minimum_hgs_version,
      ),
    };
    return messages[status.package.reason] ?? copy.packageBlocked;
  }
  const title = !dialog
    ? ""
    : dialog.mode === "create"
      ? copy.create
      : dialog.mode === "edit"
        ? copy.edit
        : dialog.mode === "administrator"
          ? copy.setupAdministrator
          : dialog.mode === "agent"
            ? copy.agentOnboarding
            : dialog.tenant.status === "active"
              ? copy.suspend
              : copy.reactivate;
  return (
    <>
      {notice ? (
        <p role="status" className="preview-notice preview-notice--live">
          {notice}
        </p>
      ) : null}
      {error && !dialog ? (
        <p role="alert" className="form-error">
          {error}
        </p>
      ) : null}
      <section
        className="inventory-panel agent-admin-panel"
        aria-labelledby="tenant-list-heading"
      >
        <div className="panel__header agent-admin-toolbar">
          <div>
            <span id="tenant-list-heading">{copy.title}</span>
            <h2>{tenants.length}</h2>
          </div>
          <div className="agent-admin-toolbar__actions">
            <button
              type="button"
              className="outline-button"
              disabled={busy}
              onClick={() => void perform(refresh, "", false)}
            >
              <RefreshCw size={16} aria-hidden="true" />
              {copy.refresh}
            </button>
            <button
              type="button"
              className="outline-button"
              disabled={busy}
              onClick={() => open({ mode: "create" })}
            >
              <Plus size={16} aria-hidden="true" />
              {copy.create}
            </button>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{copy.name}</th>
                <th>{copy.slug}</th>
                <th>{copy.purpose}</th>
                <th>{copy.status}</th>
                <th>{copy.administrator}</th>
                <th>{copy.updated} (UTC)</th>
                <th>{copy.actions}</th>
              </tr>
            </thead>
            <tbody>
              {tenants.map((tenant) => (
                <tr key={tenant.id}>
                  <td>
                    <strong>{tenant.display_name}</strong>
                  </td>
                  <td>{tenant.slug}</td>
                  <td>{copy.purposes[tenant.purpose ?? "infrastructure"]}</td>
                  <td>{copy.states[tenant.status]}</td>
                  <td>
                    {tenant.needs_administrator
                      ? copy.setupRequired
                      : copy.initialized}
                  </td>
                  <td>
                    {new Intl.DateTimeFormat(locale, {
                      dateStyle: "medium",
                      timeStyle: "short",
                      timeZone: "UTC",
                    }).format(new Date(tenant.updated_at))}
                  </td>
                  <td>
                    {tenant.status !== "decommissioned" ? (
                      <div className="agent-row-actions">
                        <button
                          className="icon-button icon-button--compact"
                          type="button"
                          aria-label={`${copy.edit} ${tenant.display_name}`}
                          disabled={busy}
                          onClick={() => open({ mode: "edit", tenant })}
                        >
                          <Pencil size={15} aria-hidden="true" />
                        </button>
                        <button
                          className="outline-button"
                          type="button"
                          disabled={busy || !tenant.needs_administrator}
                          aria-label={`${copy.setupAdministrator} ${tenant.display_name}`}
                          onClick={() =>
                            open({ mode: "administrator", tenant })
                          }
                        >
                          <UserPlus size={16} aria-hidden="true" />
                          {copy.setupAdministrator}
                        </button>
                        <button
                          className="outline-button"
                          type="button"
                          disabled={
                            busy ||
                            tenant.needs_administrator ||
                            tenant.status !== "active"
                          }
                          aria-label={`${copy.configureAgentAccess} ${tenant.display_name}`}
                          onClick={() => void openAgentOnboarding(tenant)}
                        >
                          <ShieldCheck size={16} aria-hidden="true" />
                          {copy.agentOnboarding}
                        </button>
                        <button
                          className="outline-button"
                          type="button"
                          disabled={busy}
                          aria-label={`${tenant.status === "active" ? copy.suspend : copy.reactivate} ${tenant.display_name}`}
                          onClick={() => open({ mode: "status", tenant })}
                        >
                          {tenant.status === "active"
                            ? copy.suspend
                            : copy.reactivate}
                        </button>
                      </div>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!tenants.length ? <p className="table-empty">{copy.empty}</p> : null}
      </section>
      {dialog ? (
        <dialog
          ref={modal}
          className="modal-card service-account-dialog"
          aria-labelledby="tenant-dialog-heading"
          onCancel={(event) => {
            event.preventDefault();
            close();
          }}
        >
          <div className="modal-card__heading">
            <Building2 size={20} aria-hidden="true" />
            <h3 id="tenant-dialog-heading">{title}</h3>
            <button
              type="button"
              className="icon-button icon-button--compact service-account-dialog__close"
              disabled={busy}
              aria-label={copy.cancel}
              onClick={close}
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
          {dialog.mode === "status" ? (
            <>
              <p>
                {dialog.tenant.status === "active"
                  ? copy.suspendWarning
                  : copy.reactivateWarning}
              </p>
              <p>
                <strong>{dialog.tenant.display_name}</strong>
              </p>
              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  type="button"
                  className="outline-button"
                  disabled={busy}
                  onClick={close}
                >
                  {copy.cancel}
                </button>
                <button
                  type="button"
                  className="primary-button"
                  disabled={busy}
                  onClick={() =>
                    void perform(() =>
                      request(`${dialog.tenant.id}/`, "PATCH", {
                        status:
                          dialog.tenant.status === "active"
                            ? "suspended"
                            : "active",
                      }),
                    )
                  }
                >
                  {title}
                </button>
              </div>
            </>
          ) : dialog.mode === "agent" ? (
            !onboarding ? (
              <p>{copy.unavailable}</p>
            ) : onboarding.pki.state === "missing" ? (
              <form onSubmit={submit} autoComplete="off">
                <p>{copy.recoveryHint}</p>
                <p>
                  <strong>{dialog.tenant.display_name}</strong>
                </p>
                <label>
                  {copy.gatewayDnsName}
                  <input
                    name="gateway_dns_name"
                    required
                    maxLength={253}
                    pattern="[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?"
                    autoComplete="off"
                    placeholder={`agent-${dialog.tenant.slug}.example.internal`}
                  />
                </label>
                <div className="form-grid form-grid--two-columns">
                  <label>
                    {copy.recoveryPassphrase}
                    <input
                      name="recovery_passphrase"
                      type="password"
                      required
                      minLength={20}
                      maxLength={1024}
                      autoComplete="new-password"
                    />
                  </label>
                  <label>
                    {copy.recoveryPassphraseConfirmation}
                    <input
                      name="recovery_passphrase_confirmation"
                      type="password"
                      required
                      minLength={20}
                      maxLength={1024}
                      autoComplete="new-password"
                    />
                  </label>
                </div>
                {error ? (
                  <p className="form-error" role="alert">
                    {error}
                  </p>
                ) : null}
                <div className="modal-card__actions">
                  <button
                    type="button"
                    className="outline-button"
                    disabled={busy}
                    onClick={close}
                  >
                    {copy.cancel}
                  </button>
                  <button
                    type="submit"
                    className="primary-button"
                    disabled={busy}
                  >
                    <KeyRound size={16} aria-hidden="true" />
                    {copy.initializePki}
                  </button>
                </div>
              </form>
            ) : (
              <>
                <p>
                  <strong>{dialog.tenant.display_name}</strong>
                </p>
                <dl className="detail-list">
                  <div>
                    <dt>{copy.pkiState}</dt>
                    <dd>
                      {onboarding.pki.state === "recovery_pending"
                        ? copy.pkiRecoveryPending
                        : copy.pkiReady}
                    </dd>
                  </div>
                  <div>
                    <dt>{copy.gatewayEndpoint}</dt>
                    <dd>
                      {onboarding.pki.gateway_dns_name}:
                      {onboarding.pki.gateway_port}
                    </dd>
                  </div>
                  <div>
                    <dt>SHA-256</dt>
                    <dd>
                      <code>
                        {onboarding.pki.state === "recovery_pending"
                          ? onboarding.pki.recovery_bundle_sha256
                          : onboarding.pki.gateway_fingerprint_sha256}
                      </code>
                    </dd>
                  </div>
                  <div>
                    <dt>{copy.packageLabel}</dt>
                    <dd>
                      {onboarding.package.ready
                        ? `${copy.packageReady} · ${onboarding.package.version}`
                        : packageFailure(onboarding)}
                    </dd>
                  </div>
                  <div>
                    <dt>{copy.packageDigest}</dt>
                    <dd>
                      <code>{onboarding.package.sha256}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>{copy.agentAccessStatus}</dt>
                    <dd>
                      {onboarding.ready_for_enrollment
                        ? copy.readyForEnrollment
                        : copy.onboardingNotReady}
                    </dd>
                  </div>
                </dl>
                {onboarding.pki.state === "recovery_pending" ? (
                  <p>{copy.confirmRecoveryWarning}</p>
                ) : (
                  <p>
                    {onboarding.gateway.ready
                      ? copy.gatewayReady
                      : copy.gatewayPending}
                  </p>
                )}
                {error ? (
                  <p className="form-error" role="alert">
                    {error}
                  </p>
                ) : null}
                <div className="modal-card__actions">
                  <button
                    type="button"
                    className="outline-button"
                    disabled={busy}
                    onClick={close}
                  >
                    {copy.cancel}
                  </button>
                  {onboarding.pki.state === "recovery_pending" ? (
                    <>
                      <button
                        type="button"
                        className="outline-button"
                        disabled={busy}
                        onClick={() => void downloadRecovery(dialog.tenant)}
                      >
                        <Download size={16} aria-hidden="true" />
                        {copy.downloadRecovery}
                      </button>
                      <button
                        type="button"
                        className="primary-button"
                        disabled={busy || !onboarding.pki.recovery_downloaded}
                        onClick={() =>
                          void performAgent(
                            async () =>
                              (await request(
                                `${dialog.tenant.id}/agent-onboarding/recovery/`,
                                "POST",
                                {
                                  bundle_sha256:
                                    onboarding.pki.recovery_bundle_sha256,
                                },
                              )) as AgentOnboardingStatus,
                            copy.recoveryConfirmed,
                          )
                        }
                      >
                        <ShieldCheck size={16} aria-hidden="true" />
                        {copy.confirmRecovery}
                      </button>
                    </>
                  ) : (
                    <button
                      type="button"
                      className="primary-button"
                      disabled={busy}
                      onClick={() => void verifyGateway(dialog.tenant)}
                    >
                      <Network size={16} aria-hidden="true" />
                      {copy.verifyGateway}
                    </button>
                  )}
                </div>
              </>
            )
          ) : (
            <form onSubmit={submit} autoComplete="off">
              {dialog.mode === "administrator" ? (
                <>
                  <p>{copy.setupWarning}</p>
                  <p>
                    <strong>{dialog.tenant.display_name}</strong>
                  </p>
                  <div className="form-grid form-grid--two-columns">
                    <label>
                      {copy.username}
                      <input
                        name="username"
                        required
                        maxLength={150}
                        autoComplete="off"
                      />
                    </label>
                    <label>
                      {copy.password}
                      <input
                        name="initial_password"
                        type="password"
                        required
                        minLength={12}
                        maxLength={256}
                        autoComplete="new-password"
                      />
                    </label>
                    <label>
                      {copy.firstName}
                      <input name="first_name" maxLength={150} />
                    </label>
                    <label>
                      {copy.lastName}
                      <input name="last_name" maxLength={150} />
                    </label>
                  </div>
                  <label>
                    {copy.email}
                    <input name="email" type="email" maxLength={254} />
                  </label>
                  <p>{copy.passwordHint}</p>
                </>
              ) : (
                <>
                  <label>
                    {copy.name}
                    <input
                      name="display_name"
                      required
                      maxLength={255}
                      defaultValue={
                        dialog.mode === "edit" ? dialog.tenant.display_name : ""
                      }
                    />
                  </label>
                  <label>
                    {copy.slug}
                    <input
                      name="slug"
                      required
                      maxLength={63}
                      pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
                      disabled={dialog.mode === "edit"}
                      defaultValue={
                        dialog.mode === "edit" ? dialog.tenant.slug : ""
                      }
                    />
                  </label>
                  <p>{copy.slugHint}</p>
                  <label>
                    {copy.purpose}
                    <select
                      name="purpose"
                      disabled={dialog.mode === "edit"}
                      defaultValue={
                        dialog.mode === "edit"
                          ? (dialog.tenant.purpose ?? "infrastructure")
                          : "infrastructure"
                      }
                    >
                      <option value="infrastructure">
                        {copy.purposes.infrastructure}
                      </option>
                      <option value="hgs">{copy.purposes.hgs}</option>
                    </select>
                  </label>
                  <p>{copy.purposeHint}</p>
                </>
              )}
              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  type="button"
                  className="outline-button"
                  disabled={busy}
                  onClick={close}
                >
                  {copy.cancel}
                </button>
                <button
                  type="submit"
                  className="primary-button"
                  disabled={busy}
                >
                  {dialog.mode === "administrator"
                    ? copy.createAdministrator
                    : copy.save}
                </button>
              </div>
            </form>
          )}
        </dialog>
      ) : null}
    </>
  );
}
