"use client";

import { Building2, Pencil, Plus, RefreshCw, UserPlus, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import type { Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import type { PlatformTenant } from "@/lib/platform-tenant-types";

type Copy = Dictionary["platform"];
type Dialog =
  | { mode: "create" }
  | { mode: "edit"; tenant: PlatformTenant }
  | { mode: "administrator"; tenant: PlatformTenant }
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
      setError("");
    }
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dialog || dialog.mode === "status" || pending.current) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    try {
      if (dialog.mode === "administrator") {
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
            ? { slug: String(fields.get("slug") ?? "").trim() }
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
      fields.delete("initial_password");
    }
  }
  const title = !dialog
    ? ""
    : dialog.mode === "create"
      ? copy.create
      : dialog.mode === "edit"
        ? copy.edit
        : dialog.mode === "administrator"
          ? copy.setupAdministrator
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
