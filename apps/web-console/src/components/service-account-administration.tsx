"use client";

import {
  KeyRound,
  Pencil,
  Plus,
  RefreshCw,
  Trash2,
  Unlink,
} from "lucide-react";
import {
  type FormEvent,
  type ReactNode,
  useEffect,
  useRef,
  useState,
} from "react";
import type { Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import {
  type ServiceAccount,
  type ServiceAccountHost,
  serviceAccountDocument,
} from "@/lib/service-account-types";

type Copy = Dictionary["serviceAccounts"];
type Dialog =
  | { mode: "create" }
  | { mode: "edit"; account: ServiceAccount }
  | { mode: "delete"; account: ServiceAccount }
  | { mode: "unassign"; host: ServiceAccountHost };

export function ServiceAccountAdministration({
  initialAccounts,
  initialHosts,
  available,
  csrfToken,
  tenantId,
  locale,
  copy,
}: {
  initialAccounts: ServiceAccount[];
  initialHosts: ServiceAccountHost[];
  available: boolean;
  csrfToken: string;
  tenantId: string;
  locale: Locale;
  copy: Copy;
}) {
  const [accounts, setAccounts] = useState(initialAccounts);
  const [hosts, setHosts] = useState(initialHosts);
  const [selection, setSelection] = useState<Record<string, string>>({});
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [error, setError] = useState(available ? "" : copy.unavailable);
  const [notice, setNotice] = useState("");

  async function request(
    path: string,
    method = "GET",
    body?: Record<string, string>,
  ) {
    const response = await fetch(`/api/v1/service-accounts/${path}`, {
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
    if (!response.ok) {
      const code = (await response.json().catch(() => ({})))?.error?.code;
      throw new Error(
        code === "service_account_in_use"
          ? copy.inUse
          : code === "service_account_invalid"
            ? copy.invalid
            : code === "service_account_unavailable"
              ? copy.unavailable
              : copy.actionFailed,
      );
    }
    return response.status === 204 ? null : response.json();
  }

  async function refresh() {
    const [accountData, hostData] = await Promise.all([
      request(""),
      request("hosts/"),
    ]);
    if (
      !Array.isArray(accountData?.results) ||
      !Array.isArray(hostData?.results)
    )
      throw new Error(copy.refreshFailed);
    setAccounts(accountData.results);
    setHosts(hostData.results);
    setSelection({});
  }

  async function perform(operation: () => Promise<unknown>, mutation = true) {
    if (pending.current) return;
    pending.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await operation();
      if (mutation) {
        setDialog(null);
        setNotice(copy.saved);
        try {
          await refresh();
        } catch {
          setError(copy.refreshFailed);
        }
      }
    } catch (caught) {
      setError(
        caught instanceof Error &&
          [
            copy.inUse,
            copy.invalid,
            copy.actionFailed,
            copy.refreshFailed,
            copy.unavailable,
          ].includes(caught.message)
          ? caught.message
          : copy.actionFailed,
      );
    } finally {
      pending.current = false;
      setBusy(false);
    }
  }

  async function submitAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!dialog || !["create", "edit"].includes(dialog.mode) || pending.current)
      return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    try {
      const document = serviceAccountDocument(
        {
          name: String(fields.get("name") ?? ""),
          username: String(fields.get("username") ?? ""),
          domain: String(fields.get("domain") ?? ""),
          password: String(fields.get("password") ?? ""),
        },
        dialog.mode === "edit",
        dialog.mode === "edit" ? dialog.account : undefined,
      );
      await perform(() =>
        request(
          dialog.mode === "edit" ? `${dialog.account.id}/` : "",
          dialog.mode === "edit" ? "PATCH" : "POST",
          document,
        ),
      );
    } catch {
      setError(copy.invalid);
    } finally {
      const password = form.elements.namedItem("password");
      if (password instanceof HTMLInputElement) password.value = "";
      fields.delete("password");
    }
  }

  function open(value: Dialog) {
    setError("");
    setNotice("");
    setDialog(value);
  }
  const formatDate = (value: string) => {
    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? "—"
      : new Intl.DateTimeFormat(locale, {
          dateStyle: "medium",
          timeStyle: "short",
        }).format(date);
  };
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
        aria-labelledby="service-account-table-heading"
      >
        <div className="panel__header agent-admin-toolbar">
          <div>
            <span>{copy.accounts}</span>
            <h2 id="service-account-table-heading">{accounts.length}</h2>
          </div>
          <div className="agent-admin-toolbar__actions">
            <button
              className="outline-button"
              type="button"
              disabled={busy}
              onClick={() => void perform(refresh, false)}
            >
              <RefreshCw size={16} aria-hidden="true" />
              {copy.refresh}
            </button>
            <button
              className="outline-button"
              type="button"
              disabled={busy}
              onClick={() => open({ mode: "create" })}
            >
              <Plus size={16} aria-hidden="true" />
              {copy.add}
            </button>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{copy.name}</th>
                <th>{copy.kind}</th>
                <th>{copy.username}</th>
                <th>{copy.domain}</th>
                <th>{copy.hostCount}</th>
                <th>{copy.updated}</th>
                <th>{copy.actions}</th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((account) => (
                <tr key={account.id}>
                  <td>
                    <strong>{account.name}</strong>
                  </td>
                  <td>{copy.hypervConsole}</td>
                  <td>{account.username}</td>
                  <td>{account.domain || "—"}</td>
                  <td>{account.host_count}</td>
                  <td>{formatDate(account.updated_at)}</td>
                  <td>
                    <div className="agent-row-actions">
                      <button
                        className="icon-button icon-button--compact"
                        type="button"
                        disabled={busy}
                        aria-label={`${copy.edit} ${account.name}`}
                        onClick={() => open({ mode: "edit", account })}
                      >
                        <Pencil size={15} aria-hidden="true" />
                      </button>
                      <button
                        className="icon-button icon-button--compact icon-button--danger"
                        type="button"
                        disabled={busy || account.host_count > 0}
                        title={
                          account.host_count > 0 ? copy.inUse : copy.delete
                        }
                        aria-label={`${copy.delete} ${account.name}`}
                        onClick={() => open({ mode: "delete", account })}
                      >
                        <Trash2 size={15} aria-hidden="true" />
                      </button>
                    </div>
                    {account.host_count > 0 ? (
                      <small>{copy.bound}</small>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {accounts.length === 0 ? (
          <p className="table-empty">{copy.noAccounts}</p>
        ) : null}
      </section>
      <section
        className="inventory-panel service-account-hosts"
        aria-labelledby="service-account-host-heading"
      >
        <div className="panel__header">
          <div>
            <span>{copy.hostDescription}</span>
            <h2 id="service-account-host-heading">{copy.hosts}</h2>
            <p>{copy.sessionWarning}</p>
          </div>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>{copy.fqdn}</th>
                <th>{copy.agentVersion}</th>
                <th>{copy.assignment}</th>
                <th>{copy.actions}</th>
              </tr>
            </thead>
            <tbody>
              {hosts.map((host) => {
                const chosen =
                  selection[host.id] ?? host.service_account_id ?? "";
                return (
                  <tr key={host.id}>
                    <td>
                      <strong>{host.fqdn}</strong>
                      {!host.eligible ? <small>{copy.ineligible}</small> : null}
                      {host.legacy_configured ? (
                        <small>{copy.legacy}</small>
                      ) : null}
                    </td>
                    <td>{host.agent_version}</td>
                    <td>
                      <select
                        className="service-account-select"
                        value={chosen}
                        disabled={busy || !host.eligible}
                        aria-label={`${copy.assignment} ${host.fqdn}`}
                        onChange={(event) =>
                          setSelection((current) => ({
                            ...current,
                            [host.id]: event.target.value,
                          }))
                        }
                      >
                        <option value="">{copy.unassigned}</option>
                        {accounts.map((account) => (
                          <option key={account.id} value={account.id}>
                            {account.name}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td>
                      <div className="agent-row-actions">
                        <button
                          className="outline-button"
                          type="button"
                          disabled={
                            busy ||
                            !host.eligible ||
                            !chosen ||
                            chosen === host.service_account_id
                          }
                          aria-label={`${copy.saveAssignment} ${host.fqdn}`}
                          onClick={() =>
                            void perform(() =>
                              request(`hosts/${host.id}/`, "PUT", {
                                service_account_id: chosen,
                              }),
                            )
                          }
                        >
                          {copy.saveAssignment}
                        </button>
                        <button
                          className="icon-button icon-button--compact icon-button--danger"
                          type="button"
                          disabled={
                            busy ||
                            (!host.service_account_id &&
                              !host.legacy_configured)
                          }
                          aria-label={`${copy.unassign} ${host.fqdn}`}
                          onClick={() => open({ mode: "unassign", host })}
                        >
                          <Unlink size={15} aria-hidden="true" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {hosts.length === 0 ? (
          <p className="table-empty">{copy.noHosts}</p>
        ) : null}
      </section>
      {dialog ? (
        <ServiceAccountDialog
          title={
            dialog.mode === "create"
              ? copy.add
              : dialog.mode === "edit"
                ? copy.edit
                : dialog.mode === "delete"
                  ? copy.delete
                  : copy.unassign
          }
          busy={busy}
          closeLabel={copy.cancel}
          onClose={() => {
            if (!pending.current) {
              setDialog(null);
              setError("");
            }
          }}
        >
          {dialog.mode === "create" || dialog.mode === "edit" ? (
            <form onSubmit={submitAccount} autoComplete="off">
              <p>{copy.accountHint}</p>
              {dialog.mode === "edit" ? <p>{copy.sessionWarning}</p> : null}
              <div className="form-grid form-grid--two-columns">
                <label>
                  {copy.name}
                  <input
                    name="name"
                    required
                    maxLength={128}
                    defaultValue={
                      dialog.mode === "edit" ? dialog.account.name : ""
                    }
                  />
                </label>
                <label>
                  {copy.kind}
                  <select value="hyperv_console" disabled>
                    <option value="hyperv_console">{copy.hypervConsole}</option>
                  </select>
                </label>
                <label>
                  {copy.username}
                  <input
                    name="username"
                    required
                    maxLength={256}
                    autoComplete="off"
                    defaultValue={
                      dialog.mode === "edit" ? dialog.account.username : ""
                    }
                  />
                </label>
                <label>
                  {copy.domain}
                  <input
                    name="domain"
                    maxLength={256}
                    autoComplete="off"
                    defaultValue={
                      dialog.mode === "edit" ? dialog.account.domain : ""
                    }
                  />
                </label>
              </div>
              <label>
                {copy.password}
                <input
                  name="password"
                  type="password"
                  aria-label={copy.password}
                  aria-describedby="service-account-password-hint"
                  autoComplete="new-password"
                  maxLength={1024}
                  required={dialog.mode === "create"}
                />
                <small id="service-account-password-hint">
                  {dialog.mode === "edit"
                    ? copy.keepPassword
                    : copy.passwordHint}
                </small>
              </label>
              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  className="outline-button"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setDialog(null);
                    setError("");
                  }}
                >
                  {copy.cancel}
                </button>
                <button
                  className="primary-button"
                  type="submit"
                  disabled={busy}
                >
                  {copy.save}
                </button>
              </div>
            </form>
          ) : (
            <>
              <p>
                {dialog.mode === "delete"
                  ? copy.deleteConfirm
                  : copy.unassignConfirm}
              </p>
              <p>
                <strong>
                  {dialog.mode === "delete"
                    ? dialog.account.name
                    : dialog.host.fqdn}
                </strong>
              </p>
              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  className="outline-button"
                  type="button"
                  disabled={busy}
                  onClick={() => {
                    setDialog(null);
                    setError("");
                  }}
                >
                  {copy.cancel}
                </button>
                <button
                  className="primary-button"
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    void perform(() =>
                      request(
                        dialog.mode === "delete"
                          ? `${dialog.account.id}/`
                          : `hosts/${dialog.host.id}/`,
                        "DELETE",
                      ),
                    )
                  }
                >
                  {dialog.mode === "delete" ? copy.delete : copy.unassign}
                </button>
              </div>
            </>
          )}
        </ServiceAccountDialog>
      ) : null}
    </>
  );
}

function ServiceAccountDialog({
  title,
  busy,
  closeLabel,
  onClose,
  children,
}: {
  title: string;
  busy: boolean;
  closeLabel: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const element = useRef<HTMLDialogElement | null>(null);
  useEffect(() => {
    const dialog = element.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={element}
      className="modal-card service-account-dialog"
      aria-labelledby="service-account-dialog-heading"
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
    >
      <div className="modal-card__heading">
        <KeyRound size={20} aria-hidden="true" />
        <h3 id="service-account-dialog-heading">{title}</h3>
        <button
          type="button"
          className="icon-button icon-button--compact service-account-dialog__close"
          disabled={busy}
          aria-label={closeLabel}
          onClick={onClose}
        >
          ×
        </button>
      </div>
      {children}
    </dialog>
  );
}
