"use client";

import { Pencil, Plus, Search, ShieldCheck, UserRound } from "lucide-react";
import { type FormEvent, useDeferredValue, useMemo, useState } from "react";
import type { Locale } from "@/i18n/config";
import type { Dictionary } from "@/i18n/dictionaries";
import type { TenantRole } from "@/lib/auth-types";
import type { ManagedTenantUser } from "@/lib/server-users";

import { DialogPortal } from "./dialog-portal";

type UserCopy = Dictionary["userAdministration"];
type EditableRole = Exclude<TenantRole, "platform_admin">;

const EDITABLE_ROLES: EditableRole[] = [
  "tenant_admin",
  "operator",
  "approver",
  "auditor",
  "reader",
];

function formatDate(
  value: string | null,
  formatter: Intl.DateTimeFormat,
  fallback: string,
) {
  if (!value) return fallback;
  return formatter.format(new Date(value));
}

function dateTimeLocal(value: string | null) {
  if (!value) return "";
  const date = new Date(value);
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

function apiErrorMessage(code: string, copy: UserCopy) {
  const messages: Record<string, string> = {
    username_unavailable: copy.usernameUnavailable,
    last_tenant_admin: copy.lastTenantAdmin,
    self_role_change_denied: copy.selfRoleChangeDenied,
    platform_user_protected: copy.platformUserProtected,
  };
  return messages[code] ?? copy.actionFailed;
}

export function UserAdministrationTable({
  initialUsers,
  canManage,
  csrfToken,
  tenantId,
  locale,
  copy,
}: {
  initialUsers: ManagedTenantUser[];
  canManage: boolean;
  csrfToken: string;
  tenantId: string;
  locale: Locale;
  copy: UserCopy;
}) {
  const [users, setUsers] = useState(initialUsers);
  const [search, setSearch] = useState("");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const [dialog, setDialog] = useState<
    { mode: "create" } | { mode: "edit"; user: ManagedTenantUser } | null
  >(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const dateFormatter = useMemo(
    () =>
      new Intl.DateTimeFormat(locale, {
        dateStyle: "medium",
        timeStyle: "short",
      }),
    [locale],
  );

  const filteredUsers = deferredSearch
    ? users.filter((user) =>
        [user.username, user.display_name, user.email, user.role].some(
          (value) => value.toLowerCase().includes(deferredSearch),
        ),
      )
    : users;

  async function request(
    url: string,
    method: "POST" | "PATCH",
    body: Record<string, unknown>,
  ) {
    const response = await fetch(url, {
      method,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrfToken,
        "X-IPMS-Tenant-ID": tenantId,
      },
      body: JSON.stringify(body),
    });
    const payload = (await response.json()) as
      | ManagedTenantUser
      | { error?: { code?: string } };
    if (!response.ok) {
      const code = "error" in payload ? (payload.error?.code ?? "") : "";
      throw new Error(apiErrorMessage(code, copy));
    }
    return payload as ManagedTenantUser;
  }

  async function createUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const expiration = String(form.get("expires_at") ?? "");
    try {
      const created = await request("/api/v1/auth/users/", "POST", {
        username: form.get("username"),
        first_name: form.get("first_name"),
        last_name: form.get("last_name"),
        email: form.get("email"),
        initial_password: form.get("initial_password"),
        role: form.get("role"),
        expires_at: expiration ? new Date(expiration).toISOString() : null,
      });
      setUsers((current) =>
        [...current, created].toSorted((left, right) =>
          left.username.localeCompare(right.username),
        ),
      );
      setDialog(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : copy.actionFailed);
    } finally {
      setSubmitting(false);
    }
  }

  async function updateUser(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (dialog?.mode !== "edit") return;
    setSubmitting(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const expiration = String(form.get("expires_at") ?? "");
    try {
      const updated = await request(
        `/api/v1/auth/users/${dialog.user.membership_id}/`,
        "PATCH",
        {
          role: form.get("role"),
          is_active: form.get("is_active") === "on",
          expires_at: expiration ? new Date(expiration).toISOString() : null,
        },
      );
      setUsers((current) =>
        current.map((user) =>
          user.membership_id === updated.membership_id ? updated : user,
        ),
      );
      setDialog(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : copy.actionFailed);
    } finally {
      setSubmitting(false);
    }
  }

  function closeDialog() {
    if (submitting) return;
    setError("");
    setDialog(null);
  }

  return (
    <section
      className="inventory-panel agent-admin-panel"
      aria-labelledby="user-table-heading"
    >
      <div className="panel__header agent-admin-toolbar">
        <div>
          <span>{copy.tableHeading}</span>
          <h2 id="user-table-heading">{users.length}</h2>
        </div>
        <div className="agent-admin-toolbar__actions">
          <label className="agent-search">
            <Search aria-hidden="true" size={15} />
            <span className="sr-only">{copy.search}</span>
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder={copy.search}
            />
          </label>
          {canManage ? (
            <button
              className="outline-button"
              type="button"
              onClick={() => {
                setError("");
                setDialog({ mode: "create" });
              }}
            >
              <Plus aria-hidden="true" size={16} />
              {copy.addUser}
            </button>
          ) : null}
        </div>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>{copy.username}</th>
              <th>{copy.displayName}</th>
              <th>{copy.authentication}</th>
              <th>{copy.role}</th>
              <th>{copy.status}</th>
              <th>{copy.expires}</th>
              <th>{copy.lastLogin}</th>
              <th>{copy.actions}</th>
            </tr>
          </thead>
          <tbody>
            {filteredUsers.map((user) => (
              <tr key={user.membership_id}>
                <td>
                  <strong>{user.username}</strong>
                  <small>{user.email || "—"}</small>
                </td>
                <td>{user.display_name}</td>
                <td>
                  {user.authentication_source === "oidc"
                    ? copy.oidc
                    : user.authentication_source === "hybrid"
                      ? copy.hybrid
                      : copy.local}
                </td>
                <td>{copy.roles[user.role]}</td>
                <td>
                  <span
                    className={`agent-state agent-state--${user.is_active ? "online" : "offline"}`}
                  >
                    {user.is_active ? copy.active : copy.inactive}
                  </span>
                </td>
                <td>
                  {formatDate(user.expires_at, dateFormatter, copy.never)}
                </td>
                <td>
                  {formatDate(user.last_login, dateFormatter, copy.notYet)}
                </td>
                <td>
                  <div className="agent-row-actions">
                    <button
                      className="icon-button icon-button--compact"
                      type="button"
                      disabled={!canManage || !user.manageable}
                      onClick={() => {
                        setError("");
                        setDialog({ mode: "edit", user });
                      }}
                      title={
                        user.manageable ? copy.edit : copy.platformUserProtected
                      }
                      aria-label={`${copy.edit} ${user.username}`}
                    >
                      <Pencil aria-hidden="true" size={15} />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filteredUsers.length === 0 ? (
        <p className="table-empty">{copy.noUsers}</p>
      ) : null}

      {dialog ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section
              className="modal-card user-admin-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="user-dialog-heading"
            >
              <div className="modal-card__heading">
                {dialog.mode === "create" ? (
                  <UserRound aria-hidden="true" size={20} />
                ) : (
                  <ShieldCheck aria-hidden="true" size={20} />
                )}
                <h3 id="user-dialog-heading">
                  {dialog.mode === "create"
                    ? copy.addHeading
                    : copy.editHeading}
                </h3>
                <button
                  className="modal-card__close"
                  type="button"
                  onClick={closeDialog}
                  aria-label={copy.close}
                >
                  ×
                </button>
              </div>
              {dialog.mode === "create" ? (
                <form onSubmit={createUser}>
                  <div className="form-grid form-grid--two-columns">
                    <label>
                      {copy.username}
                      <input
                        name="username"
                        autoComplete="off"
                        required
                        maxLength={150}
                      />
                    </label>
                    <label>
                      {copy.email}
                      <input name="email" type="email" autoComplete="off" />
                    </label>
                    <label>
                      {copy.firstName}
                      <input
                        name="first_name"
                        autoComplete="off"
                        maxLength={150}
                      />
                    </label>
                    <label>
                      {copy.lastName}
                      <input
                        name="last_name"
                        autoComplete="off"
                        maxLength={150}
                      />
                    </label>
                  </div>
                  <label>
                    {copy.initialPassword}
                    <input
                      name="initial_password"
                      type="password"
                      autoComplete="new-password"
                      required
                      minLength={12}
                      maxLength={1024}
                    />
                    <small>{copy.passwordHint}</small>
                  </label>
                  <div className="form-grid form-grid--two-columns">
                    <RoleField copy={copy} />
                    <label>
                      {copy.expirationOptional}
                      <input name="expires_at" type="datetime-local" />
                    </label>
                  </div>
                  {error ? (
                    <p className="form-error" role="alert">
                      {error}
                    </p>
                  ) : null}
                  <DialogActions
                    copy={copy}
                    submitting={submitting}
                    onCancel={closeDialog}
                    submitLabel={copy.create}
                  />
                </form>
              ) : (
                <form onSubmit={updateUser}>
                  <p className="user-admin-dialog__identity">
                    <strong>{dialog.user.username}</strong>
                    <span>{dialog.user.display_name}</span>
                  </p>
                  <RoleField
                    copy={copy}
                    defaultValue={dialog.user.role as EditableRole}
                  />
                  <label>
                    {copy.expirationOptional}
                    <input
                      name="expires_at"
                      type="datetime-local"
                      defaultValue={dateTimeLocal(dialog.user.expires_at)}
                    />
                  </label>
                  <label className="checkbox-field">
                    <input
                      name="is_active"
                      type="checkbox"
                      defaultChecked={dialog.user.membership_active}
                    />
                    <span>{copy.active}</span>
                  </label>
                  {error ? (
                    <p className="form-error" role="alert">
                      {error}
                    </p>
                  ) : null}
                  <DialogActions
                    copy={copy}
                    submitting={submitting}
                    onCancel={closeDialog}
                    submitLabel={copy.save}
                  />
                </form>
              )}
            </section>
          </div>
        </DialogPortal>
      ) : null}
    </section>
  );
}

function RoleField({
  copy,
  defaultValue = "reader",
}: {
  copy: UserCopy;
  defaultValue?: EditableRole;
}) {
  return (
    <label>
      {copy.role}
      <select name="role" defaultValue={defaultValue}>
        {EDITABLE_ROLES.map((role) => (
          <option key={role} value={role}>
            {copy.roles[role]}
          </option>
        ))}
      </select>
    </label>
  );
}

function DialogActions({
  copy,
  submitting,
  onCancel,
  submitLabel,
}: {
  copy: UserCopy;
  submitting: boolean;
  onCancel: () => void;
  submitLabel: string;
}) {
  return (
    <div className="modal-card__actions">
      <button
        className="outline-button"
        type="button"
        onClick={onCancel}
        disabled={submitting}
      >
        {copy.cancel}
      </button>
      <button className="primary-button" type="submit" disabled={submitting}>
        {submitLabel}
      </button>
    </div>
  );
}
