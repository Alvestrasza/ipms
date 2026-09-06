"use client";

import { KeyRound, Pencil, X } from "lucide-react";
import { type FormEvent, useEffect, useRef, useState } from "react";
import type { Dictionary } from "@/i18n/dictionaries";
import {
  type IdentityAction,
  identityActionDocument,
} from "@/lib/account-security";

type Copy = Dictionary["account"];

export function IdentityActionDialog({
  action,
  username,
  endpoint,
  tenantId,
  csrfToken,
  administrative = false,
  copy,
  onClose,
  onCompleted,
}: {
  action: IdentityAction;
  username: string;
  endpoint: string;
  tenantId?: string;
  csrfToken: string;
  administrative?: boolean;
  copy: Copy;
  onClose: () => void;
  onCompleted: (payload: unknown) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const pending = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  function close() {
    if (!pending.current) onClose();
  }
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending.current) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    pending.current = true;
    setBusy(true);
    setError("");
    const messages: Record<string, string> = {
      password_mismatch: copy.passwordMismatch,
      invalid_request: copy.invalid,
      weak_password: copy.weakPassword,
      current_password_invalid: copy.currentPasswordInvalid,
      forbidden: copy.forbidden,
      username_unavailable: copy.usernameUnavailable,
      shared_identity_protected: copy.sharedIdentityProtected,
      external_identity_managed: copy.externalIdentityManaged,
      self_password_reset_denied: copy.selfPasswordResetDenied,
      user_inactive: copy.userInactive,
      user_not_found: copy.userNotFound,
      rate_limited: copy.rateLimited,
    };
    try {
      const document = identityActionDocument(action, {
        username: String(fields.get("username") ?? ""),
        current_password: String(fields.get("current_password") ?? ""),
        new_password: String(fields.get("new_password") ?? ""),
        confirm_password: String(fields.get("confirm_password") ?? ""),
      });
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          ...(tenantId ? { "X-IPMS-Tenant-ID": tenantId } : {}),
        },
        body: JSON.stringify(document),
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok)
        throw new Error(payload?.error?.code ?? "request_failed");
      onCompleted(payload);
    } catch (caught) {
      setError(
        caught instanceof Error
          ? (messages[caught.message] ?? copy.failed)
          : copy.failed,
      );
    } finally {
      for (const name of [
        "current_password",
        "new_password",
        "confirm_password",
      ]) {
        const input = form.elements.namedItem(name);
        if (input instanceof HTMLInputElement) input.value = "";
        fields.delete(name);
      }
      pending.current = false;
      setBusy(false);
    }
  }
  const title =
    action === "rename"
      ? copy.rename
      : administrative
        ? copy.resetPassword
        : copy.changePassword;
  return (
    <dialog
      ref={dialog}
      className="modal-card service-account-dialog"
      aria-labelledby="identity-dialog-heading"
      onCancel={(event) => {
        event.preventDefault();
        close();
      }}
    >
      <div className="modal-card__heading">
        {action === "rename" ? (
          <Pencil size={20} aria-hidden="true" />
        ) : (
          <KeyRound size={20} aria-hidden="true" />
        )}
        <h3 id="identity-dialog-heading">{title}</h3>
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
      <form onSubmit={submit} autoComplete="off">
        <p>
          <strong>{username}</strong>
        </p>
        <p>
          {action === "rename"
            ? copy.renameWarning
            : administrative
              ? copy.resetWarning
              : copy.passwordWarning}
        </p>
        {action === "rename" ? (
          <label>
            {copy.newUsername}
            <input
              name="username"
              autoComplete="off"
              required
              maxLength={150}
              defaultValue={username}
              disabled={busy}
            />
          </label>
        ) : null}
        <label>
          {administrative ? copy.administratorPassword : copy.currentPassword}
          <input
            name="current_password"
            type="password"
            autoComplete="current-password"
            required
            maxLength={1024}
            disabled={busy}
          />
        </label>
        {administrative ? <p>{copy.administratorPasswordHint}</p> : null}
        {action === "password" ? (
          <>
            <label>
              {copy.newPassword}
              <input
                name="new_password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                maxLength={1024}
                disabled={busy}
              />
            </label>
            <label>
              {copy.confirmPassword}
              <input
                name="confirm_password"
                type="password"
                autoComplete="new-password"
                required
                minLength={12}
                maxLength={1024}
                disabled={busy}
              />
            </label>
            <p>{copy.passwordHint}</p>
          </>
        ) : null}
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
            onClick={close}
          >
            {copy.cancel}
          </button>
          <button className="primary-button" type="submit" disabled={busy}>
            {title}
          </button>
        </div>
      </form>
    </dialog>
  );
}
