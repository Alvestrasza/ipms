"use client";

import { KeyRound, LoaderCircle, RefreshCw, Trash2, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";
import type { Dictionary } from "@/i18n/dictionaries";
import type { ManagedConnector } from "@/lib/server-devices";
import { DialogPortal } from "./dialog-portal";

export function ManagedDeviceActions({
  connector,
  csrfToken,
  tenantId,
  copy,
}: {
  connector: ManagedConnector;
  csrfToken: string;
  tenantId: string;
  copy: Dictionary["networkDevices"];
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [busy, setBusy] = useState<"credentials" | "refresh" | "remove" | null>(
    null,
  );
  const [error, setError] = useState("");

  async function request(
    path: string,
    method: "POST" | "DELETE",
    body?: object,
  ) {
    setError("");
    const response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: {
        ...(body ? { "Content-Type": "application/json" } : {}),
        "X-CSRFToken": csrfToken,
        "X-IPMS-Tenant-ID": tenantId,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) throw new Error();
    router.refresh();
  }

  async function rotateCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("credentials");
    const form = new FormData(event.currentTarget);
    try {
      await request(`/api/v1/connectors/${connector.id}/credentials/`, "POST", {
        username: form.get("username"),
        password: form.get("password"),
        privacy_key: form.get("privacy_key") || "",
        api_key: form.get("api_key") || "",
      });
      formRef.current?.reset();
      setDialogOpen(false);
    } catch {
      setError(copy.actionFailed);
    } finally {
      setBusy(null);
    }
  }

  async function refresh() {
    setBusy("refresh");
    try {
      await request(`/api/v1/connectors/${connector.id}/discover/`, "POST", {});
    } catch {
      setError(copy.actionFailed);
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    if (!window.confirm(`${copy.removeConfirm}\n\n${connector.display_name}`)) {
      return;
    }
    setBusy("remove");
    try {
      await request(`/api/v1/connectors/${connector.id}/`, "DELETE");
    } catch {
      setError(copy.actionFailed);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="connector-actions">
      <button
        className="icon-button"
        type="button"
        disabled={busy !== null}
        onClick={() => setDialogOpen(true)}
        aria-label={`${copy.credentials}: ${connector.display_name}`}
        title={copy.credentials}
      >
        <KeyRound aria-hidden="true" size={15} />
      </button>
      <button
        className="icon-button"
        type="button"
        disabled={busy !== null}
        onClick={refresh}
        aria-label={`${copy.refresh}: ${connector.display_name}`}
        title={copy.refresh}
      >
        {busy === "refresh" ? (
          <LoaderCircle className="spin" size={15} />
        ) : (
          <RefreshCw aria-hidden="true" size={15} />
        )}
      </button>
      <button
        className="icon-button icon-button--danger"
        type="button"
        disabled={busy !== null}
        onClick={remove}
        aria-label={`${copy.remove}: ${connector.display_name}`}
        title={copy.remove}
      >
        {busy === "remove" ? (
          <LoaderCircle className="spin" size={15} />
        ) : (
          <Trash2 aria-hidden="true" size={15} />
        )}
      </button>
      {error && !dialogOpen ? (
        <span className="form-error">{error}</span>
      ) : null}
      {dialogOpen ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section className="modal-card" role="dialog" aria-modal="true">
              <div className="modal-card__header">
                <div>
                  <p className="eyebrow">{connector.display_name}</p>
                  <h3>{copy.credentialsHeading}</h3>
                </div>
                <button
                  className="icon-button"
                  type="button"
                  disabled={busy !== null}
                  onClick={() => setDialogOpen(false)}
                  aria-label={copy.close}
                >
                  <X aria-hidden="true" size={17} />
                </button>
              </div>
              <form ref={formRef} onSubmit={rotateCredentials}>
                <label>
                  {copy.username}
                  <input name="username" required autoComplete="username" />
                </label>
                <label>
                  {copy.password}
                  <input
                    name="password"
                    type="password"
                    required
                    autoComplete="new-password"
                  />
                </label>
                {connector.connector_type === "hpe-comware" ? (
                  <label>
                    {copy.privacyKey}
                    <input
                      name="privacy_key"
                      type="password"
                      required
                      autoComplete="off"
                    />
                  </label>
                ) : null}
                {connector.connector_type === "loadbalancer-org" ? (
                  <label>
                    {copy.apiKey}
                    <input
                      name="api_key"
                      type="password"
                      required
                      autoComplete="off"
                    />
                  </label>
                ) : null}
                {error ? <p className="form-error">{error}</p> : null}
                <div className="modal-card__actions">
                  <button
                    className="outline-button"
                    type="button"
                    disabled={busy !== null}
                    onClick={() => setDialogOpen(false)}
                  >
                    {copy.cancel}
                  </button>
                  <button
                    className="primary-button"
                    type="submit"
                    disabled={busy !== null}
                  >
                    {busy === "credentials" ? (
                      <LoaderCircle className="spin" size={16} />
                    ) : (
                      <KeyRound aria-hidden="true" size={16} />
                    )}
                    {copy.saveCredentials}
                  </button>
                </div>
              </form>
            </section>
          </div>
        </DialogPortal>
      ) : null}
    </div>
  );
}
