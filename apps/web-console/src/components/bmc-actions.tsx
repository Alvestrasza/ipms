"use client";

import {
  KeyRound,
  LoaderCircle,
  Minus,
  RefreshCw,
  Trash2,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";
import type { ConnectorEndpoint } from "@/lib/server-physical";

type Props = {
  connector: ConnectorEndpoint;
  csrfToken: string;
  tenantId: string;
  copy: Dictionary["bmc"];
  discoveryCopy: Dictionary["physical"];
};

export function BmcActions({
  connector,
  csrfToken,
  tenantId,
  copy,
  discoveryCopy,
}: Props) {
  const router = useRouter();
  const credentialForm = useRef<HTMLFormElement>(null);
  const [dialog, setDialog] = useState<"credentials" | "remove" | null>(null);
  const [busy, setBusy] = useState<
    "credentials" | "remove" | "discovery" | null
  >(null);
  const [error, setError] = useState("");

  function close() {
    if (busy) return;
    credentialForm.current?.reset();
    setDialog(null);
    setError("");
  }

  async function resetCredentials(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("credentials");
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch(
        `/api/v1/connectors/${connector.id}/credentials/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({
            username: form.get("username"),
            password: form.get("password"),
          }),
        },
      );
      if (!response.ok) {
        setError(copy.credentialError);
        return;
      }
      credentialForm.current?.reset();
      setDialog(null);
      setError("");
      router.refresh();
    } catch {
      setError(copy.credentialError);
    } finally {
      const password = credentialForm.current?.elements.namedItem("password");
      if (password instanceof HTMLInputElement) password.value = "";
      setBusy(null);
    }
  }

  async function removeConnector() {
    setBusy("remove");
    setError("");
    try {
      const response = await fetch(`/api/v1/connectors/${connector.id}/`, {
        method: "DELETE",
        credentials: "same-origin",
        headers: {
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
      });
      if (!response.ok) {
        setError(copy.removeError);
        return;
      }
      setDialog(null);
      router.refresh();
    } catch {
      setError(copy.removeError);
    } finally {
      setBusy(null);
    }
  }

  async function runDiscovery() {
    setBusy("discovery");
    setError("");
    try {
      const response = await fetch(
        `/api/v1/connectors/${connector.id}/discover/`,
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: "{}",
        },
      );
      if (!response.ok) setError(discoveryCopy.discoveryError);
      else router.refresh();
    } catch {
      setError(discoveryCopy.discoveryError);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="bmc-actions">
      <button
        className="icon-button icon-button--compact"
        type="button"
        onClick={() => setDialog("credentials")}
        aria-label={`${copy.resetCredentials}: ${connector.display_name}`}
        title={copy.resetCredentials}
      >
        <KeyRound aria-hidden="true" size={15} />
      </button>
      <button
        className="icon-button icon-button--compact"
        type="button"
        onClick={runDiscovery}
        disabled={busy !== null}
        aria-label={`${discoveryCopy.runDiscovery}: ${connector.display_name}`}
        title={discoveryCopy.runDiscovery}
      >
        {busy === "discovery" ? (
          <LoaderCircle className="spin" aria-hidden="true" size={15} />
        ) : (
          <RefreshCw aria-hidden="true" size={15} />
        )}
      </button>
      <button
        className="icon-button icon-button--compact icon-button--danger"
        type="button"
        onClick={() => setDialog("remove")}
        aria-label={`${copy.remove}: ${connector.display_name}`}
        title={copy.remove}
      >
        <Minus aria-hidden="true" size={16} />
      </button>
      {!dialog && error ? (
        <span className="form-error" role="alert">
          {error}
        </span>
      ) : null}

      {dialog === "credentials" ? (
        <div className="modal-backdrop">
          <section
            className="modal-card"
            role="dialog"
            aria-modal="true"
            aria-labelledby={`credential-heading-${connector.id}`}
          >
            <div className="modal-card__header">
              <div>
                <p className="eyebrow">{connector.display_name}</p>
                <h3 id={`credential-heading-${connector.id}`}>
                  {copy.resetHeading}
                </h3>
              </div>
              <button
                className="icon-button"
                type="button"
                onClick={close}
                aria-label={copy.close}
              >
                <X aria-hidden="true" size={17} />
              </button>
            </div>
            <p>{copy.resetDescription}</p>
            <form ref={credentialForm} onSubmit={resetCredentials}>
              <label>
                {copy.username}
                <input name="username" type="text" required maxLength={255} />
              </label>
              <label>
                {copy.password}
                <input
                  name="password"
                  type="password"
                  required
                  maxLength={4096}
                  autoComplete="new-password"
                />
              </label>
              <p className="wizard__hint">{copy.credentialHint}</p>
              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  className="outline-button"
                  type="button"
                  onClick={close}
                  disabled={busy !== null}
                >
                  {copy.cancel}
                </button>
                <button
                  className="primary-button"
                  type="submit"
                  disabled={busy !== null}
                >
                  {busy === "credentials" ? (
                    <LoaderCircle
                      className="spin"
                      aria-hidden="true"
                      size={16}
                    />
                  ) : (
                    <KeyRound aria-hidden="true" size={16} />
                  )}
                  {busy === "credentials"
                    ? copy.savingCredentials
                    : copy.saveCredentials}
                </button>
              </div>
            </form>
          </section>
        </div>
      ) : null}

      {dialog === "remove" ? (
        <div className="modal-backdrop">
          <section
            className="modal-card"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby={`remove-heading-${connector.id}`}
          >
            <div className="modal-card__heading modal-card__heading--danger">
              <Trash2 aria-hidden="true" size={22} />
              <h3 id={`remove-heading-${connector.id}`}>
                {copy.removeHeading}
              </h3>
            </div>
            <p>{copy.removeDescription}</p>
            {error ? (
              <p className="form-error" role="alert">
                {error}
              </p>
            ) : null}
            <div className="modal-card__actions">
              <button
                className="outline-button"
                type="button"
                onClick={close}
                disabled={busy !== null}
              >
                {copy.cancel}
              </button>
              <button
                className="danger-button"
                type="button"
                onClick={removeConnector}
                disabled={busy !== null}
              >
                {busy === "remove" ? (
                  <LoaderCircle className="spin" aria-hidden="true" size={16} />
                ) : (
                  <Minus aria-hidden="true" size={16} />
                )}
                {busy === "remove" ? copy.removing : copy.confirmRemove}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}
