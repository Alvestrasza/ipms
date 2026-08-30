"use client";

import {
  ArrowLeft,
  ArrowRight,
  Check,
  LoaderCircle,
  Plus,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";

type Props = {
  csrfToken: string;
  tenantId: string;
  copy: Dictionary["physical"];
};

export function IloConnectorWizard({ csrfToken, tenantId, copy }: Props) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(1);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  function close() {
    if (submitting) return;
    formRef.current?.reset();
    setOpen(false);
    setStep(1);
    setError("");
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setSubmitting(true);
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/connectors/ilo/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify({
          display_name: form.get("display_name"),
          base_url: form.get("base_url"),
          certificate_sha256: form.get("certificate_sha256"),
          username: form.get("username"),
          password: form.get("password"),
          confirm_read_only: form.get("confirm_read_only") === "on",
        }),
      });
      if (!response.ok) {
        setError(copy.wizardError);
        return;
      }
      formRef.current?.reset();
      setOpen(false);
      setStep(1);
      setSuccess(copy.wizardSuccess);
      router.refresh();
    } catch {
      setError(copy.wizardUnavailable);
    } finally {
      const password = formRef.current?.elements.namedItem("password");
      if (password instanceof HTMLInputElement) password.value = "";
      setSubmitting(false);
    }
  }

  function advance() {
    const fieldset = formRef.current?.querySelectorAll("fieldset")[step - 1];
    const inputs = fieldset?.querySelectorAll("input") ?? [];
    for (const input of inputs) {
      if (!input.reportValidity()) return;
    }
    setStep(step + 1);
  }

  if (!open) {
    return (
      <div className="wizard-launch">
        {success ? (
          <p className="form-success" role="status">
            {success}
          </p>
        ) : null}
        <button
          className="primary-button"
          type="button"
          onClick={() => setOpen(true)}
        >
          <Plus aria-hidden="true" size={16} />
          {copy.addConnector}
        </button>
      </div>
    );
  }

  return (
    <section className="wizard" aria-labelledby="ilo-wizard-heading">
      <div className="wizard__header">
        <div>
          <p className="eyebrow">{copy.wizardEyebrow}</p>
          <h3 id="ilo-wizard-heading">{copy.wizardHeading}</h3>
        </div>
        <button
          className="icon-button"
          type="button"
          onClick={close}
          aria-label={copy.closeWizard}
        >
          <X aria-hidden="true" size={17} />
        </button>
      </div>
      <ol className="wizard__steps" aria-label={copy.wizardProgress}>
        {[copy.stepEndpoint, copy.stepTrust, copy.stepCredential].map(
          (label, index) => (
            <li
              className={
                step === index + 1
                  ? "wizard__step--active"
                  : step > index + 1
                    ? "wizard__step--done"
                    : ""
              }
              key={label}
            >
              <span>
                {step > index + 1 ? (
                  <Check aria-hidden="true" size={13} />
                ) : (
                  index + 1
                )}
              </span>
              {label}
            </li>
          ),
        )}
      </ol>
      <form ref={formRef} onSubmit={submit}>
        <fieldset hidden={step !== 1}>
          <legend>{copy.stepEndpoint}</legend>
          <label>
            {copy.displayName}
            <input
              name="display_name"
              type="text"
              required
              maxLength={255}
              autoComplete="off"
            />
          </label>
          <label>
            {copy.baseUrl}
            <input
              name="base_url"
              type="url"
              required
              placeholder="https://192.0.2.10/"
              autoComplete="off"
            />
          </label>
          <p className="wizard__hint">{copy.endpointHint}</p>
        </fieldset>
        <fieldset hidden={step !== 2}>
          <legend>{copy.stepTrust}</legend>
          <label>
            {copy.fingerprint}
            <input
              name="certificate_sha256"
              type="text"
              required
              minLength={64}
              maxLength={95}
              spellCheck={false}
              autoComplete="off"
            />
          </label>
          <p className="wizard__hint">{copy.fingerprintHint}</p>
        </fieldset>
        <fieldset hidden={step !== 3}>
          <legend>{copy.stepCredential}</legend>
          <label>
            {copy.connectorUsername}
            <input
              name="username"
              type="text"
              required
              maxLength={255}
              autoComplete="off"
            />
          </label>
          <label>
            {copy.connectorPassword}
            <input
              name="password"
              type="password"
              required
              maxLength={4096}
              autoComplete="new-password"
            />
          </label>
          <label className="wizard__confirmation">
            <input name="confirm_read_only" type="checkbox" required />
            {copy.readOnlyConfirmation}
          </label>
          <p className="wizard__hint">{copy.credentialHint}</p>
        </fieldset>
        {error ? (
          <p className="form-error" role="alert">
            {error}
          </p>
        ) : null}
        <div className="wizard__actions">
          {step > 1 ? (
            <button
              className="outline-button"
              type="button"
              onClick={() => setStep(step - 1)}
              disabled={submitting}
            >
              <ArrowLeft aria-hidden="true" size={15} />
              {copy.back}
            </button>
          ) : (
            <span />
          )}
          {step < 3 ? (
            <button className="primary-button" type="button" onClick={advance}>
              {copy.next}
              <ArrowRight aria-hidden="true" size={15} />
            </button>
          ) : (
            <button
              className="primary-button"
              type="submit"
              disabled={submitting}
            >
              {submitting ? (
                <LoaderCircle className="spin" aria-hidden="true" size={16} />
              ) : (
                <Check aria-hidden="true" size={16} />
              )}
              {submitting ? copy.enrolling : copy.enroll}
            </button>
          )}
        </div>
      </form>
    </section>
  );
}
