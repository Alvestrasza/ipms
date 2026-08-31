"use client";

import {
  ArrowLeft,
  ArrowRight,
  Check,
  LoaderCircle,
  Plus,
  ShieldCheck,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";

type Props = {
  csrfToken: string;
  tenantId: string;
  locale: "de" | "en";
  copy: Dictionary["bmc"];
};

type Certificate = {
  fingerprint_sha256: string;
  subject: string;
  issuer: string;
  serial_number: string;
  valid_from: string;
  valid_until: string;
  dns_names: string[];
  trusted_by_system: boolean;
};

type CertificateProbe = {
  certificate: Certificate;
  requires_explicit_trust: boolean;
  certificate_trust_token: string;
};

function fingerprint(value: string) {
  return (
    value
      .match(/.{1,2}/g)
      ?.join(":")
      .toUpperCase() ?? value
  );
}

function responseErrorCode(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = responseErrorCode(item);
      if (found) return found;
    }
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) {
      const found = responseErrorCode(item);
      if (found) return found;
    }
  }
  return null;
}

export function BmcWizard({ csrfToken, tenantId, locale, copy }: Props) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState(1);
  const [busy, setBusy] = useState<"checking" | "adding" | null>(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [certificateProbe, setCertificateProbe] =
    useState<CertificateProbe | null>(null);

  async function enrollmentError(response: Response) {
    let code: string | null = null;
    try {
      code = responseErrorCode(await response.json());
    } catch {
      // The generic localized message remains the safe fallback.
    }
    const messages: Record<string, string> = {
      connection_timeout: copy.connectionTimeout,
      connection_failed: copy.connectionFailed,
      authentication_failed: copy.authenticationFailed,
      duplicate_endpoint: copy.duplicateEndpoint,
      certificate_pin_mismatch: copy.certificateChanged,
    };
    return (code && messages[code]) || copy.addError;
  }

  function resetAndClose() {
    if (busy) return;
    formRef.current?.reset();
    setOpen(false);
    setStep(1);
    setError("");
    setCertificateProbe(null);
  }

  function formPayload() {
    const form = new FormData(formRef.current ?? undefined);
    return {
      bmc_family: form.get("bmc_family"),
      display_name: form.get("display_name"),
      address: form.get("address"),
      port: Number(form.get("port")),
      username: form.get("username"),
      password: form.get("password"),
    };
  }

  async function enroll(probe: CertificateProbe, explicitTrust: boolean) {
    setBusy("adding");
    setError("");
    try {
      const response = await fetch("/api/v1/connectors/bmc/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify({
          ...formPayload(),
          certificate_trust_token: probe.certificate_trust_token,
          confirm_certificate_trust: explicitTrust,
        }),
      });
      if (!response.ok) {
        setError(await enrollmentError(response));
        return;
      }
      formRef.current?.reset();
      setCertificateProbe(null);
      setOpen(false);
      setStep(1);
      setSuccess(copy.addSuccess);
      router.refresh();
    } catch {
      setError(copy.unavailable);
    } finally {
      const password = formRef.current?.elements.namedItem("password");
      if (password instanceof HTMLInputElement) password.value = "";
      setBusy(null);
    }
  }

  async function checkCertificate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setBusy("checking");
    try {
      const payload = formPayload();
      const response = await fetch("/api/v1/connectors/bmc/certificate/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify({
          bmc_family: payload.bmc_family,
          display_name: payload.display_name,
          address: payload.address,
          port: payload.port,
        }),
      });
      if (!response.ok) {
        setError(await enrollmentError(response));
        return;
      }
      const probe = (await response.json()) as CertificateProbe;
      if (probe.requires_explicit_trust) {
        setCertificateProbe(probe);
      } else {
        await enroll(probe, false);
      }
    } catch {
      setError(copy.unavailable);
    } finally {
      setBusy((current) => (current === "checking" ? null : current));
    }
  }

  function advance() {
    const fieldset = formRef.current?.querySelectorAll("fieldset")[step - 1];
    const fields = fieldset?.querySelectorAll("input, select") ?? [];
    for (const field of fields) {
      if (
        field instanceof HTMLInputElement ||
        field instanceof HTMLSelectElement
      ) {
        if (!field.reportValidity()) return;
      }
    }
    setStep((current) => current + 1);
  }

  const dateFormatter = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });

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
        {copy.addBmc}
      </button>

      {open ? (
        <div className="modal-backdrop">
          <section
            className="modal-card modal-card--wide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="bmc-wizard-heading"
          >
            <div className="wizard__header">
              <div>
                <p className="eyebrow">{copy.eyebrow}</p>
                <h3 id="bmc-wizard-heading">{copy.addHeading}</h3>
              </div>
              <button
                className="icon-button"
                type="button"
                onClick={resetAndClose}
                aria-label={copy.close}
              >
                <X aria-hidden="true" size={17} />
              </button>
            </div>
            <ol className="wizard__steps" aria-label={copy.progress}>
              {[copy.stepType, copy.stepEndpoint, copy.stepCredentials].map(
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
            <form ref={formRef} className="wizard" onSubmit={checkCertificate}>
              <fieldset hidden={step !== 1}>
                <legend>{copy.stepType}</legend>
                <label>
                  {copy.family}
                  <select name="bmc_family" defaultValue="hpe-ilo4" required>
                    <option value="hpe-ilo4">{copy.familyIlo4}</option>
                    <option value="hpe-ilo-modern">
                      {copy.familyIloModern}
                    </option>
                    <option value="dell-idrac">{copy.familyIdrac}</option>
                    <option value="generic-redfish">
                      {copy.familyRedfish}
                    </option>
                  </select>
                </label>
              </fieldset>
              <fieldset hidden={step !== 2}>
                <legend>{copy.stepEndpoint}</legend>
                <label>
                  {copy.name}
                  <input
                    name="display_name"
                    type="text"
                    required
                    maxLength={255}
                  />
                </label>
                <div className="form-grid form-grid--endpoint">
                  <label>
                    {copy.address}
                    <input
                      name="address"
                      type="text"
                      required
                      maxLength={253}
                      placeholder="192.0.2.10"
                      spellCheck={false}
                    />
                  </label>
                  <label>
                    {copy.port}
                    <input
                      name="port"
                      type="number"
                      min={1}
                      max={65535}
                      defaultValue={443}
                      required
                    />
                  </label>
                </div>
                <p className="wizard__hint">{copy.addressHint}</p>
              </fieldset>
              <fieldset hidden={step !== 3}>
                <legend>{copy.stepCredentials}</legend>
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
                    onClick={() => setStep((current) => current - 1)}
                    disabled={Boolean(busy)}
                  >
                    <ArrowLeft aria-hidden="true" size={15} />
                    {copy.back}
                  </button>
                ) : (
                  <span />
                )}
                {step < 3 ? (
                  <button
                    className="primary-button"
                    type="button"
                    onClick={advance}
                  >
                    {copy.next}
                    <ArrowRight aria-hidden="true" size={15} />
                  </button>
                ) : (
                  <button
                    className="primary-button"
                    type="submit"
                    disabled={Boolean(busy)}
                  >
                    {busy ? (
                      <LoaderCircle
                        className="spin"
                        aria-hidden="true"
                        size={16}
                      />
                    ) : (
                      <Check aria-hidden="true" size={16} />
                    )}
                    {busy === "checking"
                      ? copy.checkingCertificate
                      : busy === "adding"
                        ? copy.adding
                        : copy.add}
                  </button>
                )}
              </div>
            </form>
          </section>
        </div>
      ) : null}

      {certificateProbe ? (
        <div className="modal-backdrop modal-backdrop--nested">
          <section
            className="modal-card certificate-dialog"
            role="alertdialog"
            aria-modal="true"
            aria-labelledby="certificate-heading"
          >
            <div className="modal-card__heading">
              <ShieldCheck aria-hidden="true" size={22} />
              <h3 id="certificate-heading">{copy.certificateHeading}</h3>
            </div>
            <p>{copy.certificateWarning}</p>
            <dl className="certificate-details">
              <div>
                <dt>{copy.certificateSubject}</dt>
                <dd>{certificateProbe.certificate.subject}</dd>
              </div>
              <div>
                <dt>{copy.certificateIssuer}</dt>
                <dd>{certificateProbe.certificate.issuer}</dd>
              </div>
              <div>
                <dt>{copy.certificateSerial}</dt>
                <dd>
                  <code>{certificateProbe.certificate.serial_number}</code>
                </dd>
              </div>
              <div>
                <dt>{copy.certificateDnsNames}</dt>
                <dd>
                  {certificateProbe.certificate.dns_names.join(", ") || "—"}
                </dd>
              </div>
              <div>
                <dt>{copy.certificateValidity}</dt>
                <dd>
                  {dateFormatter.format(
                    new Date(certificateProbe.certificate.valid_from),
                  )}{" "}
                  –{" "}
                  {dateFormatter.format(
                    new Date(certificateProbe.certificate.valid_until),
                  )}
                </dd>
              </div>
              <div>
                <dt>{copy.certificateFingerprint}</dt>
                <dd>
                  <code>
                    {fingerprint(
                      certificateProbe.certificate.fingerprint_sha256,
                    )}
                  </code>
                </dd>
              </div>
            </dl>
            <div className="modal-card__actions">
              <button
                className="outline-button"
                type="button"
                onClick={() => setCertificateProbe(null)}
                disabled={Boolean(busy)}
              >
                {copy.cancel}
              </button>
              <button
                className="primary-button"
                type="button"
                onClick={() => enroll(certificateProbe, true)}
                disabled={Boolean(busy)}
              >
                {busy ? (
                  <LoaderCircle className="spin" aria-hidden="true" size={16} />
                ) : (
                  <ShieldCheck aria-hidden="true" size={16} />
                )}
                {busy ? copy.adding : copy.trustAndAdd}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </div>
  );
}
