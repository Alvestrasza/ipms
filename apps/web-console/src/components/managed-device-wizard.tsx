"use client";

import { LoaderCircle, Plus, ShieldCheck, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useState } from "react";
import type { Dictionary } from "@/i18n/dictionaries";
import { DialogPortal } from "./dialog-portal";

type ConnectorType = "sophos-firewall" | "loadbalancer-org" | "hpe-comware";
type EnrollmentPayload = {
  connector_type: ConnectorType;
  display_name: string;
  address: string;
  port: number;
  username: string;
  password: string;
  privacy_key: string;
  api_key: string;
};
type CertificateResult = {
  certificate_trust_token: string;
  certificate: {
    subject: string;
    issuer: string;
    fingerprint_sha256: string;
  };
};

const DEFAULT_PORTS: Record<ConnectorType, number> = {
  "sophos-firewall": 4444,
  "loadbalancer-org": 9443,
  "hpe-comware": 161,
};

export function ManagedDeviceWizard({
  csrfToken,
  tenantId,
  copy,
}: {
  csrfToken: string;
  tenantId: string;
  copy: Dictionary["networkDevices"];
}) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [connectorType, setConnectorType] =
    useState<ConnectorType>("sophos-firewall");
  const [certificate, setCertificate] = useState<CertificateResult | null>(
    null,
  );
  const [payload, setPayload] = useState<EnrollmentPayload | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const form = new FormData(event.currentTarget);
    const next: EnrollmentPayload = {
      connector_type: String(form.get("connector_type")) as ConnectorType,
      display_name: String(form.get("display_name")),
      address: String(form.get("address")),
      port: Number(form.get("port")),
      username: String(form.get("username")),
      password: String(form.get("password")),
      privacy_key: String(form.get("privacy_key") || ""),
      api_key: String(form.get("api_key") || ""),
    };
    try {
      if (next.connector_type === "hpe-comware") {
        await enroll(next, null);
        return;
      }
      const response = await fetch("/api/v1/connectors/devices/certificate/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify(next),
      });
      if (!response.ok) throw new Error();
      setPayload(next);
      setCertificate((await response.json()) as CertificateResult);
    } catch {
      setError(copy.failed);
    } finally {
      setBusy(false);
    }
  }

  async function enroll(
    next: EnrollmentPayload,
    trust: CertificateResult | null,
  ) {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/v1/connectors/devices/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify({
          ...next,
          certificate_trust_token: trust?.certificate_trust_token || "",
          confirm_certificate_trust: true,
        }),
      });
      if (!response.ok) throw new Error();
      setOpen(false);
      setCertificate(null);
      setPayload(null);
      router.refresh();
    } catch {
      setError(copy.failed);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <button
        className="primary-button"
        type="button"
        onClick={() => setOpen(true)}
      >
        <Plus size={16} />
        {copy.add}
      </button>
      {open ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section
              className="modal-card modal-card--wide"
              role="dialog"
              aria-modal="true"
            >
              <div className="wizard__header">
                <div>
                  <p className="eyebrow">{copy.eyebrow}</p>
                  <h3>{copy.add}</h3>
                </div>
                <button
                  aria-label="Close"
                  className="icon-button"
                  type="button"
                  onClick={() => setOpen(false)}
                >
                  <X size={17} />
                </button>
              </div>
              {certificate && payload ? (
                <div className="wizard">
                  <div className="security-note">
                    <ShieldCheck size={20} />
                    <span>{copy.certificateConfirm}</span>
                  </div>
                  <dl className="certificate-details">
                    <div>
                      <dt>{copy.subject}</dt>
                      <dd>{certificate.certificate.subject}</dd>
                    </div>
                    <div>
                      <dt>{copy.issuer}</dt>
                      <dd>{certificate.certificate.issuer}</dd>
                    </div>
                    <div>
                      <dt>SHA-256</dt>
                      <dd>
                        <code>
                          {certificate.certificate.fingerprint_sha256}
                        </code>
                      </dd>
                    </div>
                  </dl>
                  {error ? <p className="form-error">{error}</p> : null}
                  <button
                    className="primary-button"
                    type="button"
                    disabled={busy}
                    onClick={() => enroll(payload, certificate)}
                  >
                    {busy ? (
                      <LoaderCircle className="spin" size={16} />
                    ) : (
                      <ShieldCheck size={16} />
                    )}
                    {copy.confirm}
                  </button>
                </div>
              ) : (
                <form className="wizard" onSubmit={submit}>
                  <label>
                    {copy.type}
                    <select
                      name="connector_type"
                      value={connectorType}
                      onChange={(event) =>
                        setConnectorType(event.target.value as ConnectorType)
                      }
                    >
                      <option value="sophos-firewall">Sophos Firewall</option>
                      <option value="loadbalancer-org">
                        Loadbalancer.org ADC
                      </option>
                      <option value="hpe-comware">
                        HPE 5130 / 5900AF (Comware 7.1, SNMPv3)
                      </option>
                    </select>
                  </label>
                  <label>
                    {copy.name}
                    <input name="display_name" required maxLength={255} />
                  </label>
                  <div className="form-grid form-grid--endpoint">
                    <label>
                      {copy.address}
                      <input name="address" required maxLength={253} />
                    </label>
                    <label>
                      {copy.port}
                      <input
                        key={connectorType}
                        name="port"
                        type="number"
                        min={1}
                        max={65535}
                        defaultValue={DEFAULT_PORTS[connectorType]}
                        required
                      />
                    </label>
                  </div>
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
                      autoComplete="current-password"
                    />
                  </label>
                  {connectorType === "hpe-comware" ? (
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
                  {connectorType === "loadbalancer-org" ? (
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
                  <p className="wizard__hint">{copy.snmpHint}</p>
                  {error ? <p className="form-error">{error}</p> : null}
                  <button
                    className="primary-button"
                    type="submit"
                    disabled={busy}
                  >
                    {busy ? (
                      <LoaderCircle className="spin" size={16} />
                    ) : (
                      <Plus size={16} />
                    )}
                    {copy.continue}
                  </button>
                </form>
              )}
            </section>
          </div>
        </DialogPortal>
      ) : null}
    </>
  );
}
