"use client";

import { LoaderCircle, ShieldAlert, ShieldCheck, X } from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useEffect, useRef, useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";
import type { ManagedAgent } from "@/lib/server-agents";

import { DialogPortal } from "./dialog-portal";

type Deployment = {
  id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  error_code: string;
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

type Preflight = {
  transport: "https" | "http";
  port: number;
  approval_token: string;
  requires_explicit_trust?: boolean;
  certificate?: Certificate;
};

type Props = {
  agent: ManagedAgent;
  csrfToken: string;
  tenantId: string;
  locale: "de" | "en";
  copy: Dictionary["agentAdministration"];
  deploymentCopy: Dictionary["addSystem"];
  onClose: () => void;
};

function responseErrorCode(value: unknown): string | null {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    for (const item of value) {
      const code = responseErrorCode(item);
      if (code) return code;
    }
  }
  if (value && typeof value === "object") {
    for (const item of Object.values(value)) {
      const code = responseErrorCode(item);
      if (code) return code;
    }
  }
  return null;
}

function fingerprint(value: string) {
  return (
    value
      .match(/.{1,2}/g)
      ?.join(":")
      .toUpperCase() ?? value
  );
}

export function AgentLifecycleBootstrapDialog({
  agent,
  csrfToken,
  tenantId,
  locale,
  copy,
  deploymentCopy,
  onClose,
}: Props) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [busy, setBusy] = useState<"checking" | "queuing" | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [preflight, setPreflight] = useState<Preflight | null>(null);
  const [deployment, setDeployment] = useState<Deployment | null>(null);

  useEffect(() => {
    if (!deployment || !["queued", "running"].includes(deployment.status))
      return;
    const controller = new AbortController();
    const timer = window.setTimeout(async () => {
      try {
        const response = await fetch(
          `/api/v1/agents/windows/deployments/${deployment.id}/`,
          {
            credentials: "same-origin",
            headers: { "X-IPMS-Tenant-ID": tenantId },
            signal: controller.signal,
          },
        );
        if (!response.ok) throw new Error("deployment-status-unavailable");
        const next = (await response.json()) as Deployment;
        setDeployment(next);
        if (next.status === "succeeded") router.refresh();
      } catch (requestError) {
        if (
          !(
            requestError instanceof DOMException &&
            requestError.name === "AbortError"
          )
        ) {
          setError(deploymentCopy.unavailable);
        }
      }
    }, 2000);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [deployment, deploymentCopy.unavailable, router, tenantId]);

  function errorMessage(code: string | null) {
    const messages: Record<string, string> = {
      connection_timeout: deploymentCopy.connectionTimeout,
      connection_failed: deploymentCopy.connectionFailed,
      target_unresolved: deploymentCopy.targetUnresolved,
      target_not_private: deploymentCopy.targetNotPrivate,
      deployment_already_pending: deploymentCopy.alreadyPending,
      authentication_failed: deploymentCopy.authenticationFailed,
      remote_administrator_required: deploymentCopy.remoteAdministratorRequired,
      remote_existing_agent_assessment_failed:
        deploymentCopy.remoteExistingAgentAssessmentFailed,
      remote_existing_agent_identity_mismatch: copy.bootstrapIdentityMismatch,
      remote_existing_agent_update_failed:
        deploymentCopy.remoteExistingAgentUpdateFailed,
      remote_staging_directory_failed:
        deploymentCopy.remoteStagingDirectoryFailed,
      remote_staging_acl_failed: deploymentCopy.remoteStagingAclFailed,
      remote_transfer_failed: deploymentCopy.remoteTransferFailed,
      agent_package_unavailable: deploymentCopy.packageUnavailable,
      agent_package_invalid: deploymentCopy.packageInvalid,
      windows_certificate_changed: deploymentCopy.certificateChanged,
      windows_certificate_trust_changed: deploymentCopy.certificateChanged,
      windows_deployment_approval_expired: deploymentCopy.approvalExpired,
      windows_deployment_approval_invalid: deploymentCopy.approvalInvalid,
      windows_deployment_approval_scope_mismatch:
        deploymentCopy.approvalInvalid,
      agent_lifecycle_bootstrap_not_required: copy.bootstrapNotRequired,
      agent_lifecycle_bootstrap_unavailable: copy.bootstrapUnavailable,
    };
    return (code && messages[code]) || deploymentCopy.deploymentFailed;
  }

  function values() {
    const form = new FormData(formRef.current ?? undefined);
    return {
      address: form.get("address"),
      port: Number(form.get("port")),
      username: form.get("username"),
    };
  }

  async function checkConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("checking");
    setError("");
    const payload = values();
    try {
      const response = await fetch(
        "/api/v1/agents/windows/deployments/preflight/",
        {
          method: "POST",
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken,
            "X-IPMS-Tenant-ID": tenantId,
          },
          body: JSON.stringify({
            address: payload.address,
            https_port: payload.port,
            allow_http_fallback: true,
          }),
        },
      );
      if (!response.ok) {
        setError(errorMessage(responseErrorCode(await response.json())));
        return;
      }
      setPreflight((await response.json()) as Preflight);
    } catch {
      setError(deploymentCopy.unavailable);
    } finally {
      setBusy(null);
    }
  }

  async function queueBootstrap() {
    if (!preflight) return;
    setBusy("queuing");
    setError("");
    const payload = values();
    try {
      const response = await fetch("/api/v1/agents/windows/deployments/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify({
          display_name: agent.fqdn,
          address: payload.address,
          port: preflight.port,
          transport: preflight.transport,
          approval_token: preflight.approval_token,
          confirm_connection: true,
          username: payload.username,
          password,
          existing_enrollment_id: agent.enrollment_id,
        }),
      });
      setPassword("");
      if (!response.ok) {
        setError(errorMessage(responseErrorCode(await response.json())));
        return;
      }
      setPreflight(null);
      setDeployment((await response.json()) as Deployment);
    } catch {
      setPassword("");
      setError(deploymentCopy.unavailable);
    } finally {
      setBusy(null);
    }
  }

  const dateFormatter = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });
  const terminal =
    deployment && !["queued", "running"].includes(deployment.status);

  return (
    <DialogPortal>
      <div className="modal-backdrop">
        <section
          className="modal-card modal-card--wide windows-deployment-dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="agent-bootstrap-heading"
        >
          <div className="modal-card__header">
            <div>
              <p className="eyebrow">{copy.bootstrapEyebrow}</p>
              <h3 id="agent-bootstrap-heading">{copy.bootstrapHeading}</h3>
            </div>
            <button
              className="icon-button"
              type="button"
              onClick={onClose}
              disabled={Boolean(busy)}
              aria-label={deploymentCopy.close}
            >
              <X aria-hidden="true" size={17} />
            </button>
          </div>
          <p>{copy.bootstrapDescription}</p>
          <p>
            <strong>{agent.fqdn}</strong> · v{agent.agent_version || "—"}
          </p>

          {deployment ? (
            <div className="deployment-status" role="status">
              {deployment.status === "queued" ||
              deployment.status === "running" ? (
                <LoaderCircle className="spin" aria-hidden="true" size={20} />
              ) : deployment.status === "succeeded" ? (
                <ShieldCheck aria-hidden="true" size={20} />
              ) : (
                <ShieldAlert aria-hidden="true" size={20} />
              )}
              <div>
                <strong>{copy.bootstrapStates[deployment.status]}</strong>
                <p>
                  {deployment.status === "failed"
                    ? errorMessage(deployment.error_code)
                    : deployment.status === "succeeded"
                      ? copy.bootstrapSucceeded
                      : copy.bootstrapInProgress}
                </p>
              </div>
            </div>
          ) : (
            <form ref={formRef} onSubmit={checkConnection}>
              <label>
                {deploymentCopy.address}
                <input
                  name="address"
                  type="text"
                  defaultValue={agent.fqdn}
                  readOnly={Boolean(preflight)}
                  required
                />
              </label>
              <label>
                {deploymentCopy.port}
                <input
                  name="port"
                  type="number"
                  defaultValue={5986}
                  min={1}
                  max={65535}
                  readOnly={Boolean(preflight)}
                  required
                />
              </label>
              <label>
                {deploymentCopy.username}
                <input
                  name="username"
                  type="text"
                  autoComplete="username"
                  readOnly={Boolean(preflight)}
                  required
                />
              </label>
              <label>
                {deploymentCopy.password}
                <input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  required
                />
              </label>
              <p className="wizard__hint">{deploymentCopy.credentialNote}</p>
            </form>
          )}

          {preflight?.transport === "https" && preflight.certificate ? (
            <div className="certificate-card">
              <div className="certificate-card__heading">
                {preflight.requires_explicit_trust ? (
                  <ShieldAlert aria-hidden="true" size={20} />
                ) : (
                  <ShieldCheck aria-hidden="true" size={20} />
                )}
                <strong>{deploymentCopy.certificateHeading}</strong>
              </div>
              <p>
                {preflight.requires_explicit_trust
                  ? deploymentCopy.certificateWarning
                  : deploymentCopy.certificateTrusted}
              </p>
              <dl>
                <div>
                  <dt>{deploymentCopy.certificateSubject}</dt>
                  <dd>{preflight.certificate.subject}</dd>
                </div>
                <div>
                  <dt>{deploymentCopy.certificateIssuer}</dt>
                  <dd>{preflight.certificate.issuer}</dd>
                </div>
                <div>
                  <dt>{deploymentCopy.certificateSerial}</dt>
                  <dd>{preflight.certificate.serial_number}</dd>
                </div>
                <div>
                  <dt>{deploymentCopy.certificateDnsNames}</dt>
                  <dd>{preflight.certificate.dns_names.join(", ") || "—"}</dd>
                </div>
                <div>
                  <dt>{deploymentCopy.certificateValidity}</dt>
                  <dd>
                    {dateFormatter.format(
                      new Date(preflight.certificate.valid_from),
                    )}{" "}
                    –{" "}
                    {dateFormatter.format(
                      new Date(preflight.certificate.valid_until),
                    )}
                  </dd>
                </div>
                <div>
                  <dt>{deploymentCopy.certificateFingerprint}</dt>
                  <dd>
                    <code>
                      {fingerprint(preflight.certificate.fingerprint_sha256)}
                    </code>
                  </dd>
                </div>
              </dl>
            </div>
          ) : null}

          {preflight?.transport === "http" ? (
            <div className="certificate-card certificate-card--warning">
              <div className="certificate-card__heading">
                <ShieldAlert aria-hidden="true" size={20} />
                <strong>{deploymentCopy.httpFallbackHeading}</strong>
              </div>
              <p>{deploymentCopy.httpFallbackWarning}</p>
              <p>{deploymentCopy.httpFallbackSecurity}</p>
            </div>
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
              onClick={onClose}
              disabled={Boolean(busy)}
            >
              {terminal ? deploymentCopy.close : deploymentCopy.cancel}
            </button>
            {!deployment && !preflight ? (
              <button
                className="primary-button"
                type="button"
                onClick={() => formRef.current?.requestSubmit()}
                disabled={Boolean(busy) || !password}
              >
                {busy === "checking" ? (
                  <LoaderCircle className="spin" aria-hidden="true" size={16} />
                ) : null}
                {busy === "checking"
                  ? deploymentCopy.checkingConnection
                  : deploymentCopy.checkConnection}
              </button>
            ) : null}
            {!deployment && preflight ? (
              <button
                className="primary-button"
                type="button"
                onClick={queueBootstrap}
                disabled={Boolean(busy) || !password}
              >
                {busy === "queuing" ? (
                  <LoaderCircle className="spin" aria-hidden="true" size={16} />
                ) : null}
                {busy === "queuing"
                  ? deploymentCopy.queuing
                  : copy.bootstrapConfirm}
              </button>
            ) : null}
          </div>
        </section>
      </div>
    </DialogPortal>
  );
}
