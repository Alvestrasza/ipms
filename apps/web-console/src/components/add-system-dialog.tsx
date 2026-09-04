"use client";

import {
  ArrowLeft,
  Boxes,
  LoaderCircle,
  MonitorCog,
  Plus,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type FormEvent, useEffect, useRef, useState } from "react";

import type { Dictionary } from "@/i18n/dictionaries";

import { BmcWizard } from "./bmc-wizard";
import { DialogPortal } from "./dialog-portal";

type Deployment = {
  id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  error_code: string;
};

type LinuxEnrollment = {
  enrollment_id: string;
  bootstrap_document: Record<string, string | number>;
  expires_in_minutes: number;
};

type WindowsCertificate = {
  fingerprint_sha256: string;
  subject: string;
  issuer: string;
  serial_number: string;
  valid_from: string;
  valid_until: string;
  dns_names: string[];
  trusted_by_system: boolean;
};

type WindowsPreflight = {
  transport: "https" | "http";
  port: number;
  approval_token: string;
  requires_explicit_confirmation: boolean;
  requires_explicit_trust?: boolean;
  https_error_code?: string;
  certificate?: WindowsCertificate;
};

type Props = {
  csrfToken: string;
  tenantId: string;
  locale: "de" | "en";
  canManage: boolean;
  copy: Dictionary["addSystem"];
  bmcCopy: Dictionary["bmc"];
};

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

function fingerprint(value: string) {
  return (
    value
      .match(/.{1,2}/g)
      ?.join(":")
      .toUpperCase() ?? value
  );
}

export function AddSystemDialog({
  csrfToken,
  tenantId,
  locale,
  canManage,
  copy,
  bmcCopy,
}: Props) {
  const router = useRouter();
  const windowsFormRef = useRef<HTMLFormElement>(null);
  const [selectorOpen, setSelectorOpen] = useState(false);
  const [bmcOpen, setBmcOpen] = useState(false);
  const [windowsOpen, setWindowsOpen] = useState(false);
  const [linuxOpen, setLinuxOpen] = useState(false);
  const [busy, setBusy] = useState<"checking" | "queuing" | null>(null);
  const [error, setError] = useState("");
  const [password, setPassword] = useState("");
  const [deployment, setDeployment] = useState<Deployment | null>(null);
  const [preflight, setPreflight] = useState<WindowsPreflight | null>(null);
  const [linuxEnrollment, setLinuxEnrollment] =
    useState<LinuxEnrollment | null>(null);

  useEffect(() => {
    if (!deployment || !["queued", "running"].includes(deployment.status)) {
      return;
    }
    const controller = new AbortController();
    const timeout = window.setTimeout(async () => {
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
        const nextDeployment = (await response.json()) as Deployment;
        setDeployment(nextDeployment);
        if (nextDeployment.status === "succeeded") router.refresh();
      } catch (requestError) {
        if (
          !(
            requestError instanceof DOMException &&
            requestError.name === "AbortError"
          )
        ) {
          setError(copy.unavailable);
          setDeployment((current) => (current ? { ...current } : current));
        }
      }
    }, 2000);
    return () => {
      controller.abort();
      window.clearTimeout(timeout);
    };
  }, [copy.unavailable, deployment, router, tenantId]);

  function closeWindows() {
    if (busy) return;
    setWindowsOpen(false);
    setPassword("");
    setDeployment(null);
    setPreflight(null);
    setError("");
  }

  function closeLinux() {
    if (busy) return;
    setLinuxOpen(false);
    setLinuxEnrollment(null);
    setError("");
  }

  async function createLinuxEnrollment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("queuing");
    setError("");
    const form = new FormData(event.currentTarget);
    try {
      const response = await fetch("/api/v1/agents/linux/enrollments/", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
          "X-IPMS-Tenant-ID": tenantId,
        },
        body: JSON.stringify({ display_name: form.get("display_name") }),
      });
      if (!response.ok) throw new Error("linux-enrollment-failed");
      setLinuxEnrollment((await response.json()) as LinuxEnrollment);
    } catch {
      setError(copy.linuxEnrollmentFailed);
    } finally {
      setBusy(null);
    }
  }

  function downloadLinuxEnrollment() {
    if (!linuxEnrollment) return;
    const blob = new Blob(
      [`${JSON.stringify(linuxEnrollment.bootstrap_document, null, 2)}\n`],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "enrollment.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  function deploymentError(code: string | null) {
    const messages: Record<string, string> = {
      windows_certificate_untrusted: copy.certificateUntrusted,
      windows_certificate_changed: copy.certificateChanged,
      windows_certificate_trust_changed: copy.certificateChanged,
      connection_timeout: copy.connectionTimeout,
      connection_failed: copy.connectionFailed,
      target_unresolved: copy.targetUnresolved,
      target_not_private: copy.targetNotPrivate,
      deployment_already_pending: copy.alreadyPending,
      agent_pki_unavailable: copy.pkiUnavailable,
      authentication_failed: copy.authenticationFailed,
      remote_management_failed: copy.remoteManagementFailed,
      agent_package_unavailable: copy.packageUnavailable,
      agent_package_invalid: copy.packageInvalid,
      deployment_failed: copy.deploymentFailed,
      remote_management_unavailable: copy.remoteManagementFailed,
      remote_staging_failed: copy.remoteStagingFailed,
      remote_administrator_required: copy.remoteAdministratorRequired,
      remote_agent_already_installed: copy.remoteAgentAlreadyInstalled,
      remote_existing_agent_assessment_failed:
        copy.remoteExistingAgentAssessmentFailed,
      remote_existing_agent_update_failed: copy.remoteExistingAgentUpdateFailed,
      remote_incomplete_agent_repair_failed:
        copy.remoteIncompleteAgentRepairFailed,
      remote_staging_directory_failed: copy.remoteStagingDirectoryFailed,
      remote_staging_acl_failed: copy.remoteStagingAclFailed,
      remote_package_extract_failed: copy.remotePackageExtractFailed,
      remote_service_install_failed: copy.remoteServiceInstallFailed,
      remote_enrollment_import_failed: copy.remoteEnrollmentImportFailed,
      remote_service_start_failed: copy.remoteServiceStartFailed,
      remote_install_failed: copy.remoteInstallFailed,
      deployment_initialization_failed: copy.deploymentInitializationFailed,
      deployment_package_failed: copy.packageUnavailable,
      deployment_preflight_failed: copy.remoteManagementFailed,
      deployment_staging_failed: copy.remoteStagingFailed,
      deployment_transfer_failed: copy.remoteTransferFailed,
      deployment_install_failed: copy.remoteInstallFailed,
      windows_deployment_approval_expired: copy.approvalExpired,
      windows_deployment_approval_invalid: copy.approvalInvalid,
      windows_deployment_approval_scope_mismatch: copy.approvalInvalid,
      windows_deployment_confirmation_required: copy.confirmationRequired,
    };
    return (code && messages[code]) || copy.deploymentFailed;
  }

  function windowsFormPayload() {
    const form = new FormData(windowsFormRef.current ?? undefined);
    return {
      display_name: form.get("display_name"),
      address: form.get("address"),
      https_port: Number(form.get("port")),
      username: form.get("username"),
    };
  }

  async function checkWindowsConnection(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy("checking");
    setError("");
    const payload = windowsFormPayload();
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
            https_port: payload.https_port,
            allow_http_fallback: true,
          }),
        },
      );
      if (!response.ok) {
        let code: string | null = null;
        try {
          code = responseErrorCode(await response.json());
        } catch {
          // The generic localized message remains the safe fallback.
        }
        setError(deploymentError(code));
        return;
      }
      setPreflight((await response.json()) as WindowsPreflight);
    } catch {
      setError(copy.unavailable);
    } finally {
      setBusy(null);
    }
  }

  async function queueWindows(preflightResult: WindowsPreflight) {
    setBusy("queuing");
    setError("");
    const payload = windowsFormPayload();
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
          display_name: payload.display_name,
          address: payload.address,
          port: preflightResult.port,
          transport: preflightResult.transport,
          approval_token: preflightResult.approval_token,
          confirm_connection: true,
          username: payload.username,
          password,
        }),
      });
      setPassword("");
      if (!response.ok) {
        let code: string | null = null;
        try {
          code = responseErrorCode(await response.json());
        } catch {
          // The generic localized message remains the safe fallback.
        }
        setError(deploymentError(code));
        return;
      }
      setPreflight(null);
      setDeployment((await response.json()) as Deployment);
    } catch {
      setPassword("");
      setError(copy.unavailable);
    } finally {
      setBusy(null);
    }
  }

  const statusLabels = {
    queued: copy.statusQueued,
    running: copy.statusRunning,
    succeeded: copy.statusSucceeded,
    failed: copy.statusFailed,
  };
  const statusLabel = deployment ? statusLabels[deployment.status] : "";
  const terminalError =
    deployment?.status === "failed"
      ? deploymentError(deployment.error_code)
      : "";
  const dateFormatter = new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
  });

  return (
    <>
      <button
        className="topbar-add-system"
        type="button"
        onClick={() => setSelectorOpen(true)}
        disabled={!canManage}
        aria-label={canManage ? copy.addSystem : copy.permissionRequired}
      >
        <Plus aria-hidden="true" size={17} />
        <span>{copy.addSystem}</span>
      </button>

      {selectorOpen ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section
              className="modal-card add-system-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="add-system-heading"
            >
              <div className="wizard__header">
                <div>
                  <p className="eyebrow">{copy.eyebrow}</p>
                  <h3 id="add-system-heading">{copy.heading}</h3>
                </div>
                <button
                  className="icon-button"
                  type="button"
                  onClick={() => setSelectorOpen(false)}
                  aria-label={copy.close}
                >
                  <X aria-hidden="true" size={17} />
                </button>
                <button
                  className="system-choice"
                  type="button"
                  onClick={() => {
                    setSelectorOpen(false);
                    setLinuxOpen(true);
                  }}
                >
                  <TerminalSquare aria-hidden="true" size={31} />
                  <strong>{copy.linux}</strong>
                  <span>{copy.linuxHint}</span>
                </button>
              </div>
              <p>{copy.description}</p>
              <div className="system-choice-grid">
                <button
                  className="system-choice"
                  type="button"
                  onClick={() => {
                    setSelectorOpen(false);
                    setBmcOpen(true);
                  }}
                >
                  <Boxes aria-hidden="true" size={31} />
                  <strong>{copy.bmc}</strong>
                  <span>{copy.bmcHint}</span>
                </button>
                <button
                  className="system-choice"
                  type="button"
                  onClick={() => {
                    setSelectorOpen(false);
                    setWindowsOpen(true);
                  }}
                >
                  <MonitorCog aria-hidden="true" size={31} />
                  <strong>{copy.windows}</strong>
                  <span>{copy.windowsHint}</span>
                </button>
              </div>
            </section>
          </div>
        </DialogPortal>
      ) : null}

      <BmcWizard
        csrfToken={csrfToken}
        tenantId={tenantId}
        locale={locale}
        copy={bmcCopy}
        open={bmcOpen}
        onOpenChange={setBmcOpen}
        showTrigger={false}
        showSuccessMessage={false}
      />

      {linuxOpen ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section
              className="modal-card modal-card--wide"
              role="dialog"
              aria-modal="true"
              aria-labelledby="linux-enrollment-heading"
            >
              <div className="wizard__header">
                <div>
                  <p className="eyebrow">{copy.linuxEyebrow}</p>
                  <h3 id="linux-enrollment-heading">{copy.linuxHeading}</h3>
                </div>
                <button
                  className="icon-button"
                  type="button"
                  onClick={closeLinux}
                  aria-label={copy.close}
                >
                  <X aria-hidden="true" size={17} />
                </button>
              </div>
              {linuxEnrollment ? (
                <div className="deployment-status" role="status">
                  <ShieldCheck aria-hidden="true" size={24} />
                  <div>
                    <strong>{copy.linuxEnrollmentReady}</strong>
                    <span>{copy.linuxEnrollmentInstructions}</span>
                    <button
                      className="primary-button"
                      type="button"
                      onClick={downloadLinuxEnrollment}
                    >
                      {copy.downloadEnrollment}
                    </button>
                  </div>
                </div>
              ) : (
                <form className="wizard" onSubmit={createLinuxEnrollment}>
                  <label>
                    {copy.name}
                    <input
                      name="display_name"
                      type="text"
                      required
                      maxLength={255}
                    />
                  </label>
                  <div className="security-note">
                    <ShieldCheck aria-hidden="true" size={20} />
                    <span>{copy.linuxSecurityNote}</span>
                  </div>
                  {error ? (
                    <p className="form-error" role="alert">
                      {error}
                    </p>
                  ) : null}
                  <div className="wizard__actions">
                    <button
                      className="outline-button"
                      type="button"
                      onClick={() => {
                        setLinuxOpen(false);
                        setSelectorOpen(true);
                      }}
                      disabled={Boolean(busy)}
                    >
                      <ArrowLeft aria-hidden="true" size={15} />
                      {copy.back}
                    </button>
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
                        <TerminalSquare aria-hidden="true" size={16} />
                      )}{" "}
                      {copy.createEnrollment}
                    </button>
                  </div>
                </form>
              )}
            </section>
          </div>
        </DialogPortal>
      ) : null}

      {windowsOpen ? (
        <DialogPortal>
          <div className="modal-backdrop">
            <section
              className="modal-card modal-card--wide windows-deployment-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="windows-deployment-heading"
            >
              <div className="wizard__header">
                <div>
                  <p className="eyebrow">{copy.windowsEyebrow}</p>
                  <h3 id="windows-deployment-heading">{copy.windowsHeading}</h3>
                </div>
                <button
                  className="icon-button"
                  type="button"
                  onClick={closeWindows}
                  aria-label={copy.close}
                >
                  <X aria-hidden="true" size={17} />
                </button>
              </div>

              {deployment ? (
                <div className="deployment-status" role="status">
                  {deployment.status === "queued" ||
                  deployment.status === "running" ? (
                    <LoaderCircle
                      className="spin"
                      aria-hidden="true"
                      size={24}
                    />
                  ) : deployment.status === "failed" ? (
                    <X
                      className="deployment-status__failure"
                      aria-hidden="true"
                      size={24}
                    />
                  ) : (
                    <ShieldCheck aria-hidden="true" size={24} />
                  )}
                  <div>
                    <strong>{statusLabel}</strong>
                    <span>
                      {terminalError ||
                        (deployment.status === "succeeded"
                          ? copy.deploymentSucceeded
                          : copy.deploymentInProgress)}
                    </span>
                  </div>
                </div>
              ) : (
                <form
                  ref={windowsFormRef}
                  className="wizard"
                  onSubmit={checkWindowsConnection}
                >
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
                        placeholder="server.example.invalid"
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
                        defaultValue={5986}
                        required
                      />
                    </label>
                  </div>
                  <label>
                    {copy.username}
                    <input
                      name="username"
                      type="text"
                      required
                      maxLength={255}
                      autoComplete="username"
                    />
                  </label>
                  <label>
                    {copy.password}
                    <input
                      name="password"
                      type="password"
                      required
                      maxLength={4096}
                      autoComplete="current-password"
                      value={password}
                      onChange={(event) => setPassword(event.target.value)}
                    />
                  </label>
                  <div className="security-note">
                    <ShieldCheck aria-hidden="true" size={20} />
                    <span>{copy.credentialNote}</span>
                  </div>
                  <p className="wizard__hint">{copy.winrmRequirement}</p>
                  {error ? (
                    <p className="form-error" role="alert">
                      {error}
                    </p>
                  ) : null}
                  <div className="wizard__actions">
                    <button
                      className="outline-button"
                      type="button"
                      onClick={() => {
                        setWindowsOpen(false);
                        setSelectorOpen(true);
                        setPassword("");
                        setError("");
                      }}
                      disabled={Boolean(busy)}
                    >
                      <ArrowLeft aria-hidden="true" size={15} />
                      {copy.back}
                    </button>
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
                        <MonitorCog aria-hidden="true" size={16} />
                      )}
                      {busy === "checking"
                        ? copy.checkingConnection
                        : busy === "queuing"
                          ? copy.queuing
                          : copy.checkConnection}
                    </button>
                  </div>
                </form>
              )}
            </section>
          </div>
        </DialogPortal>
      ) : null}

      {preflight ? (
        <DialogPortal>
          <div className="modal-backdrop modal-backdrop--nested">
            <section
              className="modal-card certificate-dialog"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="windows-connection-approval-heading"
            >
              <div className="modal-card__heading">
                {preflight.transport === "https" ? (
                  <ShieldCheck aria-hidden="true" size={22} />
                ) : (
                  <ShieldAlert aria-hidden="true" size={22} />
                )}
                <h3 id="windows-connection-approval-heading">
                  {preflight.transport === "https"
                    ? copy.certificateHeading
                    : copy.httpFallbackHeading}
                </h3>
              </div>

              {preflight.transport === "https" && preflight.certificate ? (
                <>
                  <p>
                    {preflight.requires_explicit_trust
                      ? copy.certificateWarning
                      : copy.certificateTrusted}
                  </p>
                  <dl className="certificate-details">
                    <div>
                      <dt>{copy.certificateSubject}</dt>
                      <dd>{preflight.certificate.subject}</dd>
                    </div>
                    <div>
                      <dt>{copy.certificateIssuer}</dt>
                      <dd>{preflight.certificate.issuer}</dd>
                    </div>
                    <div>
                      <dt>{copy.certificateSerial}</dt>
                      <dd>
                        <code>{preflight.certificate.serial_number}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>{copy.certificateDnsNames}</dt>
                      <dd>
                        {preflight.certificate.dns_names.join(", ") || "—"}
                      </dd>
                    </div>
                    <div>
                      <dt>{copy.certificateValidity}</dt>
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
                      <dt>{copy.certificateFingerprint}</dt>
                      <dd>
                        <code>
                          {fingerprint(
                            preflight.certificate.fingerprint_sha256,
                          )}
                        </code>
                      </dd>
                    </div>
                  </dl>
                </>
              ) : (
                <>
                  <p>{copy.httpFallbackWarning}</p>
                  <div className="security-note security-note--warning">
                    <ShieldAlert aria-hidden="true" size={20} />
                    <span>{copy.httpFallbackSecurity}</span>
                  </div>
                </>
              )}

              {error ? (
                <p className="form-error" role="alert">
                  {error}
                </p>
              ) : null}
              <div className="modal-card__actions">
                <button
                  className="outline-button"
                  type="button"
                  onClick={() => {
                    setPreflight(null);
                    setError("");
                  }}
                  disabled={Boolean(busy)}
                >
                  {copy.cancel}
                </button>
                <button
                  className="primary-button"
                  type="button"
                  onClick={() => queueWindows(preflight)}
                  disabled={Boolean(busy)}
                >
                  {busy === "queuing" ? (
                    <LoaderCircle
                      className="spin"
                      aria-hidden="true"
                      size={16}
                    />
                  ) : preflight.transport === "https" ? (
                    <ShieldCheck aria-hidden="true" size={16} />
                  ) : (
                    <ShieldAlert aria-hidden="true" size={16} />
                  )}
                  {busy === "queuing"
                    ? copy.queuing
                    : preflight.transport === "https"
                      ? copy.confirmCertificateAndDeploy
                      : copy.confirmHttpFallbackAndDeploy}
                </button>
              </div>
            </section>
          </div>
        </DialogPortal>
      ) : null}
    </>
  );
}
