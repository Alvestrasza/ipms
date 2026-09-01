from __future__ import annotations

import hashlib
import ipaddress
import json
import tempfile
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.certificates import (
    CertificateProbeError,
    request_bmc_certificate_probe,
    request_windows_http_probe,
)

from .deployment_secrets import load_deployment_secret
from .models import WindowsAgentDeployment


def _claim_next_deployment() -> WindowsAgentDeployment | None:
    with transaction.atomic():
        deployment = (
            WindowsAgentDeployment.objects.select_for_update(skip_locked=True)
            .select_related("tenant", "enrollment", "enrollment__tenant")
            .filter(status=WindowsAgentDeployment.Status.QUEUED)
            .order_by("created_at")
            .first()
        )
        if deployment is None:
            return None
        deployment.status = WindowsAgentDeployment.Status.RUNNING
        deployment.started_at = timezone.now()
        deployment.error_code = ""
        deployment.save(update_fields=("status", "started_at", "error_code"))
        return deployment


def _artifact() -> Path:
    artifact = Path(settings.AGENT_WINDOWS_PACKAGE_PATH)
    if not artifact.is_file():
        raise FileNotFoundError("Agent package unavailable")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != settings.AGENT_WINDOWS_PACKAGE_SHA256:
        raise ValueError("Agent package integrity check failed")
    return artifact


def _execute_checked(client, script: str) -> None:
    _, _, had_errors = client.execute_ps(script)
    if had_errors:
        raise RuntimeError("Remote fixed deployment step failed")


def _safe_error_code(exc: Exception) -> str:
    name = type(exc).__name__
    if name in {"AuthenticationError", "InvalidCredentialsError"}:
        return "authentication_failed"
    if name in {"ConnectTimeout", "ReadTimeout", "TimeoutError"}:
        return "connection_timeout"
    if isinstance(exc, CertificateProbeError):
        return exc.code
    if isinstance(exc, FileNotFoundError):
        return "agent_package_unavailable"
    if isinstance(exc, ValueError):
        return "agent_package_invalid"
    if name in {"WinRMTransportError", "WSManFaultError", "ConnectionError"}:
        return "remote_management_failed"
    return "deployment_failed"


def _https_origin(address: str, port: int) -> str:
    try:
        host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    except ValueError:
        host = address
    return f"https://{host}:{port}/"


def _http_origin(address: str, port: int) -> str:
    try:
        host = f"[{address}]" if ipaddress.ip_address(address).version == 6 else address
    except ValueError:
        host = address
    return f"http://{host}:{port}/wsman"


def _audit(deployment: WindowsAgentDeployment, *, outcome: str, error_code: str = ""):
    details = {
        "target_address": deployment.target_address,
        "target_port": deployment.target_port,
        "transport": deployment.transport,
        "certificate_trust_mode": deployment.certificate_trust_mode,
    }
    if error_code:
        details["error_code"] = error_code
    AuditEvent.objects.create(
        tenant=deployment.tenant,
        actor="ipms-agent-deployment-worker",
        action="agent.windows_deployment.complete",
        object_type="windows_agent_deployment",
        object_id=str(deployment.id),
        outcome=outcome,
        details=details,
    )


def process_deployment(deployment: WindowsAgentDeployment) -> None:
    client = None
    secret_row = None
    remote_staging = (
        "$env:ProgramData\\Alvestrasza\\IPMS Agent\\Staging\\"
        f"{deployment.id}"
    )
    succeeded = False
    error_code = ""
    try:
        secret_row = deployment.secret
        secret = load_deployment_secret(secret_row)
        artifact = _artifact()
        client_options = {
            "username": secret["username"],
            "password": secret["password"],
            "port": deployment.target_port,
            "auth": "ntlm",
            "connection_timeout": settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
            "read_timeout": settings.AGENT_DEPLOYMENT_READ_TIMEOUT_SECONDS,
            "no_proxy": True,
        }
        if deployment.transport == WindowsAgentDeployment.Transport.HTTPS:
            observation = request_bmc_certificate_probe(
                _https_origin(
                    deployment.target_address,
                    deployment.target_port,
                ),
                timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                port=settings.CERTIFICATE_PROBE_PORT,
                token=settings.CERTIFICATE_PROBE_TOKEN,
            )
            if (
                observation.fingerprint_sha256
                != deployment.certificate_fingerprint_sha256
            ):
                raise CertificateProbeError("windows_certificate_changed")
            if (
                deployment.certificate_trust_mode
                == WindowsAgentDeployment.CertificateTrustMode.SYSTEM
                and not observation.trusted_by_system
            ):
                raise CertificateProbeError("windows_certificate_trust_changed")
            client_options.update(
                {
                    "ssl": True,
                    "cert_validation": (
                        settings.AGENT_DEPLOYMENT_CA_BUNDLE
                        if deployment.certificate_trust_mode
                        == WindowsAgentDeployment.CertificateTrustMode.SYSTEM
                        else False
                    ),
                    "encryption": "auto",
                }
            )
        else:
            request_windows_http_probe(
                _http_origin(
                    deployment.target_address,
                    deployment.target_port,
                ),
                timeout=settings.AGENT_DEPLOYMENT_CONNECT_TIMEOUT_SECONDS,
                port=settings.CERTIFICATE_PROBE_PORT,
                token=settings.CERTIFICATE_PROBE_TOKEN,
            )
            client_options.update(
                {
                    "ssl": False,
                    "cert_validation": False,
                    "encryption": "always",
                }
            )

        from pypsrp.client import Client

        client = Client(
            deployment.target_address,
            **client_options,
        )
        staging_path = (
            f"$staging = {remote_staging}; "
            "$ErrorActionPreference = 'Stop'; "
            "if (-not ([Security.Principal.WindowsPrincipal] "
            "[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("
            "[Security.Principal.WindowsBuiltInRole]::Administrator)) "
            "{ throw 'Administrative access is required.' }; "
            "if (Get-Service -Name 'IPMS Agent' -ErrorAction SilentlyContinue) "
            "{ throw 'The IPMS Agent service already exists.' }; "
            "New-Item -ItemType Directory -Path $staging -Force | Out-Null; "
            "& icacls.exe $staging /inheritance:r /grant:r "
            "'SYSTEM:(OI)(CI)F' 'BUILTIN\\Administrators:(OI)(CI)F' | Out-Null; "
            "if ($LASTEXITCODE -ne 0) { throw 'Staging ACL failed.' }"
        )
        _execute_checked(client, staging_path)

        with tempfile.TemporaryDirectory(prefix="ipms-agent-deployment-") as temp:
            enrollment_path = Path(temp) / "enrollment.json"
            policy = deployment.tenant.agent_pki_policy
            enrollment_path.write_text(
                json.dumps(
                    {
                        "device_uri": deployment.enrollment.device_uri,
                        "gateway_dns_name": policy.gateway_dns_name,
                        "gateway_port": policy.gateway_port,
                        "gateway_fingerprint_sha256": (
                            policy.gateway_identity.fingerprint_sha256
                        ),
                        "bootstrap_token": secret["bootstrap_token"],
                    },
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            remote_package = (
                f"C:\\ProgramData\\Alvestrasza\\IPMS Agent\\Staging\\"
                f"{deployment.id}\\agent.zip"
            )
            remote_enrollment = (
                f"C:\\ProgramData\\Alvestrasza\\IPMS Agent\\Staging\\"
                f"{deployment.id}\\enrollment.json"
            )
            client.copy(str(artifact), remote_package)
            client.copy(str(enrollment_path), remote_enrollment)

        deploy_script = (
            f"$staging = {remote_staging}; "
            "$ErrorActionPreference = 'Stop'; "
            "$install = Join-Path $env:ProgramFiles 'Alvestrasza\\IPMS Agent'; "
            "try { "
            "if (Test-Path -LiteralPath $install) "
            "{ throw 'The IPMS Agent directory already exists.' }; "
            "New-Item -ItemType Directory -Path $install -Force | Out-Null; "
            "Expand-Archive -LiteralPath (Join-Path $staging 'agent.zip') "
            "-DestinationPath $install; "
            "& (Join-Path $install 'install-windows-agent.ps1') "
            "-BinaryPath (Join-Path $install 'ipms-agent.exe') "
            "-ConfigBinaryPath (Join-Path $install 'ipms-agent-config.exe') "
            "-StartMode Automatic; "
            "& (Join-Path $install 'import-windows-agent-enrollment.ps1') "
            "-EnrollmentDocument (Join-Path $staging 'enrollment.json'); "
            "Start-Service -Name 'IPMS Agent'; "
            "$service = Get-Service -Name 'IPMS Agent'; "
            "if ($service.Status -ne 'Running') { throw 'Agent did not start.' } "
            "} finally { Remove-Item -LiteralPath $staging -Recurse -Force "
            "-ErrorAction SilentlyContinue }"
        )
        _execute_checked(client, deploy_script)
        succeeded = True
    except Exception as exc:  # Safe error codes only; never persist remote output.
        error_code = _safe_error_code(exc)
    finally:
        if client is not None:
            try:
                client.execute_ps(
                    f"Remove-Item -LiteralPath {remote_staging} -Recurse -Force "
                    "-ErrorAction SilentlyContinue"
                )
            except Exception:
                pass
        WindowsAgentDeployment.objects.filter(id=deployment.id).update(
            status=(
                WindowsAgentDeployment.Status.SUCCEEDED
                if succeeded
                else WindowsAgentDeployment.Status.FAILED
            ),
            error_code=error_code,
            completed_at=timezone.now(),
        )
        if not succeeded:
            deployment.enrollment.bootstrap_tokens.filter(used_at__isnull=True).delete()
        if secret_row is not None:
            secret_row.delete()
        _audit(
            deployment,
            outcome=(
                AuditEvent.Outcome.SUCCEEDED
                if succeeded
                else AuditEvent.Outcome.FAILED
            ),
            error_code=error_code,
        )


def process_deployment_queue(*, limit: int) -> int:
    processed = 0
    while processed < limit:
        deployment = _claim_next_deployment()
        if deployment is None:
            break
        process_deployment(deployment)
        processed += 1
    return processed
