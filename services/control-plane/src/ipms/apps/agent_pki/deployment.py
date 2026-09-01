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


class AgentPackageUnavailableError(Exception):
    pass


class AgentPackageIntegrityError(Exception):
    pass


class RemoteDeploymentStepError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
    try:
        if not artifact.is_file():
            raise AgentPackageUnavailableError
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    except OSError as exc:
        raise AgentPackageUnavailableError from exc
    if digest != settings.AGENT_WINDOWS_PACKAGE_SHA256:
        raise AgentPackageIntegrityError
    return artifact


def _execute_checked(client, script: str, *, failure_code: str) -> str:
    output, _, had_errors = client.execute_ps(script)
    if had_errors:
        raise RemoteDeploymentStepError(failure_code)
    return str(output)


def _powershell_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _staging_path_assignment(deployment_id) -> str:
    child_path = f"Alvestrasza\\IPMS Agent\\Staging\\{deployment_id}"
    return (
        "$staging = Join-Path -Path $env:ProgramData -ChildPath "
        f"{_powershell_single_quoted(child_path)}; "
    )


def _agent_path_assignments() -> str:
    return (
        "$install = Join-Path $env:ProgramFiles 'Alvestrasza\\IPMS Agent'; "
        "$agentBinary = Join-Path $install 'ipms-agent.exe'; "
        "$ownerFile = Join-Path $install '.ipms-deployment-owner'; "
        "$configuration = Join-Path $env:ProgramData 'Alvestrasza\\IPMS Agent'; "
        "$state = Join-Path $configuration 'agent-state.json'; "
        "$enrollment = Join-Path $configuration 'enrollment.json'; "
        "$uninstallKey = 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion"
        "\\Uninstall\\IPMSAgent'; "
    )


def _incomplete_install_assessment(known_owner_ids=()) -> str:
    owners = ", ".join(
        _powershell_single_quoted(str(owner_id).lower())
        for owner_id in known_owner_ids
    )
    return _agent_path_assignments() + f"$knownOwnerIds = @({owners}); " + (
        "$service = Get-CimInstance -ClassName Win32_Service "
        "-Filter \"Name='IPMS Agent'\" -ErrorAction SilentlyContinue; "
        "$allowedFiles = @('.ipms-deployment-owner', "
        "'import-windows-agent-enrollment.ps1', "
        "'install-windows-agent.ps1', 'ipms-agent-config.exe', "
        "'ipms-agent.exe', 'ipms-agent-import-enrollment.ps1', "
        "'ipms-agent-uninstall.ps1', 'uninstall-windows-agent.ps1'); "
        "$unexpectedFiles = @(); "
        "if (Test-Path -LiteralPath $install) { "
        "$unexpectedFiles = @(Get-ChildItem -LiteralPath $install -Force | "
        "Where-Object { $_.Name -notin $allowedFiles }) }; "
        "$serviceBinary = if ($service) "
        "{ ([string]$service.PathName).Trim().Trim([char]34) } else { '' }; "
        "$uninstallRegistration = Get-ItemProperty -LiteralPath $uninstallKey "
        "-ErrorAction SilentlyContinue; "
        "$registrationMatches = $null -eq $uninstallRegistration -or "
        "($uninstallRegistration.DisplayName -eq 'IPMS Agent' -and "
        "([string]$uninstallRegistration.InstallLocation).TrimEnd([char]92) "
        "-ieq $install.TrimEnd([char]92)); "
        "$ownerValue = if (Test-Path -LiteralPath $ownerFile) "
        "{ (Get-Content -LiteralPath $ownerFile -Raw -ErrorAction Stop).Trim() } "
        "else { '' }; "
        "$ownerId = [Guid]::Empty; "
        "$ownerIsGuid = [Guid]::TryParse($ownerValue, [ref]$ownerId); "
        "$ownerMatches = $ownerIsGuid -and "
        "$knownOwnerIds -contains $ownerValue.ToLowerInvariant(); "
        "$isIncomplete = $null -ne $service -and "
        "$serviceBinary -ieq $agentBinary -and "
        "$service.StartName -eq 'LocalSystem' -and "
        "$service.State -in @('Stopped', 'Running') -and "
        "(Test-Path -LiteralPath $install) -and "
        "$unexpectedFiles.Count -eq 0 -and "
        "-not (Test-Path -LiteralPath $state) -and "
        "$ownerMatches -and "
        "$registrationMatches; "
    )


def _incomplete_install_guard_script(known_owner_ids=()) -> str:
    return (
        "$ErrorActionPreference = 'Stop'; "
        + _incomplete_install_assessment(known_owner_ids)
        + "if ($service -and -not $isIncomplete) "
        "{ throw 'An existing Agent is not an incomplete portal installation.' }"
    )


def _incomplete_install_repair_script(known_owner_ids=()) -> str:
    return (
        "$ErrorActionPreference = 'Stop'; "
        + _incomplete_install_assessment(known_owner_ids)
        + "if ($service) { "
        "if (-not $isIncomplete) { throw 'The Agent state changed before repair.' }; "
        "if ($service.State -eq 'Running') { "
        "Stop-Service -Name 'IPMS Agent' -Force -ErrorAction Stop; "
        "$serviceStopDeadline = [DateTime]::UtcNow.AddSeconds(10); "
        "do { Start-Sleep -Milliseconds 100; "
        "$service = Get-CimInstance -ClassName Win32_Service "
        "-Filter \"Name='IPMS Agent'\" -ErrorAction SilentlyContinue } "
        "while ($service -and $service.State -ne 'Stopped' -and "
        "[DateTime]::UtcNow -lt $serviceStopDeadline); "
        "if ($service -and $service.State -ne 'Stopped') "
        "{ throw 'Incomplete service stop timed out.' } }; "
        "& sc.exe delete 'IPMS Agent' | Out-Null; "
        "if ($LASTEXITCODE -ne 0) { throw 'Incomplete service removal failed.' }; "
        "$serviceRemovalDeadline = [DateTime]::UtcNow.AddSeconds(5); "
        "do { Start-Sleep -Milliseconds 100; "
        "$remainingService = Get-Service -Name 'IPMS Agent' "
        "-ErrorAction SilentlyContinue } "
        "while ($remainingService -and [DateTime]::UtcNow -lt $serviceRemovalDeadline); "
        "if ($remainingService) { throw 'Incomplete service removal timed out.' }; "
        "Remove-Item -LiteralPath $uninstallKey -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "$controlPanelGuid = '{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}'; "
        "$controlPanelClass = \"HKLM:\\Software\\Classes\\CLSID\\$controlPanelGuid\"; "
        "$controlPanelNamespace = \"HKLM:\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\$controlPanelGuid\"; "
        "Remove-Item -LiteralPath $controlPanelNamespace -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $controlPanelClass -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $install -Recurse -Force; "
        "$shortcut = Join-Path $env:ProgramData "
        "'Microsoft\\Windows\\Start Menu\\Programs\\IPMS Agent'; "
        "Remove-Item -LiteralPath $shortcut -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "$configurationChildren = @(Get-ChildItem -LiteralPath $configuration "
        "-Force -ErrorAction SilentlyContinue); "
        "if ($configurationChildren.Count -eq 0) "
        "{ Remove-Item -LiteralPath $configuration -Force -ErrorAction SilentlyContinue }; "
        "Write-Output 'IPMS_INCOMPLETE_REPAIR=1' "
        "} else { Write-Output 'IPMS_INCOMPLETE_REPAIR=0' }"
    )


def _deployment_rollback_script(deployment_id) -> str:
    owner = _powershell_single_quoted(str(deployment_id))
    return (
        "$ErrorActionPreference = 'Continue'; "
        + _agent_path_assignments()
        + "$ownerFile = Join-Path $install '.ipms-deployment-owner'; "
        f"$expectedOwner = {owner}; "
        "$ownsInstall = (Test-Path -LiteralPath $ownerFile) -and "
        "((Get-Content -LiteralPath $ownerFile -Raw -ErrorAction SilentlyContinue).Trim() "
        "-eq $expectedOwner); "
        "if ($ownsInstall -and -not (Test-Path -LiteralPath $state)) { "
        "$service = Get-CimInstance -ClassName Win32_Service "
        "-Filter \"Name='IPMS Agent'\" -ErrorAction SilentlyContinue; "
        "$serviceBinary = if ($service) "
        "{ ([string]$service.PathName).Trim().Trim([char]34) } else { '' }; "
        "if ($service -and $serviceBinary -ieq $agentBinary) { "
        "Stop-Service -Name 'IPMS Agent' -Force -ErrorAction SilentlyContinue; "
        "& sc.exe delete 'IPMS Agent' | Out-Null }; "
        "Remove-Item -LiteralPath $uninstallKey -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "$controlPanelGuid = '{4B13D2F1-A647-4D4E-B0D7-7EE33E72F691}'; "
        "$controlPanelClass = \"HKLM:\\Software\\Classes\\CLSID\\$controlPanelGuid\"; "
        "$controlPanelNamespace = \"HKLM:\\Software\\Microsoft\\Windows"
        "\\CurrentVersion\\Explorer\\ControlPanel\\NameSpace\\$controlPanelGuid\"; "
        "$shortcut = Join-Path $env:ProgramData "
        "'Microsoft\\Windows\\Start Menu\\Programs\\IPMS Agent'; "
        "Remove-Item -LiteralPath $controlPanelNamespace -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $controlPanelClass -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $shortcut -Recurse -Force "
        "-ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $enrollment -Force -ErrorAction SilentlyContinue; "
        "Remove-Item -LiteralPath $install -Recurse -Force "
        "-ErrorAction SilentlyContinue }"
    )


def _safe_error_code(exc: Exception, *, stage: str) -> str:
    names = {error_type.__name__ for error_type in type(exc).__mro__}
    if names & {
        "AuthenticationError",
        "CredentialsExpiredError",
        "InvalidCredentialError",
        "InvalidCredentialsError",
        "NoCredentialError",
        "SpnegoError",
    }:
        return "authentication_failed"
    if names & {"ConnectTimeout", "ReadTimeout", "TimeoutError"}:
        return "connection_timeout"
    if isinstance(exc, CertificateProbeError):
        return exc.code
    if isinstance(exc, AgentPackageUnavailableError):
        return "agent_package_unavailable"
    if isinstance(exc, AgentPackageIntegrityError):
        return "agent_package_invalid"
    if isinstance(exc, RemoteDeploymentStepError):
        return exc.code
    if names & {
        "ConnectionError",
        "WSManFaultError",
        "WinRMError",
        "WinRMTransportError",
    }:
        return "remote_management_failed"
    safe_stages = {
        "initialization",
        "package",
        "preflight",
        "staging",
        "transfer",
        "install",
    }
    return (
        f"deployment_{stage}_failed"
        if stage in safe_stages
        else "deployment_failed"
    )


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


def _audit(
    deployment: WindowsAgentDeployment,
    *,
    outcome: str,
    error_code: str = "",
    recovered_incomplete_install: bool = False,
):
    details = {
        "target_address": deployment.target_address,
        "target_port": deployment.target_port,
        "transport": deployment.transport,
        "certificate_trust_mode": deployment.certificate_trust_mode,
    }
    if error_code:
        details["error_code"] = error_code
    if recovered_incomplete_install:
        details["recovered_incomplete_install"] = True
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
    staging_path_assignment = _staging_path_assignment(deployment.id)
    succeeded = False
    recovered_incomplete_install = False
    error_code = ""
    stage = "initialization"
    try:
        secret_row = deployment.secret
        secret = load_deployment_secret(secret_row)
        stage = "package"
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
        stage = "preflight"
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
        known_owner_ids = tuple(
            WindowsAgentDeployment.objects.filter(
                tenant_id=deployment.tenant_id,
                target_address__iexact=deployment.target_address,
            )
            .exclude(id=deployment.id)
            .values_list("id", flat=True)
        )
        stage = "staging"
        _execute_checked(
            client,
            staging_path_assignment
            + "$ErrorActionPreference = 'Stop'; "
            + "if (-not ([Security.Principal.WindowsPrincipal] "
            + "[Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("
            + "[Security.Principal.WindowsBuiltInRole]::Administrator)) "
            + "{ throw 'Administrative access is required.' }",
            failure_code="remote_administrator_required",
        )
        _execute_checked(
            client,
            _incomplete_install_guard_script(known_owner_ids),
            failure_code="remote_agent_already_installed",
        )
        repair_output = _execute_checked(
            client,
            _incomplete_install_repair_script(known_owner_ids),
            failure_code="remote_incomplete_agent_repair_failed",
        )
        recovered_incomplete_install = "IPMS_INCOMPLETE_REPAIR=1" in repair_output
        _execute_checked(
            client,
            staging_path_assignment
            + "$ErrorActionPreference = 'Stop'; "
            + "New-Item -ItemType Directory -Path $staging -Force | Out-Null",
            failure_code="remote_staging_directory_failed",
        )
        _execute_checked(
            client,
            staging_path_assignment
            + "$ErrorActionPreference = 'Stop'; "
            + "& icacls.exe $staging /inheritance:r /grant:r "
            + "'*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; "
            + "if ($LASTEXITCODE -ne 0) { throw 'Staging ACL failed.' }",
            failure_code="remote_staging_acl_failed",
        )

        stage = "transfer"
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

        stage = "install"
        owner = _powershell_single_quoted(str(deployment.id))
        extract_script = staging_path_assignment + (
            "$ErrorActionPreference = 'Stop'; "
            "$install = Join-Path $env:ProgramFiles 'Alvestrasza\\IPMS Agent'; "
            "if (Test-Path -LiteralPath $install) "
            "{ throw 'The IPMS Agent directory already exists.' }; "
            "New-Item -ItemType Directory -Path $install -Force | Out-Null; "
            f"Set-Content -LiteralPath (Join-Path $install '.ipms-deployment-owner') "
            f"-Value {owner} -NoNewline; "
            "Expand-Archive -LiteralPath (Join-Path $staging 'agent.zip') "
            "-DestinationPath $install"
        )
        _execute_checked(
            client,
            extract_script,
            failure_code="remote_package_extract_failed",
        )
        _execute_checked(
            client,
            "$ErrorActionPreference = 'Stop'; "
            "$install = Join-Path $env:ProgramFiles 'Alvestrasza\\IPMS Agent'; "
            "& (Join-Path $install 'install-windows-agent.ps1') "
            "-BinaryPath (Join-Path $install 'ipms-agent.exe') "
            "-ConfigBinaryPath (Join-Path $install 'ipms-agent-config.exe') "
            "-StartMode Automatic -ShellIntegration Auto",
            failure_code="remote_service_install_failed",
        )
        stage = "enrollment"
        _execute_checked(
            client,
            staging_path_assignment
            + "$ErrorActionPreference = 'Stop'; "
            + "$install = Join-Path $env:ProgramFiles 'Alvestrasza\\IPMS Agent'; "
            + "& (Join-Path $install 'import-windows-agent-enrollment.ps1') "
            + "-EnrollmentDocument (Join-Path $staging 'enrollment.json')",
            failure_code="remote_enrollment_import_failed",
        )
        stage = "start"
        _execute_checked(
            client,
            "$ErrorActionPreference = 'Stop'; "
            "Start-Service -Name 'IPMS Agent'; "
            "$service = Get-Service -Name 'IPMS Agent'; "
            "if ($service.Status -ne 'Running') { throw 'Agent did not start.' }; "
            "$install = Join-Path $env:ProgramFiles 'Alvestrasza\\IPMS Agent'; "
            "Remove-Item -LiteralPath (Join-Path $install '.ipms-deployment-owner') "
            "-Force",
            failure_code="remote_service_start_failed",
        )
        succeeded = True
    except Exception as exc:  # Safe error codes only; never persist remote output.
        error_code = _safe_error_code(exc, stage=stage)
    finally:
        if client is not None:
            if not succeeded:
                try:
                    client.execute_ps(_deployment_rollback_script(deployment.id))
                except Exception:
                    pass
            try:
                client.execute_ps(
                    staging_path_assignment
                    + "Remove-Item -LiteralPath $staging -Recurse -Force "
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
            recovered_incomplete_install=recovered_incomplete_install,
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
