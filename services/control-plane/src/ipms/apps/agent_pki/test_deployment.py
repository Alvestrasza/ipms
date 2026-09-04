import hashlib
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.certificates import (
    CertificateObservation,
    CertificateProbeError,
    WindowsHttpObservation,
)
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .deployment import (
    _incomplete_install_assessment,
    _incomplete_install_repair_script,
    _managed_existing_agent_assessment,
    _managed_legacy_agent_migration_script,
    _managed_existing_agent_update_script,
    _staging_path_assignment,
    process_deployment,
)
from .deployment_approval import create_windows_deployment_approval
from .deployment_secrets import load_deployment_secret, store_deployment_secret
from .models import (
    AgentEnrollment,
    AgentEnrollmentToken,
    WindowsAgentDeployment,
    WindowsAgentDeploymentSecret,
)
from .services import bootstrap_managed_pki, create_enrollment_token


class WindowsAgentDeploymentScriptTests(TestCase):
    def test_legacy_repair_remains_limited_to_owned_unenrolled_agent(self) -> None:
        owner_id = "11111111-1111-1111-1111-111111111111"
        assessment = _incomplete_install_assessment((owner_id,))

        self.assertIn(f"$knownOwnerIds = @('{owner_id}')", assessment)
        self.assertIn("$service.StartName -eq 'LocalSystem'", assessment)
        self.assertIn("$service.State -in @('Stopped', 'Running')", assessment)
        self.assertIn("$serviceBinary -ieq $agentBinary", assessment)
        self.assertIn("-not (Test-Path -LiteralPath $state)", assessment)
        self.assertNotIn("-not (Test-Path -LiteralPath $enrollment)", assessment)
        self.assertIn("$ownerMatches", assessment)
        self.assertIn("[Guid]::TryParse", assessment)
        self.assertIn("$unexpectedFiles.Count -eq 0", assessment)
        self.assertIn("$registrationMatches", assessment)
        self.assertIn("InstallLocation", assessment)
        self.assertIn(".ipms-deployment-owner", assessment)

    def test_legacy_repair_removes_only_known_ipms_registration(self) -> None:
        repair = _incomplete_install_repair_script()

        self.assertIn("Remove-Item -LiteralPath $uninstallKey", repair)
        self.assertIn("Remove-Item -LiteralPath $controlPanelNamespace", repair)
        self.assertIn("Remove-Item -LiteralPath $controlPanelClass", repair)
        self.assertIn("Remove-Item -LiteralPath $install", repair)
        self.assertIn("Remove-Item -LiteralPath $enrollment", repair)
        self.assertIn("Stop-Service -Name 'IPMS Agent'", repair)
        self.assertIn("IPMS_INCOMPLETE_REPAIR=1", repair)

    def test_existing_update_requires_managed_identity_and_local_system(self) -> None:
        device_uri = "urn:ipms:agent:11111111-1111-1111-1111-111111111111"
        fingerprint = "ab" * 32
        assessment = _managed_existing_agent_assessment(
            expected_device_uri=device_uri,
            expected_certificate_sha256=fingerprint,
            expected_agent_version="0.1.25",
        )
        update = _managed_existing_agent_update_script(
            "22222222-2222-2222-2222-222222222222",
            expected_device_uri=device_uri,
        )

        self.assertIn(device_uri, assessment)
        self.assertIn(fingerprint, assessment)
        self.assertIn("$expectedAgentVersion = '0.1.25'", assessment)
        self.assertIn("$service.StartName -eq 'LocalSystem'", assessment)
        self.assertIn("$serviceBinary -ieq $agentBinary", assessment)
        self.assertIn("$identityMatches", assessment)
        self.assertIn("Cert:\\LocalMachine\\My", assessment)
        self.assertIn("$unexpectedFiles.Count -eq 0", assessment)
        self.assertIn("$registrationMatches", assessment)
        self.assertIn("IPMS_EXISTING_UPDATE", assessment)
        self.assertIn("IPMS_LEGACY_MIGRATION", assessment)
        self.assertIn("$expectedDeviceUri", update)
        self.assertIn("Expand-Archive", update)
        self.assertIn("$backup", update)
        self.assertIn("throw $updateFailure", update)
        self.assertIn("Start-Service -Name 'IPMS Agent'", update)
        self.assertIn("$targetVersion = '0.2.21'", update)
        self.assertIn("-Name DisplayVersion", update)
        self.assertIn("-Value $previousVersion", update)

    def test_legacy_migration_is_device_and_certificate_bound(self) -> None:
        device_uri = "urn:ipms:agent:11111111-1111-1111-1111-111111111111"
        fingerprint = "cd" * 32

        migration = _managed_legacy_agent_migration_script(
            "22222222-2222-2222-2222-222222222222",
            expected_device_uri=device_uri,
            expected_certificate_sha256=fingerprint,
            expected_agent_version="0.1.25",
        )

        self.assertIn(device_uri, migration)
        self.assertIn(fingerprint, migration)
        self.assertIn("$expectedAgentVersion = '0.1.25'", migration)
        self.assertIn("Cert:\\LocalMachine\\My", migration)
        self.assertIn("$service.StartName -ne 'LocalSystem'", migration)
        self.assertIn("Split-Path -Path $legacyBinary -Leaf", migration)
        self.assertIn("sc.exe config 'IPMS Agent'", migration)
        self.assertIn("$legacyBinary", migration)
        self.assertIn("IPMS_LEGACY_AGENT_MIGRATED=1", migration)
        self.assertIn("Remove-Item -LiteralPath $install -Recurse", migration)


class WindowsAgentDeploymentApiTests(TestCase):
    def setUp(self) -> None:
        users = get_user_model()
        self.admin = users.objects.create_user("agent-admin", password="test-password")
        self.reader = users.objects.create_user("agent-reader", password="test-password")
        self.tenant = Tenant.objects.create(slug="agent-deploy", display_name="Agent Deploy")
        self.other_tenant = Tenant.objects.create(slug="agent-other", display_name="Other")
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.admin,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.reader,
            role=TenantMembership.Role.READER,
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "root-recovery.pem",
            recovery_passphrase=b"test-only-recovery-passphrase",
            actor="test-bootstrap",
        )
        self.certificate = CertificateObservation(
            fingerprint_sha256="ab" * 32,
            subject="CN=windows.example.invalid",
            issuer="CN=synthetic-ca",
            serial_number="01",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            dns_names=("windows.example.invalid",),
            trusted_by_system=True,
        )
        probe = patch(
            "ipms.apps.agent_pki.views.request_bmc_certificate_probe",
            return_value=self.certificate,
        )
        self.probe = probe.start()
        self.addCleanup(probe.stop)
        http_probe = patch(
            "ipms.apps.agent_pki.views.request_windows_http_probe",
            return_value=WindowsHttpObservation(reachable=True),
        )
        self.http_probe = http_probe.start()
        self.addCleanup(http_probe.stop)
        self.payload = {
            "display_name": "Synthetic Windows Server",
            "address": "windows.example.invalid",
            "port": 5986,
            "transport": WindowsAgentDeployment.Transport.HTTPS,
            "approval_token": create_windows_deployment_approval(
                tenant_id=str(self.tenant.id),
                address="windows.example.invalid",
                port=5986,
                transport=WindowsAgentDeployment.Transport.HTTPS,
                fingerprint_sha256=self.certificate.fingerprint_sha256,
                trusted_by_system=True,
            ),
            "confirm_connection": True,
            "username": "example\\administrator",
            "password": "test-only-password",
        }

    def post(self, user, tenant=None):
        self.client.force_login(user)
        return self.client.post(
            reverse("core:windows-agent-deployment-list"),
            data=self.payload,
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str((tenant or self.tenant).id)},
        )

    def test_tenant_admin_queues_encrypted_write_only_deployment(self) -> None:
        response = self.post(self.admin)

        self.assertEqual(response.status_code, 201)
        deployment = WindowsAgentDeployment.objects.get()
        secret = WindowsAgentDeploymentSecret.objects.get()
        serialized = str(response.json())
        self.assertNotIn(self.payload["username"], serialized)
        self.assertNotIn(self.payload["password"], serialized)
        self.assertNotIn("certificate_fingerprint", serialized)
        self.assertNotIn(self.payload["username"].encode(), bytes(secret.ciphertext))
        self.assertNotIn(self.payload["password"].encode(), bytes(secret.ciphertext))
        plaintext = load_deployment_secret(secret)
        self.assertEqual(plaintext["username"], self.payload["username"])
        self.assertEqual(plaintext["password"], self.payload["password"])
        self.assertNotEqual(
            plaintext["bootstrap_token"],
            AgentEnrollmentToken.objects.get().token_digest,
        )
        self.assertEqual(deployment.status, WindowsAgentDeployment.Status.QUEUED)
        self.assertTrue(
            AuditEvent.objects.filter(action="agent.windows_deployment.queue").exists()
        )

    def test_admin_can_target_legacy_agent_for_identity_preserving_bootstrap(self) -> None:
        existing = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:11111111-1111-1111-1111-111111111111",
            display_name="Legacy managed Agent",
            status=AgentEnrollment.Status.ACTIVE,
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=existing.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            server_type=WindowsServer.ServerType.PHYSICAL,
            hostname="legacy-agent",
            fqdn="legacy-agent.example.invalid",
            operating_system="Microsoft Windows Server",
            os_version="10.0.26100",
            agent_version="0.1.31",
            agent_state=WindowsServer.AgentState.ONLINE,
            health=WindowsServer.Health.HEALTHY,
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.payload["existing_enrollment_id"] = str(existing.id)

        response = self.post(self.admin)

        self.assertEqual(response.status_code, 201)
        deployment = WindowsAgentDeployment.objects.get()
        self.assertEqual(deployment.lifecycle_bootstrap_enrollment, existing)
        self.assertNotEqual(deployment.enrollment, existing)
        self.assertNotIn(str(existing.id), str(response.json()))
        event = AuditEvent.objects.get(action="agent.windows_deployment.queue")
        self.assertTrue(event.details["lifecycle_bootstrap"])

    def test_current_agent_rejects_redundant_lifecycle_bootstrap(self) -> None:
        existing = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:22222222-2222-2222-2222-222222222222",
            display_name="Current managed Agent",
            status=AgentEnrollment.Status.ACTIVE,
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=existing.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            server_type=WindowsServer.ServerType.PHYSICAL,
            hostname="current-agent",
            fqdn="current-agent.example.invalid",
            operating_system="Microsoft Windows Server",
            os_version="10.0.26100",
            agent_version="0.1.32",
            agent_state=WindowsServer.AgentState.ONLINE,
            health=WindowsServer.Health.HEALTHY,
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.payload["existing_enrollment_id"] = str(existing.id)

        response = self.post(self.admin)

        self.assertEqual(response.status_code, 400)
        self.assertIn("agent_lifecycle_bootstrap_not_required", str(response.json()))
        self.assertFalse(WindowsAgentDeployment.objects.exists())

    def test_preflight_returns_certificate_and_scoped_approval(self) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("core:windows-agent-deployment-preflight"),
            data={
                "address": "windows.example.invalid",
                "https_port": 5986,
                "allow_http_fallback": True,
            },
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["transport"], "https")
        self.assertEqual(
            response.json()["certificate"]["fingerprint_sha256"],
            self.certificate.fingerprint_sha256,
        )
        self.assertNotIn(self.payload["password"], str(response.json()))

    def test_preflight_offers_http_message_encryption_fallback(self) -> None:
        self.probe.side_effect = CertificateProbeError("connection_failed")
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("core:windows-agent-deployment-preflight"),
            data={
                "address": "windows.example.invalid",
                "https_port": 5986,
                "allow_http_fallback": True,
            },
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["transport"], "http")
        self.assertEqual(response.json()["port"], 5985)
        self.assertEqual(response.json()["https_error_code"], "connection_failed")
        self.http_probe.assert_called_once()

    def test_reader_cannot_queue_deployment(self) -> None:
        response = self.post(self.reader)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(WindowsAgentDeployment.objects.exists())

    def test_admin_can_pin_untrusted_winrm_certificate(self) -> None:
        self.probe.return_value = CertificateObservation(
            **{
                **self.certificate.__dict__,
                "trusted_by_system": False,
            }
        )
        self.payload["approval_token"] = create_windows_deployment_approval(
            tenant_id=str(self.tenant.id),
            address="windows.example.invalid",
            port=5986,
            transport=WindowsAgentDeployment.Transport.HTTPS,
            fingerprint_sha256=self.certificate.fingerprint_sha256,
            trusted_by_system=False,
        )
        response = self.post(self.admin)
        self.assertEqual(response.status_code, 201)
        deployment = WindowsAgentDeployment.objects.get()
        self.assertEqual(
            deployment.certificate_trust_mode,
            WindowsAgentDeployment.CertificateTrustMode.PINNED,
        )

    def test_admin_can_confirm_http_message_encryption_fallback(self) -> None:
        self.payload.update(
            {
                "port": 5985,
                "transport": WindowsAgentDeployment.Transport.HTTP,
                "approval_token": create_windows_deployment_approval(
                    tenant_id=str(self.tenant.id),
                    address="windows.example.invalid",
                    port=5985,
                    transport=WindowsAgentDeployment.Transport.HTTP,
                ),
            }
        )

        response = self.post(self.admin)

        self.assertEqual(response.status_code, 201)
        deployment = WindowsAgentDeployment.objects.get()
        self.assertEqual(deployment.transport, WindowsAgentDeployment.Transport.HTTP)
        self.assertEqual(
            deployment.certificate_trust_mode,
            WindowsAgentDeployment.CertificateTrustMode.NONE,
        )
        self.assertEqual(deployment.certificate_fingerprint_sha256, "")

    def test_explicit_connection_confirmation_is_required(self) -> None:
        self.payload["confirm_connection"] = False

        response = self.post(self.admin)

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "windows_deployment_confirmation_required",
            str(response.json()),
        )
        self.assertFalse(WindowsAgentDeployment.objects.exists())

    def test_approval_cannot_be_reused_for_another_endpoint(self) -> None:
        self.payload["port"] = 5985

        response = self.post(self.admin)

        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "windows_deployment_approval_scope_mismatch",
            str(response.json()),
        )
        self.assertFalse(WindowsAgentDeployment.objects.exists())

    def test_active_deployment_is_not_disclosed_to_another_tenant(self) -> None:
        deployment_id = self.post(self.admin).json()["id"]
        self.client.force_login(self.admin)
        response = self.client.get(
            reverse("core:windows-agent-deployment-detail", kwargs={"pk": deployment_id}),
            headers={"X-IPMS-Tenant-ID": str(self.other_tenant.id)},
        )
        self.assertEqual(response.status_code, 404)


class WindowsAgentDeploymentWorkerTests(TestCase):
    def setUp(self) -> None:
        self.tenant = Tenant.objects.create(slug="worker", display_name="Worker")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "root-recovery.pem",
            recovery_passphrase=b"test-only-recovery-passphrase",
            actor="test-bootstrap",
        )
        enrollment, token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Worker target",
            actor="test-operator",
        )
        self.deployment = WindowsAgentDeployment.objects.create(
            tenant=self.tenant,
            enrollment=enrollment,
            display_name="Worker target",
            target_address="windows.example.invalid",
            target_port=5986,
            requested_by="test-operator",
            certificate_fingerprint_sha256="ab" * 32,
            status=WindowsAgentDeployment.Status.RUNNING,
        )
        store_deployment_secret(
            self.deployment,
            username="example\\administrator",
            password="test-only-password",
            bootstrap_token=token,
        )
        self.package = Path(self.temp.name) / "agent.zip"
        self.package.write_bytes(b"synthetic-agent-package")
        self.package_digest = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.certificate = CertificateObservation(
            fingerprint_sha256="ab" * 32,
            subject="CN=windows.example.invalid",
            issuer="CN=synthetic-ca",
            serial_number="01",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            dns_names=("windows.example.invalid",),
            trusted_by_system=True,
        )

    @override_settings()
    @patch("ipms.apps.agent_pki.deployment.request_bmc_certificate_probe")
    @patch("pypsrp.client.Client")
    def test_success_destroys_credentials_and_bootstrap_token(self, client_type, probe):
        probe.return_value = self.certificate
        client = Mock()
        client.execute_ps.return_value = ("", [], False)
        client_type.return_value = client
        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.SUCCEEDED)
        self.assertFalse(WindowsAgentDeploymentSecret.objects.exists())
        self.assertTrue(AgentEnrollmentToken.objects.exists())
        self.assertEqual(client.copy.call_count, 2)
        self.assertNotIn("test-only-password", str(client.mock_calls))
        client_type.assert_called_once()
        self.assertTrue(client_type.call_args.kwargs["ssl"])
        staging_assignment = _staging_path_assignment(self.deployment.id)
        self.assertIn(
            "Join-Path -Path $env:ProgramData -ChildPath "
            "'Alvestrasza\\IPMS Agent\\Staging\\",
            staging_assignment,
        )
        self.assertNotIn("$env:ProgramData\\Alvestrasza", staging_assignment)
        executed_scripts = [
            call.args[0] for call in client.execute_ps.call_args_list
        ]
        self.assertTrue(any("*S-1-5-18" in script for script in executed_scripts))
        self.assertTrue(
            any("*S-1-5-32-544" in script for script in executed_scripts)
        )
        self.assertFalse(
            any("BUILTIN\\Administrators" in script for script in executed_scripts)
        )
        self.assertTrue(
            any("IPMS_INCOMPLETE_REPAIR" in script for script in executed_scripts)
        )
        self.assertTrue(
            any(".ipms-deployment-owner" in script for script in executed_scripts)
        )

    @patch("ipms.apps.agent_pki.deployment.request_bmc_certificate_probe")
    @patch("pypsrp.client.Client")
    def test_pinned_https_certificate_disables_ca_validation_after_recheck(
        self,
        client_type,
        probe,
    ):
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.PINNED
        )
        self.deployment.save(update_fields=("certificate_trust_mode",))
        probe.return_value = CertificateObservation(
            **{
                **self.certificate.__dict__,
                "trusted_by_system": False,
            }
        )
        client = Mock()
        client.execute_ps.return_value = ("", [], False)
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.SUCCEEDED)
        self.assertFalse(client_type.call_args.kwargs["cert_validation"])

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("ipms.apps.agent_pki.deployment.request_bmc_certificate_probe")
    @patch("pypsrp.client.Client")
    def test_http_fallback_requires_ntlm_message_encryption(
        self,
        client_type,
        certificate_probe,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.return_value = ("", [], False)
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.SUCCEEDED)
        certificate_probe.assert_not_called()
        self.assertFalse(client_type.call_args.kwargs["ssl"])
        self.assertEqual(client_type.call_args.kwargs["auth"], "ntlm")
        self.assertEqual(client_type.call_args.kwargs["encryption"], "always")

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_remote_admin_check_failure_uses_bounded_step_code(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.return_value = ("", [], True)
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.FAILED)
        self.assertEqual(
            self.deployment.error_code,
            "remote_administrator_required",
        )
        self.assertFalse(WindowsAgentDeploymentSecret.objects.exists())
        self.assertFalse(AgentEnrollmentToken.objects.exists())

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_remote_acl_failure_uses_bounded_step_code(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.side_effect = (
            ("", [], False),
            ("", [], False),
            ("", [], False),
            ("", [], False),
            ("", [], True),
        )
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.FAILED)
        self.assertEqual(self.deployment.error_code, "remote_staging_acl_failed")
        self.assertFalse(WindowsAgentDeploymentSecret.objects.exists())
        self.assertFalse(AgentEnrollmentToken.objects.exists())

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_incomplete_install_repair_is_bounded_and_audited(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.side_effect = [
            ("", [], False),
            ("", [], False),
            ("IPMS_INCOMPLETE_REPAIR=1", [], False),
            *(("", [], False) for _ in range(7)),
        ]
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.SUCCEEDED)
        event = AuditEvent.objects.get(action="agent.windows_deployment.complete")
        self.assertTrue(event.details["recovered_incomplete_install"])

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_explicit_legacy_agent_is_updated_without_reenrollment(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        existing = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:11111111-1111-1111-1111-111111111111",
            display_name="Existing managed Agent",
            status=AgentEnrollment.Status.ACTIVE,
            certificate_fingerprint_sha256="ab" * 32,
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=existing.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            hostname="existing-managed-agent",
            agent_version="0.1.25",
            discovered_at=timezone.now(),
        )
        self.deployment.lifecycle_bootstrap_enrollment = existing
        self.deployment.save(update_fields=("lifecycle_bootstrap_enrollment",))
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.side_effect = [
            ("", [], False),
            (
                "IPMS_AGENT_PRESENT=1\nIPMS_IDENTITY_MATCH=1\n"
                "IPMS_EXISTING_UPDATE=1\nIPMS_LEGACY_MIGRATION=0",
                [],
                False,
            ),
            ("", [], False),
            ("", [], False),
            ("IPMS_EXISTING_AGENT_UPDATED=1", [], False),
            ("", [], False),
        ]
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.deployment.enrollment.refresh_from_db()
        existing.refresh_from_db()
        self.assertEqual(
            self.deployment.status,
            WindowsAgentDeployment.Status.SUCCEEDED,
        )
        self.assertEqual(client.copy.call_count, 1)
        self.assertEqual(
            self.deployment.enrollment.status,
            AgentEnrollment.Status.REVOKED,
        )
        self.assertEqual(existing.status, AgentEnrollment.Status.ACTIVE)
        self.assertFalse(AgentEnrollmentToken.objects.exists())
        event = AuditEvent.objects.get(action="agent.windows_deployment.complete")
        self.assertTrue(event.details["updated_existing_agent"])

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_explicit_nonstandard_legacy_agent_is_migrated_without_reenrollment(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        existing = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:55555555-5555-5555-5555-555555555555",
            display_name="Nonstandard legacy Agent",
            status=AgentEnrollment.Status.ACTIVE,
            certificate_fingerprint_sha256="ef" * 32,
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=existing.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            hostname="nonstandard-legacy-agent",
            agent_version="0.1.25",
            discovered_at=timezone.now(),
        )
        self.deployment.lifecycle_bootstrap_enrollment = existing
        self.deployment.save(update_fields=("lifecycle_bootstrap_enrollment",))
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.side_effect = [
            ("", [], False),
            (
                "IPMS_AGENT_PRESENT=1\nIPMS_IDENTITY_MATCH=1\n"
                "IPMS_EXISTING_UPDATE=0\nIPMS_LEGACY_MIGRATION=1",
                [],
                False,
            ),
            ("", [], False),
            ("", [], False),
            ("IPMS_LEGACY_AGENT_MIGRATED=1", [], False),
            ("", [], False),
        ]
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.deployment.enrollment.refresh_from_db()
        existing.refresh_from_db()
        self.assertEqual(
            self.deployment.status,
            WindowsAgentDeployment.Status.SUCCEEDED,
        )
        self.assertEqual(client.copy.call_count, 1)
        self.assertEqual(
            self.deployment.enrollment.status,
            AgentEnrollment.Status.REVOKED,
        )
        self.assertEqual(existing.status, AgentEnrollment.Status.ACTIVE)
        event = AuditEvent.objects.get(action="agent.windows_deployment.complete")
        self.assertTrue(event.details["updated_existing_agent"])
        self.assertTrue(event.details["migrated_legacy_agent"])

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_explicit_legacy_bootstrap_fails_closed_on_identity_mismatch(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        existing = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:33333333-3333-3333-3333-333333333333",
            display_name="Selected managed Agent",
            status=AgentEnrollment.Status.ACTIVE,
            certificate_fingerprint_sha256="cd" * 32,
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=existing.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            hostname="selected-managed-agent",
            agent_version="0.1.25",
            discovered_at=timezone.now(),
        )
        self.deployment.lifecycle_bootstrap_enrollment = existing
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "lifecycle_bootstrap_enrollment",
            )
        )
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.side_effect = [
            ("", [], False),
            (
                "IPMS_AGENT_PRESENT=1\nIPMS_IDENTITY_MATCH=0\n"
                "IPMS_EXISTING_UPDATE=0\nIPMS_LEGACY_MIGRATION=0",
                [],
                False,
            ),
            ("", [], False),
        ]
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.FAILED)
        self.assertEqual(
            self.deployment.error_code,
            "remote_existing_agent_identity_mismatch",
        )
        self.assertEqual(client.copy.call_count, 0)

    @patch("pypsrp.client.Client")
    def test_explicit_legacy_bootstrap_rechecks_active_enrollment(
        self,
        client_type,
    ):
        existing = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:44444444-4444-4444-4444-444444444444",
            display_name="Revoked managed Agent",
            status=AgentEnrollment.Status.REVOKED,
        )
        self.deployment.lifecycle_bootstrap_enrollment = existing
        self.deployment.save(update_fields=("lifecycle_bootstrap_enrollment",))

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.FAILED)
        self.assertEqual(
            self.deployment.error_code,
            "agent_lifecycle_bootstrap_unavailable",
        )
        client_type.assert_not_called()
        self.assertFalse(WindowsAgentDeploymentSecret.objects.exists())

    @patch("ipms.apps.agent_pki.deployment.request_windows_http_probe")
    @patch("pypsrp.client.Client")
    def test_service_install_failure_runs_owned_install_rollback(
        self,
        client_type,
        http_probe,
    ):
        self.deployment.transport = WindowsAgentDeployment.Transport.HTTP
        self.deployment.target_port = 5985
        self.deployment.certificate_trust_mode = (
            WindowsAgentDeployment.CertificateTrustMode.NONE
        )
        self.deployment.certificate_fingerprint_sha256 = ""
        self.deployment.save(
            update_fields=(
                "transport",
                "target_port",
                "certificate_trust_mode",
                "certificate_fingerprint_sha256",
            )
        )
        http_probe.return_value = WindowsHttpObservation(reachable=True)
        client = Mock()
        client.execute_ps.side_effect = (
            ("", [], False),
            ("", [], False),
            ("IPMS_INCOMPLETE_REPAIR=0", [], False),
            ("", [], False),
            ("", [], False),
            ("", [], False),
            ("", [], True),
            ("", [], False),
            ("", [], False),
        )
        client_type.return_value = client

        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.FAILED)
        self.assertEqual(self.deployment.error_code, "remote_service_install_failed")
        scripts = [call.args[0] for call in client.execute_ps.call_args_list]
        self.assertIn(".ipms-deployment-owner", scripts[-2])

    @patch("ipms.apps.agent_pki.deployment.request_bmc_certificate_probe")
    def test_failure_still_destroys_transient_secret(self, probe):
        probe.return_value = CertificateObservation(
            **{
                **self.certificate.__dict__,
                "fingerprint_sha256": "cd" * 32,
            }
        )
        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
        ):
            process_deployment(self.deployment)

        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.status, WindowsAgentDeployment.Status.FAILED)
        self.assertEqual(self.deployment.error_code, "windows_certificate_changed")
        self.assertFalse(WindowsAgentDeploymentSecret.objects.exists())
        self.assertFalse(AgentEnrollmentToken.objects.exists())
