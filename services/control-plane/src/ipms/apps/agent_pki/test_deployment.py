import hashlib
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.certificates import (
    CertificateObservation,
    CertificateProbeError,
    WindowsHttpObservation,
)
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .deployment import process_deployment
from .deployment_approval import create_windows_deployment_approval
from .deployment_secrets import load_deployment_secret, store_deployment_secret
from .models import (
    AgentEnrollmentToken,
    WindowsAgentDeployment,
    WindowsAgentDeploymentSecret,
)
from .services import bootstrap_managed_pki, create_enrollment_token


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
    def test_remote_staging_failure_uses_bounded_stage_code(
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
        self.assertEqual(self.deployment.error_code, "remote_staging_failed")
        self.assertFalse(WindowsAgentDeploymentSecret.objects.exists())
        self.assertFalse(AgentEnrollmentToken.objects.exists())

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
