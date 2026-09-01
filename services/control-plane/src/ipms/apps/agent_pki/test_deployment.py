import hashlib
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.certificates import CertificateObservation
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .deployment import process_deployment
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
        self.payload = {
            "display_name": "Synthetic Windows Server",
            "address": "windows.example.invalid",
            "port": 5986,
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

    def test_reader_cannot_queue_deployment(self) -> None:
        response = self.post(self.reader)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(WindowsAgentDeployment.objects.exists())

    def test_untrusted_winrm_certificate_is_rejected(self) -> None:
        self.probe.return_value = CertificateObservation(
            **{
                **self.certificate.__dict__,
                "trusted_by_system": False,
            }
        )
        response = self.post(self.admin)
        self.assertEqual(response.status_code, 400)
        self.assertIn("windows_certificate_untrusted", str(response.json()))
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
