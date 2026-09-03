import hashlib
import tempfile
import zipfile
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .lifecycle import lifecycle_artifact, offer_lifecycle_job, record_lifecycle_result
from .models import AgentEnrollment, AgentLifecycleJob


class AgentLifecycleTests(TestCase):
    def setUp(self) -> None:
        users = get_user_model()
        self.admin = users.objects.create_user("lifecycle-admin", password="test-password")
        self.reader = users.objects.create_user("lifecycle-reader", password="test-password")
        self.tenant = Tenant.objects.create(slug="lifecycle", display_name="Lifecycle")
        self.other_tenant = Tenant.objects.create(slug="lifecycle-other", display_name="Other")
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
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            display_name="Managed Agent",
            device_uri="urn:ipms:agent:11111111-1111-1111-1111-111111111111",
            status=AgentEnrollment.Status.ACTIVE,
            last_seen_at=timezone.now(),
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=self.enrollment.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            server_type=WindowsServer.ServerType.PHYSICAL,
            hostname="managed-agent",
            fqdn="managed-agent.example.invalid",
            operating_system="Microsoft Windows Server",
            os_version="10.0.26100",
            agent_version="0.1.32",
            agent_state=WindowsServer.AgentState.ONLINE,
            health=WindowsServer.Health.HEALTHY,
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / "agent.zip"
        with zipfile.ZipFile(self.package, "w") as archive:
            archive.writestr("ipms-agent.exe", b"synthetic-agent-0.1.33")
        self.package_digest = hashlib.sha256(self.package.read_bytes()).hexdigest()
        self.settings = override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.package_digest,
            AGENT_WINDOWS_VERSION="0.1.33",
        )
        self.settings.enable()
        self.addCleanup(self.settings.disable)

    def _headers(self, tenant=None):
        return {"HTTP_X_IPMS_TENANT_ID": str((tenant or self.tenant).id)}

    def test_administration_inventory_is_tenant_scoped_and_version_aware(self) -> None:
        self.client.force_login(self.admin)

        response = self.client.get(reverse("core:agent-administration-list"), **self._headers())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        document = response.json()[0]
        self.assertEqual(document["fqdn"], "managed-agent.example.invalid")
        self.assertEqual(document["status"], "online")
        self.assertEqual(document["agent_version"], "0.1.32")
        self.assertEqual(document["target_version"], "0.1.33")
        self.assertEqual(document["compliance"], "outdated")
        self.assertTrue(document["lifecycle_capable"])

    def test_reader_cannot_list_or_queue_agent_lifecycle_operations(self) -> None:
        self.client.force_login(self.reader)

        list_response = self.client.get(reverse("core:agent-administration-list"), **self._headers())
        action_response = self.client.post(
            reverse("core:agent-lifecycle", kwargs={"pk": self.enrollment.id}),
            {"action": "update"},
            content_type="application/json",
            **self._headers(),
        )

        self.assertEqual(list_response.status_code, 403)
        self.assertEqual(action_response.status_code, 403)

    def test_update_job_is_audited_offered_and_completed(self) -> None:
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("core:agent-lifecycle", kwargs={"pk": self.enrollment.id}),
            {"action": "update"},
            content_type="application/json",
            **self._headers(),
        )

        self.assertEqual(response.status_code, 201)
        job = AgentLifecycleJob.objects.get(id=response.json()["id"])
        self.assertEqual(job.status, AgentLifecycleJob.Status.QUEUED)
        self.assertEqual(job.target_version, "0.1.33")
        self.assertEqual(job.artifact_sha256, hashlib.sha256(b"synthetic-agent-0.1.33").hexdigest())
        self.assertTrue(
            AuditEvent.objects.filter(
                tenant=self.tenant,
                action="agent.lifecycle.update.queue",
                object_id=str(job.id),
            ).exists()
        )

        assignment = offer_lifecycle_job(self.enrollment)
        self.assertEqual(assignment["job_id"], str(job.id))
        binary, digest = lifecycle_artifact(self.enrollment, job_id=str(job.id))
        self.assertEqual(binary, b"synthetic-agent-0.1.33")
        self.assertEqual(digest, job.artifact_sha256)
        record_lifecycle_result(
            self.enrollment,
            job_id=str(job.id),
            result="running",
            result_code="accepted",
        )
        record_lifecycle_result(
            self.enrollment,
            job_id=str(job.id),
            result="succeeded",
            result_code="updated",
        )
        job.refresh_from_db()
        self.assertEqual(job.status, AgentLifecycleJob.Status.SUCCEEDED)
        self.assertIsNotNone(job.completed_at)

    def test_legacy_agent_requires_one_time_bootstrap(self) -> None:
        WindowsServer.objects.filter(source_id=self.enrollment.device_uri).update(agent_version="0.1.31")
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("core:agent-lifecycle", kwargs={"pk": self.enrollment.id}),
            {"action": "update"},
            content_type="application/json",
            **self._headers(),
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(AgentLifecycleJob.objects.exists())

    def test_other_tenant_cannot_address_enrollment(self) -> None:
        other_admin = get_user_model().objects.create_user("other-admin", password="test-password")
        TenantMembership.objects.create(
            tenant=self.other_tenant,
            user=other_admin,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        self.client.force_login(other_admin)

        response = self.client.post(
            reverse("core:agent-lifecycle", kwargs={"pk": self.enrollment.id}),
            {"action": "uninstall"},
            content_type="application/json",
            **self._headers(self.other_tenant),
        )

        self.assertEqual(response.status_code, 404)
        self.assertFalse(AgentLifecycleJob.objects.exists())
