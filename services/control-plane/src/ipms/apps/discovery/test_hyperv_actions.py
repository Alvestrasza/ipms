from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ipms.apps.agent_pki.hyperv_actions import (
    create_hyperv_action_job,
    offer_hyperv_action_job,
    record_hyperv_action_result,
)
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .models import HyperVVirtualMachine, HyperVVirtualMachineActionJob, WindowsServer


class HyperVVirtualMachineActionTests(TestCase):
    def setUp(self) -> None:
        users = get_user_model()
        self.admin = users.objects.create_user("hyperv-admin", password="test-password")
        self.reader = users.objects.create_user("hyperv-reader", password="test-password")
        self.tenant = Tenant.objects.create(slug="hyperv-actions", display_name="Hyper-V actions")
        self.other_tenant = Tenant.objects.create(slug="hyperv-other", display_name="Other")
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
            display_name="Hyper-V host Agent",
            device_uri="urn:ipms:agent:11111111-1111-1111-1111-111111111111",
            platform=AgentEnrollment.Platform.WINDOWS,
            status=AgentEnrollment.Status.ACTIVE,
            last_seen_at=timezone.now(),
        )
        self.host = WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=self.enrollment.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            server_type=WindowsServer.ServerType.PHYSICAL,
            hostname="hyperv-host",
            fqdn="hyperv-host.example.invalid",
            operating_system="Microsoft Windows Server",
            hyperv_inventory_status=WindowsServer.HyperVInventoryStatus.COLLECTED,
            agent_version="0.2.2",
            agent_state=WindowsServer.AgentState.ONLINE,
            health=WindowsServer.Health.HEALTHY,
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant,
            host=self.host,
            source_id="22222222-2222-2222-2222-222222222222",
            name="Test VM",
            state=HyperVVirtualMachine.State.RUNNING,
            observed_at=timezone.now(),
        )

    def _headers(self, tenant=None):
        return {"HTTP_X_IPMS_TENANT_ID": str((tenant or self.tenant).id)}

    def test_tenant_admin_can_queue_and_read_action_job(self) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("core:hyperv-virtual-machine-action", args=(self.vm.id,)),
            {"action": "pause"},
            content_type="application/json",
            **self._headers(),
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json()["status"], "queued")
        status_response = self.client.get(
            reverse("core:hyperv-virtual-machine-action-job", args=(response.json()["id"],)),
            **self._headers(),
        )
        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json()["vm_name"], "Test VM")
        self.assertTrue(AuditEvent.objects.filter(action="hyperv.virtual_machine.action.queue").exists())

    def test_reader_is_denied_and_cross_tenant_identifier_is_hidden(self) -> None:
        self.client.force_login(self.reader)
        denied = self.client.post(
            reverse("core:hyperv-virtual-machine-action", args=(self.vm.id,)),
            {"action": "pause"},
            content_type="application/json",
            **self._headers(),
        )
        self.assertEqual(denied.status_code, 403)
        self.client.force_login(self.admin)
        hidden = self.client.post(
            reverse("core:hyperv-virtual-machine-action", args=(self.vm.id,)),
            {"action": "pause"},
            content_type="application/json",
            **self._headers(self.other_tenant),
        )
        self.assertIn(hidden.status_code, (403, 404))

    def test_action_state_contract_and_single_active_job_are_enforced(self) -> None:
        with self.assertRaises(ValidationError):
            create_hyperv_action_job(virtual_machine=self.vm, action="start", actor="fixture")
        job = create_hyperv_action_job(virtual_machine=self.vm, action="pause", actor="fixture")
        with self.assertRaises(ValidationError):
            create_hyperv_action_job(virtual_machine=self.vm, action="stop", actor="fixture")
        self.assertEqual(job.status, HyperVVirtualMachineActionJob.Status.QUEUED)

    def test_agent_offer_and_result_update_the_inventory_projection(self) -> None:
        job = create_hyperv_action_job(virtual_machine=self.vm, action="pause", actor="fixture")
        assignment = offer_hyperv_action_job(self.enrollment)
        self.assertEqual(
            assignment,
            {
                "job_id": str(job.id),
                "action": "pause",
                "vm_source_id": self.vm.source_id,
                "expected_state": "paused",
            },
        )
        record_hyperv_action_result(
            self.enrollment,
            job_id=str(job.id),
            result="running",
            result_code="accepted",
        )
        record_hyperv_action_result(
            self.enrollment,
            job_id=str(job.id),
            result="succeeded",
            result_code="state_confirmed",
        )
        self.vm.refresh_from_db()
        job.refresh_from_db()
        self.assertEqual(self.vm.state, HyperVVirtualMachine.State.PAUSED)
        self.assertEqual(job.status, HyperVVirtualMachineActionJob.Status.SUCCEEDED)

    def test_failed_result_does_not_change_inventory_state(self) -> None:
        job = create_hyperv_action_job(virtual_machine=self.vm, action="stop", actor="fixture")
        offer_hyperv_action_job(self.enrollment)
        record_hyperv_action_result(
            self.enrollment,
            job_id=str(job.id),
            result="running",
            result_code="accepted",
        )
        record_hyperv_action_result(
            self.enrollment,
            job_id=str(job.id),
            result="failed",
            result_code="invalid_vm_state",
        )
        self.vm.refresh_from_db()
        self.assertEqual(self.vm.state, HyperVVirtualMachine.State.RUNNING)

    def test_legacy_agent_cannot_receive_a_vm_action(self) -> None:
        self.host.agent_version = "0.2.1"
        self.host.save(update_fields=("agent_version",))
        with self.assertRaises(ValidationError):
            create_hyperv_action_job(
                virtual_machine=self.vm,
                action="pause",
                actor="fixture",
            )
