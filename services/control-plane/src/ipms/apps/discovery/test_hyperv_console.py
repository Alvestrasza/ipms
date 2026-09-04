import base64
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ipms.apps.agent_pki.hyperv_console import process_console_cycle
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .models import (
    HyperVConsoleInputEvent,
    HyperVConsoleSession,
    HyperVVirtualMachine,
    WindowsServer,
)


class HyperVConsoleTests(TestCase):
    def setUp(self) -> None:
        users = get_user_model()
        self.admin = users.objects.create_user("console-admin", password="test-password")
        self.other_admin = users.objects.create_user("other-admin", password="test-password")
        self.reader = users.objects.create_user("console-reader", password="test-password")
        self.tenant = Tenant.objects.create(slug="console", display_name="Console")
        self.other_tenant = Tenant.objects.create(slug="other", display_name="Other")
        for user, role in (
            (self.admin, TenantMembership.Role.TENANT_ADMIN),
            (self.other_admin, TenantMembership.Role.TENANT_ADMIN),
            (self.reader, TenantMembership.Role.READER),
        ):
            TenantMembership.objects.create(tenant=self.tenant, user=user, role=role)
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            display_name="Hyper-V host Agent",
            device_uri="urn:ipms:agent:31111111-1111-1111-1111-111111111111",
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
            agent_version="0.2.17",
            agent_state=WindowsServer.AgentState.ONLINE,
            health=WindowsServer.Health.HEALTHY,
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant,
            host=self.host,
            source_id="32222222-2222-2222-2222-222222222222",
            name="Console VM",
            state=HyperVVirtualMachine.State.RUNNING,
            observed_at=timezone.now(),
        )

    def headers(self):
        return {"HTTP_X_IPMS_TENANT_ID": str(self.tenant.id)}

    def create_session(self):
        self.client.force_login(self.admin)
        return self.client.post(
            reverse("core:hyperv-console-session-create", args=(self.vm.id,)),
            {},
            content_type="application/json",
            **self.headers(),
        )

    def test_admin_can_open_one_console_and_second_user_receives_occupancy(self) -> None:
        created = self.create_session()
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["status"], "requested")
        self.assertTrue(
            AuditEvent.objects.filter(action="hyperv.virtual_machine.console.open").exists()
        )

        self.client.force_login(self.other_admin)
        occupied = self.client.post(
            reverse("core:hyperv-console-session-create", args=(self.vm.id,)),
            {},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(occupied.status_code, 409)
        self.assertEqual(occupied.json()["code"], "console_session_in_use")
        self.assertEqual(occupied.json()["session"]["requested_by"], "console-admin")

    def test_reader_is_denied(self) -> None:
        self.client.force_login(self.reader)
        denied = self.client.post(
            reverse("core:hyperv-console-session-create", args=(self.vm.id,)),
            {},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(denied.status_code, 403)

    def test_other_operator_cannot_observe_control_or_close_owned_session(self) -> None:
        session_id = self.create_session().json()["id"]
        self.client.force_login(self.other_admin)
        for method, route, document in (
            (
                self.client.get,
                reverse("core:hyperv-console-session", args=(session_id,)),
                None,
            ),
            (
                self.client.post,
                reverse("core:hyperv-console-input", args=(session_id,)),
                {"type": "secure_attention", "payload": {}},
            ),
            (
                self.client.delete,
                reverse("core:hyperv-console-session", args=(session_id,)),
                None,
            ),
        ):
            if document is None:
                response = method(route, **self.headers())
            else:
                response = method(
                    route,
                    document,
                    content_type="application/json",
                    **self.headers(),
                )
            self.assertEqual(response.status_code, 404)
        self.assertEqual(
            HyperVConsoleSession.objects.get(id=session_id).status,
            HyperVConsoleSession.Status.REQUESTED,
        )

    def test_agent_cycle_activates_session_and_delivers_bounded_input(self) -> None:
        created = self.create_session().json()
        session_id = created["id"]
        input_response = self.client.post(
            reverse("core:hyperv-console-input", args=(session_id,)),
            {"type": "key", "payload": {"key_code": 65, "is_down": True}},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(input_response.status_code, 202)

        assignment = process_console_cycle(
            self.enrollment,
            session_id="",
            frame_png_base64="",
            frame_width=0,
            frame_height=0,
            acknowledged_input_ids=[],
            failure_code="",
        )
        self.assertEqual(assignment["session_id"], session_id)
        self.assertEqual(assignment["inputs"][0]["key_code"], 65)

        png = b"\x89PNG\r\n\x1a\nfixture"
        process_console_cycle(
            self.enrollment,
            session_id=session_id,
            frame_png_base64=base64.b64encode(png).decode(),
            frame_width=1024,
            frame_height=768,
            acknowledged_input_ids=[input_response.json()["id"]],
            failure_code="",
        )
        session = HyperVConsoleSession.objects.get(id=session_id)
        self.assertEqual(session.status, HyperVConsoleSession.Status.ACTIVE)
        self.assertEqual(session.frame_sequence, 1)
        self.assertEqual(bytes(session.frame_png), png)
        self.assertEqual(HyperVConsoleInputEvent.objects.count(), 0)

        frame = self.client.get(
            reverse("core:hyperv-console-frame", args=(session_id,)),
            **self.headers(),
        )
        self.assertEqual(frame.status_code, 200)
        self.assertEqual(frame["Content-Type"], "image/png")
        self.assertEqual(frame["X-IPMS-Frame-Sequence"], "1")

    def test_host_agent_rotates_between_distinct_vm_sessions(self) -> None:
        first_session_id = self.create_session().json()["id"]
        second_vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant,
            host=self.host,
            source_id="33333333-3333-3333-3333-333333333333",
            name="Second Console VM",
            state=HyperVVirtualMachine.State.RUNNING,
            observed_at=timezone.now(),
        )
        second = self.client.post(
            reverse("core:hyperv-console-session-create", args=(second_vm.id,)),
            {},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(second.status_code, 201)
        second_session_id = second.json()["id"]

        first_assignment = process_console_cycle(
            self.enrollment,
            session_id="",
            frame_png_base64="",
            frame_width=0,
            frame_height=0,
            acknowledged_input_ids=[],
            failure_code="",
        )
        self.assertEqual(first_assignment["session_id"], first_session_id)
        next_assignment = process_console_cycle(
            self.enrollment,
            session_id=first_session_id,
            frame_png_base64=base64.b64encode(b"\x89PNG\r\n\x1a\nfirst").decode(),
            frame_width=1024,
            frame_height=768,
            acknowledged_input_ids=[],
            failure_code="",
        )
        self.assertEqual(next_assignment["session_id"], second_session_id)

    def test_secure_attention_is_dedicated_and_audited(self) -> None:
        session_id = self.create_session().json()["id"]
        response = self.client.post(
            reverse("core:hyperv-console-input", args=(session_id,)),
            {"type": "secure_attention", "payload": {}},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 202)
        self.assertTrue(
            AuditEvent.objects.filter(
                action="hyperv.virtual_machine.console.secure_attention"
            ).exists()
        )

    def test_owner_can_close_and_stale_lease_releases_vm(self) -> None:
        session_id = self.create_session().json()["id"]
        closed = self.client.delete(
            reverse("core:hyperv-console-session", args=(session_id,)),
            **self.headers(),
        )
        self.assertEqual(closed.status_code, 204)
        self.assertEqual(
            HyperVConsoleSession.objects.get(id=session_id).status,
            HyperVConsoleSession.Status.CLOSED,
        )
        reopened = self.create_session()
        self.assertEqual(reopened.status_code, 201)
        active = HyperVConsoleSession.objects.get(id=reopened.json()["id"])
        active.lease_expires_at = timezone.now() - timedelta(seconds=1)
        active.save(update_fields=("lease_expires_at",))
        again = self.create_session()
        self.assertEqual(again.status_code, 201)

    def test_console_requires_running_vm_and_capable_agent(self) -> None:
        self.vm.state = HyperVVirtualMachine.State.STOPPED
        self.vm.save(update_fields=("state",))
        response = self.create_session()
        self.assertEqual(response.status_code, 400)
        self.vm.state = HyperVVirtualMachine.State.RUNNING
        self.vm.save(update_fields=("state",))
        self.host.agent_version = "0.2.16"
        self.host.save(update_fields=("agent_version",))
        response = self.create_session()
        self.assertEqual(response.status_code, 400)
