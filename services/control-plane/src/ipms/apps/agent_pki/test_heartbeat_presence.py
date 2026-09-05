import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import (
    HyperVConsoleSession, HyperVVirtualMachine, WindowsServer, WindowsServerTelemetry,
)
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .models import AgentEnrollment
from .hyperv_console import create_console_session
from . import views


class AgentHeartbeatPresenceTests(TestCase):
    def setUp(self):
        self.now = timezone.now()
        self.old = self.now - timedelta(minutes=10)
        self.tenant = Tenant.objects.create(slug="heartbeat-presence", display_name="Presence")
        self.admin = get_user_model().objects.create_user("presence-admin", password="test-password")
        TenantMembership.objects.create(
            tenant=self.tenant, user=self.admin, role=TenantMembership.Role.TENANT_ADMIN,
        )
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            display_name="Presence Agent",
            device_uri="urn:ipms:agent:44444444-1111-1111-1111-111111111111",
            status=AgentEnrollment.Status.ACTIVE,
            last_seen_at=self.old,
        )
        self.server = WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=self.enrollment.device_uri,
            inventory_source=WindowsServer.InventorySource.AGENT,
            hostname="presence-host",
            fqdn="presence-host.example.invalid",
            agent_version="0.2.23",
            discovered_at=self.old,
            last_seen_at=self.old,
        )
        self.telemetry = WindowsServerTelemetry.objects.create(
            tenant=self.tenant, server=self.server,
            cpu_used_percent=10, memory_total_bytes=100, memory_available_bytes=75,
            memory_used_bytes=25, memory_used_percent=25, observed_at=self.old,
        )
        self.client.force_login(self.admin)
        self.headers = {"HTTP_X_IPMS_TENANT_ID": str(self.tenant.id)}

    def document(self):
        response = self.client.get(reverse("core:agent-administration-list"), **self.headers)
        self.assertEqual(response.status_code, 200)
        return response.json()[0]

    def remove(self):
        return self.client.delete(
            reverse("core:agent-administration-detail", kwargs={"pk": self.enrollment.id}),
            **self.headers,
        )

    def assert_removal_denied(self):
        response = self.remove()
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"]["code"], "agent_removal_not_allowed")
        self.assertFalse(AuditEvent.objects.filter(action="agent.remove").exists())

    def session(self, **overrides):
        values = {
            "tenant": self.tenant,
            "enrollment": self.enrollment,
            "vm_source_id": str(uuid.uuid4()),
            "vm_name": "Presence test VM",
            "requested_by": self.admin.username,
            "status": HyperVConsoleSession.Status.ACTIVE,
            "lease_expires_at": self.now + timedelta(seconds=30),
            "last_activity_at": self.now,
            "last_agent_contact_at": self.now,
        }
        values.update(overrides)
        return HyperVConsoleSession.objects.create(**values)

    def test_fresh_heartbeat_is_online_without_refreshing_inventory_or_telemetry(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(last_heartbeat_at=self.now)

        document = self.document()

        self.assertEqual(document["status"], "online")
        self.assertFalse(document["can_remove"])
        self.assertEqual(parse_datetime(document["last_seen_at"]), self.now)
        self.assertEqual(parse_datetime(document["last_heartbeat_at"]), self.now)
        self.assertEqual(parse_datetime(document["last_inventory_at"]), self.old)
        self.assertEqual(parse_datetime(document["last_telemetry_at"]), self.old)
        self.assert_removal_denied()
        self.enrollment.refresh_from_db()
        self.server.refresh_from_db()
        self.telemetry.refresh_from_db()
        self.assertEqual(self.enrollment.last_seen_at, self.old)
        self.assertEqual(self.server.last_seen_at, self.old)
        self.assertEqual(self.telemetry.observed_at, self.old)

    def test_old_heartbeat_is_offline_and_removable(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(last_heartbeat_at=self.old)
        document = self.document()
        self.assertEqual(document["status"], "offline")
        self.assertTrue(document["can_remove"])
        self.assertEqual(self.remove().status_code, 204)

    def test_recent_but_not_online_heartbeat_remains_stale_and_not_removable(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(
            last_heartbeat_at=self.now - timedelta(minutes=2),
        )
        self.assertEqual(self.document()["status"], "stale")
        self.assert_removal_denied()

    def test_presence_thresholds_preserve_45_second_and_five_minute_boundaries(self):
        for seconds, expected in ((45, "online"), (46, "stale"), (300, "stale"), (301, "offline")):
            with self.subTest(seconds=seconds), patch(
                "ipms.apps.agent_pki.views.timezone.now", return_value=self.now,
            ):
                AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(
                    last_heartbeat_at=self.now - timedelta(seconds=seconds),
                )
                self.assertEqual(self.document()["status"], expected)

    def test_heartbeat_proves_contact_before_first_inventory_without_faking_inventory(self):
        self.server.delete()
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(
            last_seen_at=None, last_heartbeat_at=self.now,
        )
        document = self.document()
        self.assertEqual(document["status"], "online")
        self.assertIsNone(document["last_inventory_at"])
        self.assertIsNone(document["last_telemetry_at"])
        self.assert_removal_denied()

    def test_unseen_enrollment_without_heartbeat_is_still_not_seen_and_removable(self):
        self.server.delete()
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(last_seen_at=None)
        document = self.document()
        self.assertEqual(document["status"], "not-seen")
        self.assertIsNone(document["last_seen_at"])
        self.assertTrue(document["can_remove"])
        self.assertEqual(self.remove().status_code, 204)

    def test_latest_legacy_contact_is_used_even_when_server_inventory_is_old(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(last_seen_at=self.now)
        document = self.document()
        self.assertEqual(document["status"], "online")
        self.assertEqual(parse_datetime(document["last_seen_at"]), self.now)
        self.assert_removal_denied()

    def test_latest_server_contact_is_used_even_when_enrollment_is_old(self):
        WindowsServer.objects.filter(pk=self.server.pk).update(last_seen_at=self.now)
        self.assertEqual(self.document()["status"], "online")
        self.assert_removal_denied()

    def test_legacy_active_console_contact_keeps_agent_online(self):
        self.session()
        document = self.document()
        self.assertEqual(document["status"], "online")
        self.assertEqual(parse_datetime(document["last_seen_at"]), self.now)
        self.assertFalse(document["can_remove"])
        self.assert_removal_denied()

    def test_active_lease_blocks_removal_without_claiming_stalled_agent_is_online(self):
        self.session(last_agent_contact_at=self.old)
        document = self.document()
        self.assertEqual(document["status"], "offline")
        self.assertFalse(document["can_remove"])
        self.assert_removal_denied()

    def test_requested_lease_blocks_removal_before_any_agent_response(self):
        self.session(status=HyperVConsoleSession.Status.REQUESTED, last_agent_contact_at=None)
        document = self.document()
        self.assertEqual(document["status"], "offline")
        self.assertFalse(document["can_remove"])
        self.assert_removal_denied()

    def test_console_lease_committed_while_removal_waits_for_enrollment_lock_is_protected(self):
        get_object_or_404 = views.get_object_or_404

        def lock_acquired(*args, **kwargs):
            enrollment = get_object_or_404(*args, **kwargs)
            # Simulate a console creation committed just before this lock was
            # acquired, after the removal request captured its initial time.
            started = timezone.now()
            self.session(
                status=HyperVConsoleSession.Status.REQUESTED,
                last_activity_at=started,
                lease_expires_at=started + timedelta(seconds=30),
                last_agent_contact_at=None,
            )
            return enrollment

        with patch.object(views, "get_object_or_404", side_effect=lock_acquired):
            self.assert_removal_denied()

    def test_expired_closed_or_malformed_console_lease_does_not_prove_presence(self):
        cases = (
            {"lease_expires_at": self.now - timedelta(seconds=1)},
            {"status": HyperVConsoleSession.Status.CLOSED},
            {"closed_at": self.now},
            {"lease_expires_at": self.now + timedelta(hours=1)},
            {"last_activity_at": self.now + timedelta(hours=1)},
        )
        for values in cases:
            with self.subTest(values=values):
                session = self.session(**values)
                document = self.document()
                self.assertEqual(document["status"], "offline")
                self.assertTrue(document["can_remove"])
                session.delete()

    def test_foreign_tenant_console_cannot_affect_presence_or_removal(self):
        other_tenant = Tenant.objects.create(slug="presence-other", display_name="Other")
        self.session(tenant=other_tenant)
        document = self.document()
        self.assertEqual(document["status"], "offline")
        self.assertTrue(document["can_remove"])
        self.assertEqual(self.remove().status_code, 204)

    def test_revoked_state_wins_over_recent_contact_and_remains_removable(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(
            status=AgentEnrollment.Status.REVOKED, last_heartbeat_at=self.now,
        )
        document = self.document()
        self.assertEqual(document["status"], "revoked")
        self.assertTrue(document["can_remove"])
        self.assertEqual(self.remove().status_code, 204)

    def test_revoked_agent_with_valid_console_lease_is_not_removed_mid_session(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(status=AgentEnrollment.Status.REVOKED)
        self.session()
        document = self.document()
        self.assertEqual(document["status"], "revoked")
        self.assertFalse(document["can_remove"])
        self.assert_removal_denied()

    def test_open_console_only_expires_sessions_for_the_selected_vm_and_tenant(self):
        vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant, host=self.server, source_id=str(uuid.uuid4()),
            name="Selected VM", state=HyperVVirtualMachine.State.RUNNING, observed_at=self.now,
        )
        selected = self.session(
            virtual_machine=vm, vm_source_id=vm.source_id,
            lease_expires_at=self.old,
        )
        unrelated = self.session(lease_expires_at=self.old)
        other_tenant = Tenant.objects.create(slug="expiry-other", display_name="Other")
        foreign = self.session(tenant=other_tenant, vm_source_id=vm.source_id, lease_expires_at=self.old)

        created, occupied = create_console_session(virtual_machine=vm, actor=self.admin.username)

        self.assertIsNone(occupied)
        self.assertEqual(created.status, HyperVConsoleSession.Status.REQUESTED)
        selected.refresh_from_db()
        unrelated.refresh_from_db()
        foreign.refresh_from_db()
        self.assertEqual(selected.status, HyperVConsoleSession.Status.EXPIRED)
        self.assertEqual(unrelated.status, HyperVConsoleSession.Status.ACTIVE)
        self.assertEqual(foreign.status, HyperVConsoleSession.Status.ACTIVE)

    def test_console_creation_rejects_removed_enrollment(self):
        vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant, host=self.server, source_id=str(uuid.uuid4()),
            name="Selected VM", state=HyperVVirtualMachine.State.RUNNING, observed_at=self.now,
        )
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(status=AgentEnrollment.Status.REMOVED)
        with self.assertRaises(ValidationError):
            create_console_session(virtual_machine=vm, actor=self.admin.username)
        self.assertFalse(HyperVConsoleSession.objects.filter(virtual_machine=vm).exists())
