import base64
from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from ipms.apps.discovery.models import HyperVConsoleSession, HyperVVirtualMachine, WindowsServer
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .hyperv_console import create_console_session, process_console_cycle, queue_console_input
from .models import AgentEnrollment


class ConsoleInputChannelTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="input-channel", display_name="Input channel")
        user = get_user_model().objects.create_user("operator")
        TenantMembership.objects.create(tenant=self.tenant, user=user, role="operator")
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant, display_name="Host", device_uri="urn:ipms:agent:input-host",
            platform="windows", status="active",
        )
        host = WindowsServer.objects.create(
            tenant=self.tenant, source_id=self.enrollment.device_uri, hostname="host",
            agent_version="0.2.24", discovered_at=timezone.now(), last_seen_at=timezone.now(),
        )
        vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant, host=host, source_id="41111111-1111-1111-1111-111111111111",
            name="Input VM", state="running", observed_at=timezone.now(),
        )
        self.session, _ = create_console_session(virtual_machine=vm, actor="operator")

    def event(self, event_type="key", payload=None):
        return queue_console_input(
            session=self.session, actor="operator", event_type=event_type,
            payload=payload or {"key_code": 65, "is_down": True},
        )

    def input_cycle(self, **kwargs):
        from .hyperv_console import process_console_input_cycle

        return process_console_input_cycle(
            self.enrollment, session_id=kwargs.pop("session_id", ""),
            acknowledged_input_ids=kwargs.pop("acknowledged_input_ids", []),
            failure_code=kwargs.pop("failure_code", ""), **kwargs,
        )

    def frame_cycle(self, **kwargs):
        return process_console_cycle(
            self.enrollment, session_id=str(self.session.id), frame_png_base64="",
            frame_width=0, frame_height=0, acknowledged_input_ids=kwargs.pop("acks", []),
            failure_code="", include_inputs=False, **kwargs,
        )

    def test_frame_channel_does_not_deliver_or_acknowledge_inputs(self):
        event = self.event()
        self.assertEqual(self.frame_cycle()["inputs"], [])
        event.refresh_from_db()
        self.assertIsNone(event.delivered_at)
        with self.assertRaises(ValidationError):
            self.frame_cycle(acks=[str(event.id)])
        self.assertTrue(self.session.input_events.filter(id=event.id).exists())

    def test_input_is_delivered_and_acknowledged_without_any_frame(self):
        event = self.event()
        active, assignment = self.input_cycle()
        self.assertTrue(active)
        self.assertEqual(assignment["session_id"], str(self.session.id))
        self.assertEqual(assignment["inputs"][0]["id"], str(event.id))
        self.assertEqual(assignment["inputs"][0]["key_code"], 65)
        self.input_cycle(session_id=str(self.session.id), acknowledged_input_ids=[str(event.id)])
        self.session.refresh_from_db()
        self.assertEqual(self.session.frame_sequence, 0)
        self.assertIsNone(self.session.last_agent_contact_at)
        self.assertFalse(self.session.input_events.exists())

    def test_ack_retry_is_idempotent_and_never_delivers_next_events(self):
        first = self.event()
        self.input_cycle()
        second = self.event(payload={"key_code": 65, "is_down": False})
        for _ in range(2):
            active, assignment = self.input_cycle(
                session_id=str(self.session.id), acknowledged_input_ids=[str(first.id)],
            )
            self.assertTrue(active)
            self.assertIsNone(assignment)
        second.refresh_from_db()
        self.assertIsNone(second.delivered_at)
        self.assertEqual(self.input_cycle()[1]["inputs"][0]["id"], str(second.id))

    def test_input_poll_preserves_frame_payload_and_order(self):
        self.session.frame_png = b"\x89PNG\r\n\x1a\nprivate-frame"
        self.session.frame_sequence = 17
        self.session.save(update_fields=("frame_png", "frame_sequence"))
        now = timezone.now()
        # This test exercises distinct chronological inputs, not equal clock ticks.
        with patch("django.utils.timezone.now", return_value=now):
            first = self.event("mouse_move", {"x": 10, "y": 20})
        with patch(
            "django.utils.timezone.now", return_value=now + timedelta(milliseconds=1)
        ):
            second = self.event("mouse_button", {"button": 1, "is_down": True})
        with patch(
            "django.utils.timezone.now", return_value=now + timedelta(milliseconds=2)
        ):
            third = self.event("mouse_move", {"x": 30, "y": 40})
        assignment = self.input_cycle()[1]
        self.assertEqual([item["id"] for item in assignment["inputs"]], [str(e.id) for e in (first, second, third)])
        self.assertNotIn("frame_png_base64", assignment)
        self.session.refresh_from_db()
        self.assertEqual(self.session.frame_sequence, 17)
        self.assertEqual(bytes(self.session.frame_png), b"\x89PNG\r\n\x1a\nprivate-frame")

    def test_closed_and_expired_sessions_cannot_deliver_input(self):
        self.event()
        self.session.lease_expires_at = timezone.now() - timedelta(seconds=1)
        self.session.save(update_fields=("lease_expires_at",))
        self.assertEqual(self.input_cycle(), (False, None))
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, HyperVConsoleSession.Status.EXPIRED)

    def test_revoked_requester_closes_and_clears_console_without_delivering_input(self):
        event = self.event()
        self.session.frame_png = b"private-frame"
        self.session.save(update_fields=("frame_png",))
        TenantMembership.objects.filter(tenant=self.tenant).update(is_active=False)
        self.assertEqual(self.input_cycle(), (False, None))
        self.session.refresh_from_db()
        event.refresh_from_db()
        self.assertEqual(self.session.status, "closed")
        self.assertEqual(bytes(self.session.frame_png), b"")
        self.assertIsNone(event.delivered_at)
        TenantMembership.objects.filter(tenant=self.tenant).update(is_active=True)
        self.assertIsNone(self.frame_cycle())

    def test_revoked_requester_cannot_publish_a_late_frame(self):
        TenantMembership.objects.filter(tenant=self.tenant).update(is_active=False)
        assignment = process_console_cycle(
            self.enrollment,
            session_id=str(self.session.id),
            frame_png_base64=base64.b64encode(b"\x89PNG\r\n\x1a\nlate-frame").decode(),
            frame_width=640,
            frame_height=480,
            acknowledged_input_ids=[],
            failure_code="",
        )
        self.assertIsNone(assignment)
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, "closed")
        self.assertEqual(self.session.frame_sequence, 0)
        self.assertEqual(bytes(self.session.frame_png), b"")

    def test_other_identity_cannot_acknowledge_input(self):
        event = self.event()
        other = AgentEnrollment.objects.create(
            tenant=self.tenant, display_name="Other", device_uri="urn:ipms:agent:other-host",
            platform="windows", status="active",
        )
        from .hyperv_console import process_console_input_cycle

        with self.assertRaises(ValidationError):
            process_console_input_cycle(other, session_id=str(self.session.id), acknowledged_input_ids=[str(event.id)], failure_code="")
        self.assertTrue(self.session.input_events.filter(id=event.id).exists())

    def test_failure_closes_only_exact_session_and_clears_frame(self):
        self.session.frame_png = base64.b64decode("iVBORw0KGgo=")
        self.session.save(update_fields=("frame_png",))
        self.input_cycle(session_id=str(self.session.id), failure_code="console_input_failed")
        self.session.refresh_from_db()
        self.assertEqual(self.session.status, "failed")
        self.assertEqual(self.session.failure_code, "console_input_failed")
        self.assertFalse(self.session.frame_png)

    def test_poll_rejects_unscoped_acks_and_invalid_uuid(self):
        with self.assertRaises(ValidationError):
            self.input_cycle(acknowledged_input_ids=["41111111-1111-1111-1111-111111111111"])
        with self.assertRaises(ValidationError):
            self.input_cycle(session_id="not-a-uuid")

    def test_closed_session_ack_cannot_affect_replacement_session(self):
        old = self.event()
        self.input_cycle()
        self.session.status = "closed"
        self.session.save(update_fields=("status",))
        replacement, _ = create_console_session(virtual_machine=self.session.virtual_machine, actor="operator")
        new = queue_console_input(session=replacement, actor="operator", event_type="key", payload={"key_code": 66, "is_down": True})
        self.input_cycle(session_id=str(self.session.id), acknowledged_input_ids=[str(old.id), str(new.id)])
        self.assertTrue(replacement.input_events.filter(id=new.id).exists())
        self.assertEqual(self.input_cycle()[1]["session_id"], str(replacement.id))

    def test_input_queries_never_read_the_frame_blob(self):
        self.event()
        with CaptureQueriesContext(connection) as queries:
            self.input_cycle()
        selects = [query["sql"] for query in queries if query["sql"].lstrip().startswith("SELECT")]
        self.assertTrue(selects)
        self.assertFalse(any('"frame_png"' in query for query in selects))

    def test_pending_input_batch_remains_bounded(self):
        for index in range(70):
            self.event(payload={"key_code": 65, "is_down": index % 2 == 0})
        assignment = self.input_cycle()[1]
        self.assertEqual(len(assignment["inputs"]), 64)
        self.assertEqual(self.session.input_events.filter(delivered_at__isnull=True).count(), 6)
