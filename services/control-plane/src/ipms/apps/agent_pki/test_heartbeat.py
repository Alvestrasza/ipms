import asyncio
import tempfile
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from ipms.apps.tenancy.models import Tenant
from . import gateway, services
from .models import AgentEnrollment
from .test_console_transport import ConsoleWriter, request
from .tests import create_csr


class HeartbeatTransportTests(SimpleTestCase):
    def test_postgres_heartbeat_limits_are_transaction_local(self):
        database = MagicMock(vendor="postgresql")
        cursor = database.cursor.return_value.__enter__.return_value
        with patch.object(gateway, "connection", database), patch.object(gateway.transaction, "atomic") as atomic:
            self.assertEqual(gateway._bounded_heartbeat_database_call(lambda value: value, "alive"), "alive")
        atomic.assert_called_once_with()
        self.assertEqual([item.args[0] for item in cursor.execute.call_args_list], [
            "SET LOCAL lock_timeout = '1s'", "SET LOCAL statement_timeout = '2s'",
        ])

    def test_postgres_database_errors_leave_the_transaction_for_rollback(self):
        database = MagicMock(vendor="postgresql")
        error = RuntimeError("synthetic lock timeout")
        def blocked():
            raise error
        with patch.object(gateway, "connection", database), patch.object(gateway.transaction, "atomic") as atomic:
            with self.assertRaises(RuntimeError):
                gateway._bounded_heartbeat_database_call(blocked)
            exit_arguments = atomic.return_value.__exit__.call_args.args
            self.assertIs(exit_arguments[1], error)

    async def exchange(self, *, certificate=True, revoked=False, **document):
        reader = asyncio.StreamReader()
        reader.feed_data(request(path="/v1/heartbeat", type="heartbeat", **document))
        reader.feed_eof()
        writer = ConsoleWriter()
        if not certificate:
            writer.get_extra_info = lambda name: SimpleNamespace(
                selected_alpn_protocol=lambda: "http/1.1",
                getpeercert=lambda **kwargs: None,
            ) if name == "ssl_object" else None
        calls = []

        async def heartbeat_database(function, *args, **kwargs):
            calls.append(function.__name__)
            if function.__name__ == "validate_peer_certificate":
                if revoked:
                    raise ValidationError("The test identity was revoked.")
                return SimpleNamespace(device_uri="test-device")
            self.assertEqual(function.__name__, "confirm_heartbeat")

        async def ordinary_database(*args, **kwargs):
            self.fail("Heartbeat used the inventory/console database executor.")

        with patch.object(gateway, "_heartbeat_database_call_async", heartbeat_database, create=True), patch.object(
            gateway, "_database_call_async", ordinary_database
        ):
            await gateway.handle_connection(reader, writer)
        self.assertTrue(writer.closed)
        return bytes(writer.output), calls

    async def test_heartbeat_has_no_assignment_or_telemetry_side_effect(self):
        output, calls = await self.exchange(correlation_id="heartbeat-test")
        self.assertIn(b"HTTP/1.1 200", output)
        self.assertIn(b'"type":"accepted"', output)
        self.assertNotIn(b"hyperv_console", output)
        self.assertNotIn(b"lifecycle", output)
        self.assertIn(b"Connection: close", output)
        self.assertEqual(calls, ["validate_peer_certificate", "confirm_heartbeat"])

    async def test_heartbeat_rejects_no_certificate_revocation_and_wrong_identity(self):
        for values in ({"certificate": False}, {"revoked": True}, {"device": "other-device"}):
            output, calls = await self.exchange(**values)
            self.assertIn(b"HTTP/1.1 400", output)
            self.assertNotIn("confirm_heartbeat", calls)

    async def test_heartbeat_rejects_inventory_or_command_fields(self):
        for values in ({"inventory": {}}, {"command": "test"}, {"observed_at": "future"}):
            output, calls = await self.exchange(**values)
            self.assertIn(b"HTTP/1.1 400", output)
            self.assertNotIn("confirm_heartbeat", calls)

    async def test_heartbeat_database_lane_progresses_while_normal_lane_is_blocked(self):
        entered, release = threading.Event(), threading.Event()

        def blocked():
            entered.set()
            if not release.wait(5):
                raise RuntimeError("The test did not release the normal lane.")

        with patch.object(gateway, "close_old_connections"):
            task = asyncio.create_task(gateway._database_call_async(blocked))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                result = await asyncio.wait_for(gateway._heartbeat_database_call_async(lambda: "alive"), 1)
                self.assertEqual(result, "alive")
                self.assertFalse(task.done())
            finally:
                release.set()
                await task


class HeartbeatPersistenceTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="heartbeat-test", display_name="Heartbeat Test")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        services.bootstrap_managed_pki(
            tenant=self.tenant, gateway_dns_name="gateway.example.invalid",
            recovery_output=Path(temporary.name) / "recovery.pem",
            recovery_passphrase=b"test-only-recovery-passphrase", actor="test-operator",
        )
        _, token, _ = services.create_enrollment_token(
            tenant=self.tenant, display_name="Synthetic Agent", actor="test-operator"
        )
        _, csr = create_csr()
        self.enrollment, _, _ = services.enroll_agent(raw_token=token, csr_pem=csr)

    def test_heartbeat_records_server_time_without_inventing_inventory(self):
        stale = timezone.now() - timedelta(minutes=10)
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(last_seen_at=stale)
        before = timezone.now()
        services.confirm_heartbeat(self.enrollment)
        self.enrollment.refresh_from_db()
        self.assertGreaterEqual(self.enrollment.last_heartbeat_at, before)
        self.assertEqual(self.enrollment.last_seen_at, stale)
        self.assertIsNone(self.enrollment.first_inventory_at)
        from ipms.apps.discovery.models import WindowsServer, WindowsServerTelemetry
        self.assertFalse(WindowsServer.objects.exists())
        self.assertFalse(WindowsServerTelemetry.objects.exists())

    def test_stale_authenticated_object_cannot_heartbeat_after_revocation(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(status=AgentEnrollment.Status.REVOKED)
        with self.assertRaises(ValidationError):
            services.confirm_heartbeat(self.enrollment)
        self.enrollment.refresh_from_db()
        self.assertIsNone(self.enrollment.last_heartbeat_at)

    def test_heartbeat_rejects_changed_certificate_or_tenant_binding(self):
        other = Tenant.objects.create(slug="heartbeat-other", display_name="Other")
        original_tenant = self.enrollment.tenant_id
        self.enrollment.tenant_id = other.pk
        with self.assertRaises(ValidationError):
            services.confirm_heartbeat(self.enrollment)
        self.enrollment.tenant_id = original_tenant
        self.enrollment.certificate_fingerprint_sha256 = "0" * 64
        with self.assertRaises(ValidationError):
            services.confirm_heartbeat(self.enrollment)

    def test_expired_certificate_cannot_record_heartbeat(self):
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(
            certificate_not_after=timezone.now() - timedelta(seconds=1)
        )
        with self.assertRaises(ValidationError):
            services.confirm_heartbeat(self.enrollment)
