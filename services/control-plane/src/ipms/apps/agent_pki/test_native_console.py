import asyncio
import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, TransactionTestCase, override_settings, SimpleTestCase
from django.urls import reverse
from django.utils import timezone
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed, InvalidStatus

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import HyperVConsoleSession, HyperVVirtualMachine, WindowsServer
from ipms.apps.tenancy.models import Tenant, TenantMembership
from .models import AgentEnrollment, NativeConsoleCredential
from .native_console import authorize_browser, authorize_agent, close_native, load_credential, store_credential
from .hyperv_console import create_console_session, process_console_cycle
from . import console_broker
from .native_protocol import AgentWebSocket, NativeProtocolError, guac, guac_instructions, preconnection_pdu, read_guac


class NativeFixture:
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        key = Path(self.temp.name) / "console.key"
        key.write_bytes(os.urandom(32))
        self.settings_override = override_settings(NATIVE_CONSOLE_KEY_FILE=str(key), NATIVE_CONSOLE_ORIGIN="https://portal.example.invalid")
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.tenant = Tenant.objects.create(slug="native", display_name="Native")
        self.user = get_user_model().objects.create_user("native-admin", password="test-password")
        self.other = get_user_model().objects.create_user("native-other", password="test-password")
        self.reader = get_user_model().objects.create_user("native-reader", password="test-password")
        for user, role in ((self.user, "tenant_admin"), (self.other, "tenant_admin"), (self.reader, "reader")):
            TenantMembership.objects.create(user=user, tenant=self.tenant, role=role)
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant, display_name="Native host", device_uri="urn:ipms:agent:" + str(uuid.uuid4()), status="active",
        )
        self.host = WindowsServer.objects.create(
            tenant=self.tenant, source_id=self.enrollment.device_uri, inventory_source="agent",
            hostname="native-host", agent_version="0.2.26", discovered_at=timezone.now(),
        )
        self.vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant, host=self.host, source_id=str(uuid.uuid4()), name="Native VM", state="running", observed_at=timezone.now(),
        )
        self.credential = {"username": "console-service", "password": "test-only-private-password", "domain": "EXAMPLE"}
        store_credential(self.enrollment, user=self.user, document=self.credential)
        self.client.force_login(self.user)
        self.cookie = self.client.cookies["ipms_sessionid"].value
        self.headers = {"HTTP_X_IPMS_TENANT_ID": str(self.tenant.id)}

    def native_session(self):
        session, occupied = create_console_session(
            virtual_machine=self.vm, actor=self.user.username, owner=self.user,
            transport="vmconnect", external_session_acknowledged=True,
        )
        self.assertIsNone(occupied)
        return session


class NativeConsoleTests(NativeFixture, TestCase):
    def test_configuration_is_encrypted_bound_and_never_returned(self):
        secret = NativeConsoleCredential.objects.get(enrollment=self.enrollment)
        self.assertNotIn(self.credential["password"].encode(), bytes(secret.ciphertext))
        session = self.native_session()
        self.assertEqual(load_credential(session), self.credential)
        endpoint = reverse("core:native-console-configuration", args=(self.vm.id,))
        response = self.client.get(endpoint, **self.headers)
        self.assertEqual(response.json(), {"configured": True, "can_manage": True, "native_supported": True})
        self.assertNotIn("password", response.content.decode())
        other = Tenant.objects.create(slug="native-foreign", display_name="Foreign")
        NativeConsoleCredential.objects.filter(pk=secret.pk).update(tenant=other)
        with self.assertRaises(NativeConsoleCredential.DoesNotExist):
            load_credential(session)
        self.assertNotIn(self.credential["password"], str(list(AuditEvent.objects.values("details"))))

    def test_reader_and_foreign_tenant_cannot_configure(self):
        endpoint = reverse("core:native-console-configuration", args=(self.vm.id,))
        self.client.force_login(self.reader)
        self.assertEqual(self.client.post(endpoint, self.credential, content_type="application/json", **self.headers).status_code, 403)
        self.client.force_login(self.other)
        foreign = Tenant.objects.create(slug="native-foreign", display_name="Foreign")
        self.assertEqual(self.client.get(endpoint, HTTP_X_IPMS_TENANT_ID=str(foreign.id)).status_code, 404)

    def test_native_create_requires_acknowledgement_version_and_credentials(self):
        endpoint = reverse("core:hyperv-console-session-create", args=(self.vm.id,))
        self.assertEqual(self.client.post(endpoint, {"transport": "vmconnect"}, content_type="application/json", **self.headers).status_code, 400)
        self.host.agent_version = "0.2.25"
        self.host.save(update_fields=("agent_version",))
        with self.assertRaises(ValidationError):
            self.native_session()
        self.host.agent_version = "0.2.26"
        self.host.save(update_fields=("agent_version",))
        NativeConsoleCredential.objects.all().delete()
        with self.assertRaises(ValidationError):
            self.native_session()

    def test_owner_cookie_claim_generation_and_replay_are_checked(self):
        session = self.native_session()
        with self.assertRaises(ValidationError):
            authorize_browser(str(session.id), "invalid-cookie", attach=True)
        attached = authorize_browser(str(session.id), self.cookie, attach=True)
        self.assertIsNotNone(attached.browser_claim)
        with self.assertRaises(ValidationError):
            authorize_browser(str(session.id), self.cookie, attach=True)
        with self.assertRaises(ValidationError):
            authorize_browser(str(session.id), self.cookie, claim=uuid.uuid4())
        with self.assertRaises(HyperVConsoleSession.DoesNotExist):
            authorize_agent(self.enrollment, str(session.id), str(uuid.uuid4()))
        self.assertEqual(authorize_agent(self.enrollment, str(session.id), str(session.stream_generation)).id, session.id)
        self.client.force_login(self.other)
        with self.assertRaises(HyperVConsoleSession.DoesNotExist):
            authorize_browser(str(session.id), self.client.cookies["ipms_sessionid"].value, attach=True)

    def test_revocation_membership_loss_vm_move_and_expiry_fail_closed(self):
        session = self.native_session()
        attached = authorize_browser(str(session.id), self.cookie, attach=True)
        cases = (
            (AgentEnrollment.objects.filter(pk=self.enrollment.pk), {"status": "revoked"}, {"status": "active"}),
            (TenantMembership.objects.filter(user=self.user), {"is_active": False}, {"is_active": True}),
            (HyperVConsoleSession.objects.filter(pk=session.pk), {"lease_expires_at": timezone.now() - timedelta(seconds=1)}, {"lease_expires_at": timezone.now() + timedelta(seconds=30)}),
            (WindowsServer.objects.filter(pk=self.host.pk), {"source_id": "different"}, {"source_id": self.enrollment.device_uri}),
        )
        for queryset, bad, good in cases:
            queryset.update(**bad)
            with self.assertRaises(ValidationError):
                authorize_browser(str(session.id), self.cookie, claim=attached.browser_claim)
            queryset.update(**good)
        self.client.logout()
        with self.assertRaises(ValidationError):
            authorize_browser(str(session.id), self.cookie, claim=attached.browser_claim)

    def test_native_assignment_is_fixed_and_rejects_thumbnail_result(self):
        session = self.native_session()
        arguments = dict(session_id="", frame_png_base64="", frame_width=0, frame_height=0, acknowledged_input_ids=[], failure_code="")
        assignment = process_console_cycle(self.enrollment, **arguments)
        self.assertEqual(assignment["transport"], "vmconnect")
        self.assertEqual(assignment["vm_source_id"], self.vm.source_id)
        self.assertEqual(assignment["stream_generation"], str(session.stream_generation))
        self.assertEqual(assignment["inputs"], [])
        self.assertNotIn("hostname", assignment)
        with self.assertRaises(ValidationError):
            process_console_cycle(self.enrollment, **{**arguments, "session_id": str(session.id)})

    def test_native_http_owner_survives_rename_and_cannot_use_legacy_frame(self):
        session = self.native_session()
        self.user.username = "renamed-console-owner"
        self.user.save(update_fields=("username",))
        endpoint = reverse("core:hyperv-console-session", args=(session.id,))
        self.assertEqual(self.client.get(endpoint, **self.headers).status_code, 200)
        self.assertEqual(self.client.get(reverse("core:hyperv-console-frame", args=(session.id,)), **self.headers).status_code, 404)
        self.assertEqual(self.client.delete(endpoint, **self.headers).status_code, 204)
        session.refresh_from_db()
        self.assertEqual(session.status, "closed")

    def test_invalid_login_hash_is_denied_without_mutating_django_session(self):
        from django.contrib.sessions.models import Session
        session = self.native_session()
        previous = Session.objects.get(session_key=self.cookie).session_data
        self.user.set_password("replacement-test-only-password")
        self.user.save(update_fields=("password",))
        with self.assertRaises(ValidationError):
            authorize_browser(str(session.id), self.cookie, attach=True)
        self.assertEqual(Session.objects.get(session_key=self.cookie).session_data, previous)


class NativeProtocolTests(SimpleTestCase):
    def test_broker_settings_need_only_broker_scoped_secrets(self):
        environment = {name: value for name, value in os.environ.items() if name in ("PATH", "SystemRoot", "SYSTEMROOT", "PYTHONPATH", "TEMP", "TMP")}
        environment.update({
            "DJANGO_SETTINGS_MODULE": "ipms_control_plane.settings.console_broker",
            "IPMS_SECRET_KEY": "test-only-session-signing-key",
            "IPMS_DATABASE_NAME": "test-unused", "IPMS_DATABASE_USER": "test-unused",
            "IPMS_DATABASE_PASSWORD": "test-unused", "IPMS_DATABASE_HOST": "127.0.0.1",
            "IPMS_NATIVE_CONSOLE_KEY_FILE": "/test-unused/key", "IPMS_NATIVE_CONSOLE_ORIGIN": "https://portal.example.invalid",
        })
        code = (
            "import django; django.setup(); from django.conf import settings; "
            "assert settings.SESSION_COOKIE_NAME == 'ipms_sessionid'; "
            "assert settings.SESSION_ENGINE == 'django.contrib.sessions.backends.db'; "
            "assert not any(hasattr(settings, name) for name in "
            "('CONNECTOR_MASTER_KEY','AGENT_PKI_MASTER_KEY','AGENT_DEPLOYMENT_MASTER_KEY',"
            "'CERTIFICATE_PROBE_TOKEN','AGENT_WINDOWS_PACKAGE_PATH')); print('broker-scoped settings ready')"
        )
        result = subprocess.run([sys.executable, "-c", code], env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "broker-scoped settings ready")

    def test_failure_classification_never_echoes_remote_or_secret_text(self):
        self.assertEqual(console_broker.classify_failure(NativeProtocolError("native_certificate_rejected")), "native_certificate_rejected")
        self.assertEqual(console_broker.classify_failure(RuntimeError("private credential material from remote peer")), "native_connection_failed")

    async def test_native_database_lane_does_not_block_heartbeat(self):
        from . import gateway, native_gateway
        entered, release = threading.Event(), threading.Event()

        def blocked():
            entered.set()
            if not release.wait(3):
                raise RuntimeError("Test native lane was not released")

        with patch.object(gateway, "close_old_connections"), patch.object(gateway, "_bounded_heartbeat_database_call", lambda function, *args, **kwargs: function(*args, **kwargs)):
            task = asyncio.create_task(native_gateway.native_database_call(blocked))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                self.assertEqual(await asyncio.wait_for(gateway._heartbeat_database_call_async(lambda: "alive"), 1), "alive")
                self.assertFalse(task.done())
            finally:
                release.set()
                await task

    async def test_broker_startup_rejects_missing_origin_or_key_before_network(self):
        for origin, key in (("", ""), ("http://portal.example.invalid", ""), ("https://portal.example.invalid/", ""), ("https://portal.example.invalid", "")):
            with override_settings(NATIVE_CONSOLE_ORIGIN=origin, NATIVE_CONSOLE_KEY_FILE=key), patch.object(asyncio, "open_connection", AsyncMock()) as network:
                with self.assertRaises((RuntimeError, ValidationError)):
                    await console_broker.validate_startup()
                network.assert_not_called()

    def test_preconnection_binds_only_canonical_vm_identity(self):
        vm_id = "11111111-2222-3333-4444-555555555555"
        pdu = preconnection_pdu(vm_id)
        self.assertEqual(int.from_bytes(pdu[:4], "little"), len(pdu))
        self.assertEqual(struct.unpack("<IIIIH", pdu[:18]), (92, 0, 2, 0, 37))
        self.assertEqual(pdu[18:].decode("utf-16-le"), vm_id + "\x00")
        with self.assertRaises((ValueError, NativeProtocolError)):
            preconnection_pdu(vm_id + ";EnhancedMode=1")

    def test_browser_guac_input_rejects_configuration_and_oversized_payload(self):
        self.assertEqual(guac_instructions(guac("key", 65, 1)), [["key", "65", "1"]])
        for instruction in (["select", "rdp"], ["key", "1", "2"], ["mouse", "0", "0", "256"], ["size", "99999", "100"]):
            with self.assertRaises(NativeProtocolError):
                console_broker.validate_browser_instruction(instruction)
        with self.assertRaises(NativeProtocolError):
            guac_instructions("9.key;")

    async def test_sans_io_agent_socket_accepts_binary_and_rejects_text(self):
        received = []

        async def server(reader, writer):
            try:
                header = await reader.readuntil(b"\r\n\r\n")
                ws = AgentWebSocket(reader, writer, header)
                await ws.accept()
                await ws.send({"type": "lease", "seconds": 15, "stream_generation": "test"})
                received.append(await ws.recv())
                with self.assertRaises(NativeProtocolError):
                    await ws.recv()
            finally:
                writer.close()
                await writer.wait_closed()

        listener = await asyncio.start_server(server, "127.0.0.1", 0)
        async with listener:
            port = listener.sockets[0].getsockname()[1]
            async with connect(f"ws://127.0.0.1:{port}/v1/hyperv-console-native", compression=None) as ws:
                self.assertEqual(json.loads(await ws.recv())["type"], "lease")
                await ws.send(b"test-native-data")
                await ws.send("unauthorized-text")
                with self.assertRaises(Exception):
                    await ws.recv()
        self.assertEqual(received, [b"test-native-data"])

    async def test_certificate_probe_uses_direct_tls_after_pcb_without_authentication(self):
        vm_id = "11111111-2222-3333-4444-555555555555"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-hypervisor.invalid")])
        now = timezone.now()
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                       .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
        with tempfile.TemporaryDirectory() as temporary:
            cert_path, key_path = Path(temporary) / "test.pem", Path(temporary) / "test.key"
            cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)

            accepted_stream = asyncio.get_running_loop().create_future()

            async def accepted(reader, writer):
                accepted_stream.set_result((reader, writer))

            # Match the real reverse-tunnel topology: the broker owns an
            # accepted stream, not a stream created by open_connection().
            unix_path = str(Path(temporary) / "probe.sock")
            if sys.platform == "win32":
                listener = await asyncio.start_server(accepted, "127.0.0.1", 0)
                endpoint = ("127.0.0.1", listener.sockets[0].getsockname()[1])
            else:
                listener = await asyncio.start_unix_server(accepted, path=unix_path)
                endpoint = unix_path
            async with listener:

                def server():
                    raw = socket.socket(socket.AF_INET if sys.platform == "win32" else socket.AF_UNIX)
                    raw.settimeout(5)
                    with raw:
                        raw.connect(endpoint)
                        pcb = b""
                        while len(pcb) < 92:
                            received = raw.recv(92 - len(pcb))
                            if not received:
                                raise EOFError()
                            pcb += received
                        # No X.224 round trip is allowed between PCB and TLS.
                        with context.wrap_socket(raw, server_side=True) as secured:
                            return pcb, secured.recv(1024)

                completed = asyncio.create_task(asyncio.to_thread(server))

                class TestBridge:
                    session = SimpleNamespace(vm_source_id=vm_id)
                    writer = None

                    async def open_agent(self):
                        reader, self.writer = await asyncio.wait_for(accepted_stream, 3)
                        return reader, self.writer

                    async def release_agent(self):
                        await console_broker.close_writer(self.writer)

                observed = await console_broker.observe_certificate(TestBridge())
                self.assertEqual(observed["sha256"], hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest())
                self.assertEqual(observed["subject"], "CN=test-hypervisor.invalid")
                pcb, application_data = await asyncio.wait_for(completed, 5)
                self.assertEqual(pcb, preconnection_pdu(vm_id))
                self.assertEqual(application_data, b"")

    async def test_guacd_handshake_fixes_target_version_identity_and_redirection(self):
        fields = ["VERSION_1_5_0", "hostname", "port", "username", "password", "domain", "security",
                  "preconnection-blob", "preconnection-id", "cert-fingerprints", "ipms-strict-certificate",
                  "ignore-cert", "cert-tofu", "disable-copy", "disable-paste", "enable-drive", "enable-printing",
                  "disable-audio", "enable-audio-input", "enable-sftp", "gateway-hostname"]
        captured = asyncio.get_running_loop().create_future()
        finished = asyncio.Event()

        async def server(reader, writer):
            try:
                self.assertEqual(await read_guac(reader), ["select", "rdp"])
                writer.write(guac("args", *fields).encode())
                await writer.drain()
                messages = [await read_guac(reader) for _ in range(5)]
                captured.set_result(messages)
                writer.write(guac("ready", "test-guacd-id").encode())
                await writer.drain()
                await reader.read()
            except Exception as exc:
                if not captured.done():
                    captured.set_exception(exc)
            finally:
                await console_broker.close_writer(writer)
                finished.set()

        listener = await asyncio.start_server(server, "127.0.0.1", 0)
        async with listener:
            bridge = SimpleNamespace(session=SimpleNamespace(vm_source_id="11111111-2222-3333-4444-555555555555"), proxy_task=None)
            credential = {"username": "test-console", "password": "test-only-password", "domain": "TEST"}
            with patch.object(console_broker, "GUACD_PORT", listener.sockets[0].getsockname()[1]), patch.object(console_broker, "db", AsyncMock(return_value=credential)):
                _, writer, proxy = await console_broker.guacd_connect(bridge, {"width": 1024, "height": 768}, "a" * 64)
            try:
                messages = await asyncio.wait_for(captured, 3)
                self.assertEqual(messages[0], ["size", "1024", "768", "96"])
                self.assertEqual(messages[1:4], [["audio"], ["video"], ["image", "image/png", "image/jpeg"]])
                self.assertEqual(messages[4][0], "connect")
                parameters = dict(zip(fields, messages[4][1:], strict=True))
                self.assertEqual(parameters["VERSION_1_5_0"], "VERSION_1_5_0")
                self.assertEqual(parameters["hostname"], "127.0.0.1")
                self.assertEqual(parameters["port"], str(proxy.sockets[0].getsockname()[1]))
                self.assertEqual(parameters["preconnection-blob"], bridge.session.vm_source_id)
                self.assertEqual(parameters["preconnection-id"], "0")
                self.assertEqual(parameters["security"], "vmconnect")
                self.assertEqual(parameters["cert-fingerprints"], "sha256:" + "a" * 64)
                self.assertEqual(parameters["password"], "test-only-password")
                for name in ("ipms-strict-certificate", "disable-copy", "disable-paste", "disable-audio"):
                    self.assertEqual(parameters[name], "true")
                for name in ("ignore-cert", "cert-tofu", "enable-drive", "enable-printing", "enable-audio-input", "enable-sftp"):
                    self.assertEqual(parameters[name], "false")
                self.assertEqual(parameters["gateway-hostname"], "")
                self.assertEqual(credential, {})
            finally:
                proxy.close()
                await proxy.wait_closed()
                await console_broker.close_writer(writer)
                await asyncio.wait_for(finished.wait(), 3)

    async def test_stock_guacd_rejected_before_credential_decryption(self):
        async def server(reader, writer):
            try:
                await read_guac(reader)
                writer.write(guac("args", "VERSION_1_5_0", "hostname", "password", "cert-fingerprints").encode())
                await writer.drain()
                await reader.read()
            finally:
                await console_broker.close_writer(writer)

        listener = await asyncio.start_server(server, "127.0.0.1", 0)
        async with listener:
            bridge = SimpleNamespace(session=SimpleNamespace(vm_source_id=str(uuid.uuid4())), proxy_task=None)
            with patch.object(console_broker, "GUACD_PORT", listener.sockets[0].getsockname()[1]), patch.object(console_broker, "db", AsyncMock()) as secret_read:
                with self.assertRaises(NativeProtocolError):
                    await console_broker.guacd_connect(bridge, {"width": 1024, "height": 768}, "a" * 64)
                secret_read.assert_not_called()
            with override_settings(NATIVE_CONSOLE_ORIGIN="https://portal.example.invalid"), patch("ipms.apps.agent_pki.native_console._key", return_value=b"k" * 32), patch.object(console_broker, "GUACD_PORT", listener.sockets[0].getsockname()[1]):
                with self.assertRaises(RuntimeError):
                    await console_broker.validate_startup()


class NativeBrowserBoundaryTests(NativeFixture, TransactionTestCase):
    def test_ready_stream_closes_browser_agent_and_guacd_on_permission_loss(self):
        session = self.native_session()

        async def exercise():
            agent_closed, guacd_closed = asyncio.Event(), asyncio.Event()
            forwarded = asyncio.Queue()

            async def agent_peer(reader, writer):
                try:
                    await reader.read()
                finally:
                    await console_broker.close_writer(writer)
                    agent_closed.set()

            async def guacd_peer(reader, writer):
                try:
                    writer.write(guac("sync", 1).encode())
                    await writer.drain()
                    while data := await reader.read(65536):
                        forwarded.put_nowait(data)
                finally:
                    await console_broker.close_writer(writer)
                    guacd_closed.set()

            async def unexpected_proxy(reader, writer):
                await console_broker.close_writer(writer)
                self.fail("The synthetic test proxy must not be opened")

            async with await asyncio.start_server(agent_peer, "127.0.0.1", 0) as agent, await asyncio.start_server(guacd_peer, "127.0.0.1", 0) as guacd:
                async def ready_adapter(bridge, viewport, fingerprint):
                    _, bridge.active_writer = await asyncio.open_connection("127.0.0.1", agent.sockets[0].getsockname()[1])
                    reader, writer = await asyncio.open_connection("127.0.0.1", guacd.sockets[0].getsockname()[1])
                    listener = await asyncio.start_server(unexpected_proxy, "127.0.0.1", 0)
                    return reader, writer, listener

                certificate = {"type": "certificate", "sha256": "a" * 64, "subject": "CN=test", "issuer": "CN=test", "not_before": "2026-01-01T00:00:00+00:00", "not_after": "2027-01-01T00:00:00+00:00"}
                with patch.object(console_broker, "observe_certificate", AsyncMock(return_value=certificate)), patch.object(console_broker, "guacd_connect", ready_adapter), patch.object(console_broker, "AUTHORIZATION_CHECK_SECONDS", 0.02):
                    async with serve(console_broker.browser_socket, "127.0.0.1", 0, process_request=console_broker.process_request, subprotocols=["guacamole"], compression=None) as server:
                        port = server.sockets[0].getsockname()[1]
                        uri = f"ws://127.0.0.1:{port}/api/v1/hyper-v/console-sessions/{session.id}/native-stream/"
                        async with connect(uri, origin="https://portal.example.invalid", additional_headers={"Cookie": "ipms_sessionid=" + self.cookie}, subprotocols=["guacamole"]) as ws:
                            await ws.send(json.dumps({"type": "connect", "width": 1024, "height": 768}))
                            self.assertEqual(json.loads(await ws.recv())["type"], "certificate")
                            await ws.send(json.dumps({"type": "trust", "sha256": "a" * 64}))
                            self.assertEqual(json.loads(await ws.recv()), {"type": "ready"})
                            self.assertEqual(guac_instructions(await ws.recv())[0][0], "")
                            self.assertEqual(await ws.recv(), guac("sync", 1))
                            await ws.send(guac("key", 65, 1))
                            self.assertEqual(await asyncio.wait_for(forwarded.get(), 2), guac("key", 65, 1).encode())
                            await console_broker.db(lambda: TenantMembership.objects.filter(user_id=self.user.pk, tenant_id=self.tenant.pk).update(is_active=False))
                            with self.assertRaises(ConnectionClosed):
                                await asyncio.wait_for(ws.recv(), 2)
                            await asyncio.wait_for(agent_closed.wait(), 2)
                            await asyncio.wait_for(guacd_closed.wait(), 2)
                            with self.assertRaises(ConnectionClosed):
                                await ws.send(guac("key", 66, 1))
                            self.assertTrue(forwarded.empty())
                        for _ in range(20):
                            if not console_broker._bridges:
                                break
                            await asyncio.sleep(0.01)
            self.assertFalse(console_broker._bridges)

        asyncio.run(exercise())
        session.refresh_from_db()
        self.assertIn(session.status, ("closed", "failed"))

    def test_real_websocket_rejects_origin_cookie_query_and_other_owner(self):
        session = self.native_session()

        async def exercise():
            async with serve(console_broker.browser_socket, "127.0.0.1", 0,
                             process_request=console_broker.process_request, subprotocols=["guacamole"], compression=None) as server:
                port = server.sockets[0].getsockname()[1]
                base = f"ws://127.0.0.1:{port}/api/v1/hyper-v/console-sessions/{session.id}/native-stream/"
                for uri, origin, cookie in (
                    (base, "https://evil.example.invalid", self.cookie),
                    (base, "https://portal.example.invalid", "invalid"),
                    (base + "?token=forbidden", "https://portal.example.invalid", self.cookie),
                ):
                    with self.assertRaises(InvalidStatus):
                        async with connect(uri, origin=origin, additional_headers={"Cookie": "ipms_sessionid=" + cookie}, subprotocols=["guacamole"]):
                            self.fail("Unauthorized native stream was upgraded")
        asyncio.run(exercise())

    def test_real_websocket_explicit_trust_required_and_close_releases_claim(self):
        session = self.native_session()

        async def observation(bridge):
            return {"type": "certificate", "sha256": "a" * 64, "subject": "CN=test", "issuer": "CN=test", "not_before": "2026-01-01T00:00:00+00:00", "not_after": "2027-01-01T00:00:00+00:00"}

        async def exercise():
            with patch.object(console_broker, "observe_certificate", observation):
                async with serve(console_broker.browser_socket, "127.0.0.1", 0,
                                 process_request=console_broker.process_request, subprotocols=["guacamole"], compression=None) as server:
                    port = server.sockets[0].getsockname()[1]
                    uri = f"ws://127.0.0.1:{port}/api/v1/hyper-v/console-sessions/{session.id}/native-stream/"
                    async with connect(uri, origin="https://portal.example.invalid", additional_headers={"Cookie": "ipms_sessionid=" + self.cookie}, subprotocols=["guacamole"]) as ws:
                        await ws.send(json.dumps({"type": "connect", "width": 1024, "height": 768}))
                        self.assertEqual(json.loads(await ws.recv())["type"], "certificate")
                        await ws.send(json.dumps({"type": "trust", "sha256": "b" * 64}))
                        self.assertEqual(json.loads(await ws.recv())["type"], "error")
                    for _ in range(20):
                        if not console_broker._bridges:
                            break
                        await asyncio.sleep(0.01)
        asyncio.run(exercise())
        session.refresh_from_db()
        self.assertEqual(session.status, "failed")
        self.assertFalse(console_broker._bridges)
