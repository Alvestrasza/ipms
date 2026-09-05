import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from .gateway import handle_connection


class ConsoleWriter:
    def __init__(self):
        self.output = bytearray()
        self.closed = False

    def get_extra_info(self, name):
        if name == "ssl_object":
            return SimpleNamespace(
                selected_alpn_protocol=lambda: "http/1.1",
                getpeercert=lambda **kwargs: b"test-certificate",
            )
        return None

    def write(self, data):
        self.output.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    async def wait_closed(self):
        pass


def request(*, path="/v1/hyperv-console", keep_alive=True, device="test-device"):
    body = json.dumps({"type": "hyperv_console_cycle", "device_uri": device}).encode()
    return (
        f"POST {path} HTTP/1.1\r\nHost: gateway.example.invalid\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\n"
    ).encode() + body


class ConsoleTransportTests(SimpleTestCase):
    async def exchange(self, data, *, revoke_on=None):
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()
        writer = ConsoleWriter()
        validations = 0
        cycles = 0

        async def database_call(function, *args, **kwargs):
            nonlocal validations, cycles
            if function.__name__ == "validate_peer_certificate":
                validations += 1
                if validations == revoke_on:
                    raise ValidationError("The test identity was revoked.")
                return SimpleNamespace(device_uri="test-device")
            if function.__name__ == "process_console_cycle":
                cycles += 1
                return None
            self.fail("A console connection called an unrelated capability.")

        with patch("ipms.apps.agent_pki.gateway._database_call_async", database_call):
            await handle_connection(reader, writer)
        self.assertTrue(writer.closed)
        return bytes(writer.output), validations, cycles

    async def test_reuses_connection_and_revalidates_each_request(self):
        output, validations, cycles = await self.exchange(request() + request(keep_alive=False))
        self.assertEqual(validations, 2)
        self.assertEqual(cycles, 2)
        self.assertEqual(output.count(b"HTTP/1.1 200"), 2)
        self.assertIn(b"Connection: keep-alive", output)
        self.assertIn(b"Connection: close", output)

    async def test_revocation_blocks_second_message_on_existing_connection(self):
        output, validations, cycles = await self.exchange(request() + request(), revoke_on=2)
        self.assertEqual(validations, 2)
        self.assertEqual(cycles, 1)
        self.assertIn(b"HTTP/1.1 400", output)

    async def test_persistent_connection_cannot_change_routes_or_device(self):
        for second in (request(path="/v1/enroll"), request(device="another-device")):
            output, _, cycles = await self.exchange(request() + second)
            self.assertEqual(cycles, 1)
            self.assertIn(b"HTTP/1.1 400", output)

    async def test_connection_lifetime_is_bounded(self):
        output, validations, cycles = await self.exchange(request() * 257)
        self.assertEqual(validations, 256)
        self.assertEqual(cycles, 256)
        self.assertEqual(output.count(b"HTTP/1.1 200"), 256)
        self.assertIn(b"Connection: close", output)

    async def test_old_one_shot_clients_remain_supported(self):
        output, validations, cycles = await self.exchange(request(keep_alive=False) + request())
        self.assertEqual((validations, cycles), (1, 1))
        self.assertNotIn(b"Connection: keep-alive", output)
