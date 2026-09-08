"""Real browser WebSocket / TCP relay boundaries; no real host is contacted."""
import asyncio
import codecs
import json
import random
from unittest.mock import AsyncMock, patch

from django.test import SimpleTestCase, TransactionTestCase
from django.utils import timezone
from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed
from websockets.frames import Opcode

from ipms.apps.discovery.models import HyperVConsoleSession

from . import console_broker
from .native_protocol import CHUNK_BYTES, GuacStreamFramer, NativeProtocolError, guac, guac_instructions
from .test_native_console import NativeFixture


class RendererFramerTests(SimpleTestCase):
    def test_every_utf8_split_preserves_unicode_lengths_and_literal_delimiters(self):
        wire = (guac("name", "Größe 🙂 .;,:") + guac("blob", 1, "YWJjZA==") + guac("sync", 123)).encode()
        for split in range(len(wire) + 1):
            framer = GuacStreamFramer()
            decoder = codecs.getincrementaldecoder("utf-8")()
            messages = []
            for part in (wire[:split], wire[split:]):
                messages.extend(framer.feed(decoder.decode(part)))
            decoder.decode(b"", final=True)
            framer.finish()
            self.assertEqual("".join(messages).encode(), wire)

    def test_byte_at_a_time_and_empty_elements_preserve_exact_wire(self):
        wire = guac("", "ping", 1) + guac("name", "") + guac("nop")
        framer = GuacStreamFramer()
        messages = []
        for character in wire:
            messages.extend(framer.feed(character))
        framer.finish()
        self.assertEqual("".join(messages), wire)
        self.assertEqual(len(messages), 3)

    def test_partial_large_instruction_is_bounded_without_one_message_per_element(self):
        payload = "Y" * (CHUNK_BYTES * 3)
        wire = guac("blob", 7, payload)
        framer = GuacStreamFramer()
        for offset in range(0, len(wire) - 1, CHUNK_BYTES):
            self.assertEqual(framer.feed(wire[offset:min(offset + CHUNK_BYTES, len(wire) - 1)]), [])
        self.assertEqual(framer.feed(";"), [wire])
        framer.finish()
        small = guac("nop") * 1000
        self.assertEqual(framer.feed(small), [small])

    def test_batch_limits_do_not_split_instructions(self):
        first = guac("blob", 1, "A" * (CHUNK_BYTES - 40))
        second = guac("blob", 2, "B" * 64)
        messages = GuacStreamFramer().feed(first + second + guac("sync", 1))
        self.assertEqual(messages, [first, second + guac("sync", 1)])

    def test_byte_limit_includes_multibyte_payload_and_framing(self):
        wire = guac("name", "🙂")
        self.assertEqual(GuacStreamFramer(maximum=len(wire.encode())).feed(wire), [wire])
        with self.assertRaises(NativeProtocolError):
            GuacStreamFramer(maximum=len(wire.encode()) - 1).feed(wire)

    def test_invalid_lengths_delimiters_and_truncated_streams_fail_closed(self):
        for wire in ("x.nop;", "-1.x;", ".nop;", "99999999.x;", "8388608.x;", "3.nop!", "٣.nop;"):
            with self.subTest(wire=wire), self.assertRaises(NativeProtocolError):
                GuacStreamFramer().feed(wire)
        for wire in ("3", "3.", "3.no", "3.nop", "3.nop,", "3.nop,0."):
            with self.subTest(wire=wire), self.assertRaises(NativeProtocolError):
                framer = GuacStreamFramer()
                framer.feed(wire)
                framer.finish()

    def test_repeated_fragmented_images_preserve_order_and_flush_complete_prefix(self):
        rng = random.Random(240)
        wire = "".join(guac("blob", 1, "Y" * rng.randrange(1, 4096)) + guac("sync", i) for i in range(200))
        framer = GuacStreamFramer()
        messages, offset = [], 0
        while offset < len(wire):
            width = rng.randrange(1, 1000)
            messages.extend(framer.feed(wire[offset:offset + width]))
            offset += width
        framer.finish()
        self.assertEqual("".join(messages), wire)
        for message in messages:
            guac_instructions(message)
        self.assertEqual(framer.feed(guac("nop") + "4.blob,1.1,"), [guac("nop")])


class NativeStreamFramingTests(NativeFixture, TransactionTestCase):
    def test_keepalive_cannot_interrupt_a_partial_renderer_instruction(self):
        self.exercise_stream(application_heartbeats=True)

    def test_native_browser_pongs_keep_renderer_alive_without_javascript_messages(self):
        self.exercise_stream(application_heartbeats=False)

    def test_missing_native_pong_closes_without_manufacturing_renderer_input(self):
        self.exercise_stream(application_heartbeats=False, native_pongs=False)

    def exercise_stream(self, *, application_heartbeats, native_pongs=True):
        session = self.native_session()

        async def exercise():
            first_read_completed = asyncio.Event()
            release_tail = asyncio.Event()
            forwarded = asyncio.Queue()
            payload = guac("blob", 1, "YWJjZA==")
            split = payload.index("YW") + 2

            async def renderer_peer(reader, writer):
                try:
                    writer.write(payload[:split].encode())
                    await writer.drain()
                    await release_tail.wait()
                    writer.write((payload[split:] + guac("sync", 1)).encode())
                    await writer.drain()
                    while data := await reader.read(65536):
                        forwarded.put_nowait(data)
                finally:
                    await console_broker.close_writer(writer)

            class ObservedReader:
                def __init__(self, reader):
                    self.reader = reader
                    self.reads = 0

                async def read(self, size):
                    self.reads += 1
                    if self.reads == 2:
                        # The first partial read has been fully processed by the
                        # production relay. No sleep or packet-timing assumption.
                        first_read_completed.set()
                    return await self.reader.read(size)

            async def unused_proxy(reader, writer):
                await console_broker.close_writer(writer)
                self.fail("No Agent or host may be opened by this test")

            certificate = {
                "type": "certificate", "sha256": "a" * 64,
                "subject": "CN=fixture", "issuer": "CN=fixture",
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
            }
            async with await asyncio.start_server(renderer_peer, "127.0.0.1", 0) as renderer:
                async def ready_adapter(bridge, viewport, fingerprint):
                    reader, writer = await asyncio.open_connection(
                        "127.0.0.1", renderer.sockets[0].getsockname()[1],
                    )
                    listener = await asyncio.start_server(unused_proxy, "127.0.0.1", 0)
                    return ObservedReader(reader), writer, listener

                with patch.object(console_broker, "observe_certificate", AsyncMock(return_value=certificate)), patch.object(console_broker, "guacd_connect", ready_adapter):
                    async with serve(
                        console_broker.browser_socket, "127.0.0.1", 0,
                        process_request=console_broker.process_request,
                        subprotocols=["guacamole"], compression=None,
                    ) as server:
                        uri = f"ws://127.0.0.1:{server.sockets[0].getsockname()[1]}/api/v1/hyper-v/console-sessions/{session.id}/native-stream/"
                        async with connect(uri, origin="https://portal.example.invalid", additional_headers={"Cookie": "ipms_sessionid=" + self.cookie}, subprotocols=["guacamole"]) as ws:
                            try:
                                await ws.send(json.dumps({"type": "connect", "width": 1024, "height": 768}))
                                self.assertEqual(json.loads(await ws.recv())["type"], "certificate")
                                await ws.send(json.dumps({"type": "trust", "sha256": "a" * 64}))
                                self.assertEqual(json.loads(await ws.recv()), {"type": "ready"})
                                self.assertEqual(guac_instructions(await ws.recv())[0][0], "")
                                await asyncio.wait_for(first_read_completed.wait(), 2)
                                ping = guac("", "ping", 1)
                                await ws.send(ping)
                                received = []
                                while True:
                                    chunk = await asyncio.wait_for(ws.recv(), 2)
                                    received.append(chunk)
                                    if chunk == ping:
                                        break
                                release_tail.set()
                                while not received[-1].endswith(guac("sync", 1)):
                                    received.append(await asyncio.wait_for(ws.recv(), 2))
                                self.assertEqual(
                                    guac_instructions("".join(received)),
                                    [["", "ping", "1"], ["blob", "1", "YWJjZA=="], ["sync", "1"]],
                                )
                                # Genuine browser liveness must reach the final
                                # renderer, not only the outer WebSocket broker.
                                self.assertEqual(await asyncio.wait_for(forwarded.get(), 2), guac("nop").encode())
                                # Real elapsed time beyond both the renderer's
                                # 15-second input timeout and the 30-second lease.
                                # The screen is idle; only genuine browser pings
                                # and independent authorization checks continue.
                                if application_heartbeats:
                                    for pulse in range(2, 47):
                                        await asyncio.sleep(1)
                                        heartbeat = guac("", "ping", pulse)
                                        await ws.send(heartbeat)
                                        self.assertEqual(await asyncio.wait_for(ws.recv(), 2), heartbeat)
                                        self.assertEqual(await asyncio.wait_for(forwarded.get(), 2), guac("nop").encode())
                                elif native_pongs:
                                    # Native WebSocket PONGs are handled without
                                    # application messages or JavaScript timers.
                                    for _ in range(8):
                                        self.assertEqual(await asyncio.wait_for(forwarded.get(), 7), guac("nop").encode())
                                else:
                                    # Suppress only this fixture peer's native
                                    # PONG at the actual protocol boundary.
                                    receive_frame = ws.protocol.recv_frame
                                    ws.protocol.recv_frame = lambda frame: None if frame.opcode == Opcode.PING else receive_frame(frame)
                                    self.assertEqual(json.loads(await asyncio.wait_for(ws.recv(), 12)), {
                                        "type": "error", "code": "native_connection_failed",
                                    })
                                    with self.assertRaises(ConnectionClosed):
                                        await asyncio.wait_for(ws.recv(), 2)
                                    self.assertTrue(forwarded.empty())
                                current = await console_broker.db(lambda: HyperVConsoleSession.objects.get(pk=session.pk))
                                self.assertEqual(current.status, "active" if native_pongs else "failed")
                                if native_pongs:
                                    self.assertGreater(current.lease_expires_at, timezone.now())
                            finally:
                                release_tail.set()
            self.assertFalse(console_broker._bridges)

        asyncio.run(exercise())
