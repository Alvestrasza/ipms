"""Bounded protocol adapters. RFC 6455 parsing is owned by websockets Sans-I/O."""
import asyncio
import json
import struct
import uuid

from websockets.frames import Frame, Opcode
from websockets.server import ServerProtocol
from websockets.http11 import Request

CHUNK_BYTES = 65_536


class NativeProtocolError(Exception):
    pass


async def write(writer, data):
    writer.write(data)
    await asyncio.wait_for(writer.drain(), 5)


class AgentWebSocket:
    def __init__(self, reader, writer, header):
        self.reader, self.writer = reader, writer
        self.protocol = ServerProtocol(max_size=CHUNK_BYTES)
        self.protocol.receive_data(header)
        events = self.protocol.events_received()
        if len(events) != 1 or not isinstance(events[0], Request):
            raise NativeProtocolError()
        self.request = events[0]
        self.fragment = bytearray()
        self.fragment_opcode = None
        self.pending = []
        self.send_lock = asyncio.Lock()

    async def accept(self):
        response = self.protocol.accept(self.request)
        if response.status_code != 101:
            raise NativeProtocolError()
        self.protocol.send_response(response)
        await self._flush()

    async def _flush(self):
        for data in self.protocol.data_to_send():
            if data:
                await write(self.writer, data)

    async def send(self, data):
        async with self.send_lock:
            if isinstance(data, bytes):
                if len(data) > CHUNK_BYTES:
                    raise NativeProtocolError()
                self.protocol.send_binary(data)
            else:
                self.protocol.send_text(json.dumps(data, separators=(",", ":")).encode())
            await self._flush()

    async def recv(self):
        while True:
            if not self.pending:
                # An idle guest need not produce RDP bytes. The independent
                # authorization/lease task cancels this read on loss of access.
                raw = await self.reader.read(CHUNK_BYTES)
                if not raw:
                    raise EOFError()
                self.protocol.receive_data(raw)
                self.pending.extend(self.protocol.events_received())
                async with self.send_lock:
                    await self._flush()
                if self.protocol.parser_exc:
                    raise NativeProtocolError()
            while self.pending:
                frame = self.pending.pop(0)
                if not isinstance(frame, Frame):
                    raise NativeProtocolError()
                if frame.opcode in (Opcode.PING, Opcode.PONG):
                    continue
                if frame.opcode == Opcode.CLOSE:
                    raise EOFError()
                if frame.opcode not in (Opcode.BINARY, Opcode.CONT):
                    raise NativeProtocolError()
                if frame.opcode == Opcode.BINARY:
                    self.fragment_opcode = Opcode.BINARY
                elif self.fragment_opcode is None:
                    raise NativeProtocolError()
                self.fragment.extend(frame.data)
                if len(self.fragment) > CHUNK_BYTES:
                    raise NativeProtocolError()
                if frame.fin:
                    message = bytes(self.fragment)
                    self.fragment.clear()
                    self.fragment_opcode = None
                    return message


def preconnection_pdu(vm_id):
    if str(uuid.UUID(vm_id)) != vm_id:
        raise NativeProtocolError()
    blob = (vm_id + "\x00").encode("utf-16-le")
    return struct.pack("<IIIIH", 18 + len(blob), 0, 2, 0, len(blob) // 2) + blob


def guac(*values):
    return ",".join(f"{len(str(value))}.{value}" for value in values) + ";"


def guac_instructions(text, *, maximum=CHUNK_BYTES):
    """Parse only complete bounded browser instructions; no user config opcode."""
    if not isinstance(text, str) or not text.isascii() or len(text) > maximum:
        raise NativeProtocolError()
    offset, values, result = 0, [], []
    while offset < len(text):
        dot = text.find(".", offset)
        digits = text[offset:dot]
        if dot < 0 or not digits.isdigit() or len(digits) > 6:
            raise NativeProtocolError()
        length = int(digits)
        end = dot + 1 + length
        if end >= len(text):
            raise NativeProtocolError()
        values.append(text[dot + 1:end])
        if text[end] == ";":
            result.append(values)
            values = []
        elif text[end] != ",":
            raise NativeProtocolError()
        offset = end + 1
    if values:
        raise NativeProtocolError()
    return result


async def read_guac(reader):
    values, total = [], 0
    while True:
        prefix = await asyncio.wait_for(reader.readuntil(b"."), 10)
        if len(prefix) > 7 or not prefix[:-1].isdigit():
            raise NativeProtocolError()
        length = int(prefix[:-1])
        total += length + len(prefix) + 1
        if total > CHUNK_BYTES:
            raise NativeProtocolError()
        # Handshake replies contain ASCII argument names / connection IDs only.
        value = await asyncio.wait_for(reader.readexactly(length), 10)
        values.append(value.decode("ascii"))
        delimiter = await asyncio.wait_for(reader.readexactly(1), 10)
        if delimiter == b";":
            return values
        if delimiter != b",":
            raise NativeProtocolError()
