"""Bounded protocol adapters. RFC 6455 parsing is owned by websockets Sans-I/O."""
import asyncio
import io
import json
import struct
import uuid

from websockets.frames import Frame, Opcode
from websockets.server import ServerProtocol
from websockets.http11 import Request

CHUNK_BYTES = 65_536
MAX_GUAC_INSTRUCTION_BYTES = 8_388_608


class NativeProtocolError(Exception):
    pass


class GuacStreamFramer:
    """Frame UTF-8-decoded renderer output at complete instruction boundaries.

    TCP read boundaries are not Guacamole message boundaries. Browser keepalive
    replies share this stream and may only be inserted between instructions.
    Lengths count Unicode code points, while the retained data is byte-bounded.
    StringIO avoids repeatedly copying a growing fragmented image instruction.
    """

    def __init__(self, maximum=MAX_GUAC_INSTRUCTION_BYTES):
        if type(maximum) is not int or not 1 <= maximum <= MAX_GUAC_INSTRUCTION_BYTES:
            raise ValueError("Invalid native instruction limit")
        self.maximum = maximum
        self.instruction = io.StringIO()
        self.size = 0
        self.prefix = ""
        self.remaining = None

    def _append(self, text):
        self.size += len(text.encode("utf-8"))
        if self.size > self.maximum:
            raise NativeProtocolError()
        self.instruction.write(text)

    def feed(self, text):
        position = 0
        messages, batch, batch_size = [], [], 0
        while position < len(text):
            if self.remaining is None:
                dot = text.find(".", position)
                end = len(text) if dot < 0 else dot
                digits = text[position:end]
                self.prefix += digits
                if (len(self.prefix) > 7 or not self.prefix.isascii()
                        or not self.prefix.isdigit()):
                    raise NativeProtocolError()
                self._append(digits)
                position = end
                if dot < 0:
                    break
                self.remaining = int(self.prefix)
                self.prefix = ""
                self._append(".")
                if self.size + self.remaining + 1 > self.maximum:
                    raise NativeProtocolError()
                position += 1
            elif self.remaining:
                length = min(self.remaining, len(text) - position)
                self._append(text[position:position + length])
                self.remaining -= length
                position += length
            else:
                delimiter = text[position]
                if delimiter not in (",", ";"):
                    raise NativeProtocolError()
                self._append(delimiter)
                position += 1
                self.remaining = None
                if delimiter == ";":
                    if batch and batch_size + self.size > CHUNK_BYTES:
                        messages.append("".join(batch))
                        batch, batch_size = [], 0
                    batch.append(self.instruction.getvalue())
                    batch_size += self.size
                    self.instruction = io.StringIO()
                    self.size = 0
        if batch:
            messages.append("".join(batch))
        return messages

    def finish(self):
        if self.size:
            raise NativeProtocolError()


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
