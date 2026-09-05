"""Loopback browser/guacd broker; native network access exists only at the Agent."""
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import struct
import uuid
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit

import django
from cryptography import x509
from django.conf import settings
from django.utils import timezone
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosedOK

from .native_protocol import CHUNK_BYTES, NativeProtocolError, guac, guac_instructions, preconnection_pdu, read_guac, write

ROUTE = re.compile(r"^/api/v1/hyper-v/console-sessions/([0-9a-f-]{36})/native-stream/$")
_bridges = {}
GUACD_PORT = 4822
AUTHORIZATION_CHECK_SECONDS = 5


def classify_failure(error):
    # Never echo arbitrary TLS, database, credential or remote error text.
    if isinstance(error, NativeProtocolError) and str(error) == "native_certificate_rejected":
        return "native_certificate_rejected"
    return "native_connection_failed"


async def db(function, *args, **kwargs):
    from .native_gateway import native_database_call
    return await native_database_call(function, *args, **kwargs)


async def close_writer(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 5)
    except Exception:
        writer.transport.abort()


class Bridge:
    def __init__(self, session, cookie):
        self.session, self.cookie = session, cookie
        self.waiter = None
        self.active_writer = None
        self.proxy_task = None

    async def open_agent(self):
        if self.waiter is not None or self.active_writer is not None:
            raise NativeProtocolError()
        waiter = asyncio.get_running_loop().create_future()
        self.waiter = waiter
        try:
            reader, writer = await asyncio.wait_for(waiter, 20)
            self.active_writer = writer
            return reader, writer
        finally:
            self.waiter = None

    async def release_agent(self):
        writer, self.active_writer = self.active_writer, None
        await close_writer(writer)


def peer_is_gateway(writer):
    if not hasattr(socket, "SO_PEERCRED"):
        return False
    import pwd
    expected = pwd.getpwnam(os.environ.get("IPMS_NATIVE_CONSOLE_GATEWAY_USER", "ipms-agent-gateway")).pw_uid
    peer = writer.get_extra_info("socket")
    _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid == expected


async def agent_socket(reader, writer):
    transferred = False
    try:
        if not peer_is_gateway(writer):
            raise NativeProtocolError()
        raw = await asyncio.wait_for(reader.readline(), 5)
        if len(raw) > 512:
            raise NativeProtocolError()
        message = json.loads(raw)
        if set(message) != {"session_id", "stream_generation", "enrollment_id"}:
            raise NativeProtocolError()
        bridge = _bridges.get(message["session_id"])
        if (bridge is None or message["stream_generation"] != str(bridge.session.stream_generation)
                or message["enrollment_id"] != str(bridge.session.enrollment_id)
                or bridge.waiter is None or bridge.waiter.done() or bridge.active_writer is not None):
            raise NativeProtocolError()
        from .native_console import authorize_browser
        await db(authorize_browser, str(bridge.session.id), bridge.cookie, claim=bridge.session.browser_claim)
        if bridge.waiter is None or bridge.waiter.done():
            raise NativeProtocolError()
        await write(writer, b"OK\n")
        bridge.waiter.set_result((reader, writer))
        transferred = True
    except Exception:
        pass
    finally:
        if not transferred:
            await close_writer(writer)


async def observe_certificate(bridge):
    reader, writer = await bridge.open_agent()
    try:
        await write(writer, preconnection_pdu(bridge.session.vm_source_id))
        # VMConnect's preconnection mode disables X.224 security negotiation:
        # PCB is followed directly by TLS. Stop before any CredSSP/application
        # authentication or graphical connection, exactly as an observation.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Observation only; never an authenticated console.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # This writer was accepted from the Agent Gateway's reverse Unix
        # connection. StreamWriter.start_tls infers the TLS *server* role from
        # that socket, which is wrong here. Explicit client MemoryBIO keeps TLS
        # role independent of who opened the underlying transport.
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        secured = context.wrap_bio(incoming, outgoing, server_side=False)
        received_bytes = 0
        async with asyncio.timeout(10):
            while True:
                try:
                    secured.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    while outgoing.pending:
                        await write(writer, outgoing.read(CHUNK_BYTES))
                    data = await reader.read(CHUNK_BYTES)
                    received_bytes += len(data)
                    if not data or received_bytes > 1_048_576:
                        raise NativeProtocolError()
                    incoming.write(data)
                except ssl.SSLWantWriteError:
                    while outgoing.pending:
                        await write(writer, outgoing.read(CHUNK_BYTES))
            while outgoing.pending:
                await write(writer, outgoing.read(CHUNK_BYTES))
        certificate = secured.getpeercert(binary_form=True)
        parsed = x509.load_der_x509_certificate(certificate)
        now = timezone.now()
        if not parsed.not_valid_before_utc <= now <= parsed.not_valid_after_utc:
            raise NativeProtocolError("native_certificate_rejected")
        # Close the observation as TLS, without authenticating. An immediate
        # raw close can reset a peer still emitting TLS 1.3 session tickets.
        # Shutdown is best-effort and bounded; it sends no application data.
        with contextlib.suppress(Exception):
            async with asyncio.timeout(1):
                while True:
                    try:
                        secured.unwrap()
                        break
                    except ssl.SSLWantReadError:
                        while outgoing.pending:
                            await write(writer, outgoing.read(CHUNK_BYTES))
                        data = await reader.read(CHUNK_BYTES)
                        received_bytes += len(data)
                        if not data or received_bytes > 1_048_576:
                            break
                        incoming.write(data)
                while outgoing.pending:
                    await write(writer, outgoing.read(CHUNK_BYTES))
        return {
            "type": "certificate", "sha256": hashlib.sha256(certificate).hexdigest(),
            "subject": parsed.subject.rfc4514_string()[:2048], "issuer": parsed.issuer.rfc4514_string()[:2048],
            "not_before": parsed.not_valid_before_utc.isoformat(), "not_after": parsed.not_valid_after_utc.isoformat(),
        }
    finally:
        await bridge.release_agent()


async def bidi(reader_a, writer_a, reader_b, writer_b):
    async def copy(reader, writer):
        while data := await reader.read(CHUNK_BYTES):
            await write(writer, data)
    tasks = [asyncio.create_task(copy(reader_a, writer_b)), asyncio.create_task(copy(reader_b, writer_a))]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def guacd_connect(bridge, viewport, fingerprint):
    claimed = False

    async def proxy(reader, writer):
        nonlocal claimed
        if claimed:
            await close_writer(writer)
            return
        claimed = True
        bridge.proxy_task = asyncio.current_task()
        try:
            agent_reader, agent_writer = await bridge.open_agent()
            await bidi(reader, writer, agent_reader, agent_writer)
        finally:
            await close_writer(writer)
            await bridge.release_agent()

    listener = await asyncio.start_server(proxy, "127.0.0.1", 0, limit=CHUNK_BYTES, backlog=1)
    reader, writer = None, None
    try:
        port = listener.sockets[0].getsockname()[1]
        reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", GUACD_PORT, limit=CHUNK_BYTES), 5)
        await write(writer, guac("select", "rdp").encode())
        arguments = await read_guac(reader)
        if not arguments or arguments[0] != "args" or "ipms-strict-certificate" not in arguments:
            raise NativeProtocolError()
        names = arguments[1:]
        from .native_console import load_credential
        credential = await db(load_credential, bridge.session)
        parameters = {
            "hostname": "127.0.0.1", "port": str(port), "security": "vmconnect",
            "preconnection-blob": bridge.session.vm_source_id, "preconnection-id": "0",
            "username": credential["username"], "password": credential["password"], "domain": credential["domain"],
            "ipms-strict-certificate": "true", "cert-fingerprints": "sha256:" + fingerprint,
            "ignore-cert": "false", "cert-tofu": "false", "disable-auth": "false",
            "disable-copy": "true", "disable-paste": "true", "enable-drive": "false",
            "enable-printing": "false", "enable-audio": "false", "disable-audio": "true",
            "enable-audio-input": "false", "enable-sftp": "false", "enable-wallpaper": "false",
            "enable-theming": "false", "enable-font-smoothing": "false", "enable-desktop-composition": "false",
            "enable-menu-animations": "false", "enable-full-window-drag": "false",
            "disable-bitmap-caching": "false", "disable-offscreen-caching": "false",
            "resize-method": "display-update", "timeout": "10", "max-retries": "0",
        }
        if names and re.fullmatch(r"VERSION_\d+_\d+_\d+", names[0]):
            # The version marker occupies a real connect argument position.
            # Omitting it shifts credentials and all following settings.
            parameters[names[0]] = "VERSION_1_5_0"
        for required in ("hostname", "port", "preconnection-blob", "preconnection-id", "security", "cert-fingerprints", "username", "password"):
            if required not in names:
                raise NativeProtocolError()
        await write(writer, guac("size", viewport["width"], viewport["height"], 96).encode())
        await write(writer, (guac("audio") + guac("video") + guac("image", "image/png", "image/jpeg")).encode())
        await write(writer, guac("connect", *(parameters.get(name, "") for name in names)).encode())
        credential.clear()
        parameters.clear()
        response = await read_guac(reader)
        if len(response) != 2 or response[0] != "ready":
            raise NativeProtocolError()
        return reader, writer, listener
    except BaseException:
        listener.close()
        await listener.wait_closed()
        await close_writer(writer)
        if bridge.proxy_task:
            bridge.proxy_task.cancel()
            await asyncio.gather(bridge.proxy_task, return_exceptions=True)
        raise


async def process_request(connection, request):
    from .native_console import authorize_browser
    try:
        origin = getattr(settings, "NATIVE_CONSOLE_ORIGIN", "")
        match = ROUTE.fullmatch(request.path)
        if not origin or request.headers.get("Origin") != origin or not match or len(_bridges) >= 32:
            raise NativeProtocolError()
        cookie = SimpleCookie()
        cookie.load(request.headers.get("Cookie", ""))
        session_cookie = cookie[settings.SESSION_COOKIE_NAME].value
        await db(authorize_browser, match[1], session_cookie, peek=True)
        connection.ipms_session_id, connection.ipms_cookie = match[1], session_cookie
    except Exception:
        return connection.respond(403, "Native console unavailable\n")
    return None


async def browser_socket(websocket):
    from .native_console import authorize_browser, audit_native, close_native, mark_native_ready
    bridge = None
    watcher = None
    guacd_writer = None
    listener = None
    failure = ""
    try:
        session = await db(authorize_browser, websocket.ipms_session_id, websocket.ipms_cookie, attach=True)
        bridge = Bridge(session, websocket.ipms_cookie)
        if str(session.id) in _bridges or len(_bridges) >= 32:
            raise NativeProtocolError()
        _bridges[str(session.id)] = bridge

        async def watch():
            try:
                while True:
                    await db(authorize_browser, str(session.id), bridge.cookie, claim=session.browser_claim, renew=True)
                    await asyncio.sleep(AUTHORIZATION_CHECK_SECONDS)
            except Exception:
                await bridge.release_agent()
                await websocket.close(code=1008, reason="Authorization expired")

        watcher = asyncio.create_task(watch())
        viewport = json.loads(await asyncio.wait_for(websocket.recv(), 10))
        if (set(viewport) != {"type", "width", "height"} or viewport["type"] != "connect"
                or any(type(viewport[name]) is not int or not 200 <= viewport[name] <= 3840 for name in ("width", "height"))):
            raise NativeProtocolError()
        certificate = await observe_certificate(bridge)
        await websocket.send(json.dumps(certificate))
        approval = json.loads(await asyncio.wait_for(websocket.recv(), 60))
        if set(approval) != {"type", "sha256"} or approval != {"type": "trust", "sha256": certificate["sha256"]}:
            raise NativeProtocolError("native_certificate_rejected")
        await db(audit_native, session, "certificate.accept", {"sha256": certificate["sha256"]})
        guacd_reader, guacd_writer, listener = await guacd_connect(bridge, viewport, certificate["sha256"])
        await db(mark_native_ready, str(session.id), session.browser_claim)
        await websocket.send(json.dumps({"type": "ready"}))
        await websocket.send(guac("", str(uuid.uuid4())))

        async def to_browser():
            import codecs
            decoder = codecs.getincrementaldecoder("utf-8")()
            while data := await guacd_reader.read(CHUNK_BYTES):
                text = decoder.decode(data)
                if text:
                    await asyncio.wait_for(websocket.send(text), 5)

        async def to_guacd():
            async for message in websocket:
                if not isinstance(message, str):
                    raise NativeProtocolError()
                if message.startswith("{"):
                    if json.loads(message) != {"type": "secure_attention"}:
                        raise NativeProtocolError()
                    await db(audit_native, session, "secure_attention")
                    message = "".join(guac("key", key, pressed) for key, pressed in (
                        (65507, 1), (65513, 1), (65535, 1), (65535, 0), (65513, 0), (65507, 0),
                    ))
                for instruction in guac_instructions(message):
                    opcode = instruction[0]
                    if opcode == "":
                        if len(instruction) != 3 or instruction[1] != "ping" or not instruction[2].isdigit():
                            raise NativeProtocolError()
                        await websocket.send(guac(*instruction))
                        continue
                    if opcode not in {"key", "mouse", "size", "sync", "ack", "nop", "disconnect"}:
                        raise NativeProtocolError()
                    validate_browser_instruction(instruction)
                    await write(guacd_writer, guac(*instruction).encode())

        transfers = [asyncio.create_task(to_browser()), asyncio.create_task(to_guacd())]
        try:
            done, _ = await asyncio.wait(transfers, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        finally:
            for task in transfers:
                task.cancel()
            await asyncio.gather(*transfers, return_exceptions=True)
    except ConnectionClosedOK:
        pass
    except Exception as error:
        failure = classify_failure(error)
        with contextlib.suppress(Exception):
            await websocket.send(json.dumps({"type": "error", "code": failure}))
    finally:
        if watcher:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
        if listener:
            listener.close()
            await listener.wait_closed()
        await close_writer(guacd_writer)
        if bridge:
            if bridge.proxy_task:
                bridge.proxy_task.cancel()
                await asyncio.gather(bridge.proxy_task, return_exceptions=True)
            await bridge.release_agent()
            _bridges.pop(str(bridge.session.id), None)
            with contextlib.suppress(Exception):
                await db(close_native, str(bridge.session.id), bridge.session.browser_claim, failure=failure)
        await websocket.close()


def validate_browser_instruction(instruction):
    opcode, *args = instruction
    lengths = {"key": (2,), "mouse": (3,), "size": (2, 3), "sync": (1, 2), "ack": (3,), "nop": (0,), "disconnect": (0,)}
    if opcode not in lengths or len(args) not in lengths[opcode]:
        raise NativeProtocolError()
    for index, value in enumerate(args):
        if opcode == "ack" and index == 1:
            if len(value) > 256:
                raise NativeProtocolError()
        elif not value.isdigit() or len(value) > 20:
            raise NativeProtocolError()
    if opcode == "key" and (int(args[0]) > 0xffffffff or args[1] not in ("0", "1")):
        raise NativeProtocolError()
    if opcode == "mouse" and (int(args[0]) > 8192 or int(args[1]) > 8192 or int(args[2]) > 255):
        raise NativeProtocolError()
    if opcode == "size" and any(not 200 <= int(value) <= 3840 for value in args[:2]):
        raise NativeProtocolError()


async def run():
    await validate_startup()
    path = os.environ.get("IPMS_NATIVE_CONSOLE_AGENT_SOCKET", "/run/ipms-console/agent.sock")
    if Path(path).exists():
        # Refuse unexpected path reuse; systemd RuntimeDirectory owns cleanup.
        raise RuntimeError("Native console socket path already exists")
    unix = await asyncio.start_unix_server(agent_socket, path=path, limit=4096)
    os.chmod(path, 0o660)
    try:
        async with unix, serve(
            browser_socket, "127.0.0.1", 9420, subprotocols=["guacamole"],
            process_request=process_request, compression=None, max_size=CHUNK_BYTES,
            max_queue=4, write_limit=CHUNK_BYTES, open_timeout=10, close_timeout=5,
            ping_interval=10, ping_timeout=10, server_header=None,
        ):
            await asyncio.Future()
    finally:
        Path(path).unlink(missing_ok=True)


async def validate_startup():
    from .native_console import _key
    origin = getattr(settings, "NATIVE_CONSOLE_ORIGIN", "")
    parsed = urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or origin != f"https://{parsed.netloc}"):
        raise RuntimeError("Native console origin is not configured")
    _key()
    reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", GUACD_PORT, limit=CHUNK_BYTES), 5)
    try:
        await write(writer, guac("select", "rdp").encode())
        arguments = await read_guac(reader)
        if not arguments or arguments[0] != "args" or "ipms-strict-certificate" not in arguments:
            raise RuntimeError("Native console strict adapter is unavailable")
    finally:
        await close_writer(writer)


def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ipms_control_plane.settings.console_broker")
    django.setup()
    # No debug-level WebSocket/RDP payload logging, including handshake cookies.
    logging.getLogger("websockets").setLevel(logging.CRITICAL)
    asyncio.run(run())


if __name__ == "__main__":
    main()
