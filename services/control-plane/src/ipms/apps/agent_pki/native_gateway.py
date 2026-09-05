"""Authenticated, fixed-route native reverse transport on the existing Gateway."""
import asyncio
import contextlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

from asgiref.sync import sync_to_async

from .native_protocol import AgentWebSocket, CHUNK_BYTES, NativeProtocolError, write

_connections = set()
_native_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="native-console-authorization")


async def native_database_call(function, *args, **kwargs):
    # Native authorization must never queue ahead of dedicated Agent liveness.
    from .gateway import _database_call, _bounded_heartbeat_database_call
    return await sync_to_async(_database_call, thread_sensitive=False, executor=_native_executor)(
        _bounded_heartbeat_database_call, function, *args, **kwargs,
    )


async def handle_native_gateway(reader, writer, peer_certificate, header):
    from .services import validate_peer_certificate
    from .native_console import authorize_agent, record_native_contact

    websocket = AgentWebSocket(reader, writer, header)
    request = websocket.request
    if request.path != "/v1/hyperv-console-native" or not peer_certificate:
        raise NativeProtocolError()
    session_id = request.headers["X-IPMS-Console-Session"]
    generation = request.headers["X-IPMS-Console-Generation"]
    enrollment = await native_database_call(validate_peer_certificate, peer_certificate)
    await native_database_call(authorize_agent, enrollment, session_id, generation)
    key = (str(enrollment.id), session_id, generation)
    if key in _connections or len(_connections) >= 32:
        raise NativeProtocolError()
    _connections.add(key)
    upstream = None
    tasks = []
    try:
        upstream_reader, upstream = await asyncio.wait_for(asyncio.open_unix_connection(
            os.environ.get("IPMS_NATIVE_CONSOLE_AGENT_SOCKET", "/run/ipms-console/agent.sock"), limit=CHUNK_BYTES,
        ), 5)
        await write(upstream, json.dumps({
            "session_id": session_id, "stream_generation": generation, "enrollment_id": str(enrollment.id),
        }, separators=(",", ":")).encode() + b"\n")
        if await asyncio.wait_for(upstream_reader.readline(), 5) != b"OK\n":
            raise NativeProtocolError()
        await websocket.accept()
        await websocket.send({"type": "lease", "seconds": 15, "stream_generation": generation})

        async def leases():
            while True:
                await asyncio.sleep(5)
                current = await native_database_call(validate_peer_certificate, peer_certificate)
                await native_database_call(authorize_agent, current, session_id, generation)
                await websocket.send({"type": "lease", "seconds": 15, "stream_generation": generation})
                await native_database_call(record_native_contact, session_id, generation)

        async def to_agent():
            while data := await upstream_reader.read(CHUNK_BYTES):
                await websocket.send(data)

        async def from_agent():
            while True:
                await write(upstream, await websocket.recv())

        tasks = [asyncio.create_task(operation()) for operation in (leases, to_agent, from_agent)]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if upstream is not None:
            upstream.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(upstream.wait_closed(), 5)
        _connections.discard(key)
