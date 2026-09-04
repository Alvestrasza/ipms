import asyncio
import contextlib
import json
import logging
import os
import ssl
from pathlib import Path

import django
from asgiref.sync import sync_to_async
from django.core.exceptions import ValidationError
from django.db import close_old_connections


MAX_MESSAGE_BYTES = 65_536
MAX_HTTP_HEADER_BYTES = 16_384
ALLOWED_AGENT_MESSAGES = {
    "hello",
    "inventory",
    "software_inventory",
    "telemetry",
    "acknowledgement",
    "health",
    "certificate_renewal",
}
logger = logging.getLogger("ipms.agent_gateway")


def _database_call(function, *args, **kwargs):
    close_old_connections()
    try:
        return function(*args, **kwargs)
    finally:
        close_old_connections()


async def _database_call_async(function, *args, **kwargs):
    return await sync_to_async(_database_call, thread_sensitive=True)(
        function,
        *args,
        **kwargs,
    )


def _connection_protocol(selected_alpn: str | None) -> str:
    if selected_alpn == "ipms-agent/1":
        return "stream"
    if selected_alpn in {"http/1.1", None}:
        return "http"
    raise ValidationError("The Agent Gateway ALPN is invalid.")


def _bounded_json(line: bytes) -> dict:
    if not line or len(line) > MAX_MESSAGE_BYTES:
        raise ValidationError("The Gateway message size is invalid.")
    try:
        document = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValidationError("The Gateway message is invalid.") from exc
    if not isinstance(document, dict) or not isinstance(document.get("type"), str):
        raise ValidationError("The Gateway message envelope is invalid.")
    return document


def build_tls_context(runtime_directory: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_OPTIONAL
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    if hasattr(ssl, "VERIFY_X509_PARTIAL_CHAIN"):
        context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    context.load_cert_chain(
        runtime_directory / "gateway-chain.pem",
        runtime_directory / "gateway.key",
    )
    context.load_verify_locations(cafile=runtime_directory / "agent-trust.pem")
    context.set_alpn_protocols(["ipms-agent/1", "http/1.1"])
    return context


async def _reply(writer: asyncio.StreamWriter, document: dict) -> None:
    writer.write(json.dumps(document, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


def _parse_http_request(header: bytes) -> tuple[str, dict[str, str], int]:
    if (
        not header
        or len(header) > MAX_HTTP_HEADER_BYTES
        or not header.endswith(b"\r\n\r\n")
    ):
        raise ValidationError("The Agent Gateway HTTP header is invalid.")
    try:
        lines = header[:-4].decode("ascii").split("\r\n")
        method, path, version = lines[0].split(" ")
    except (UnicodeDecodeError, ValueError, IndexError) as exc:
        raise ValidationError("The Agent Gateway HTTP request line is invalid.") from exc
    if method != "POST" or version != "HTTP/1.1" or path not in {
        "/v1/enroll",
        "/v1/inventory",
        "/v1/software-inventory",
        "/v1/telemetry",
        "/v1/lifecycle-result",
        "/v1/lifecycle-artifact",
        "/v1/hyperv-action-result",
    }:
        raise ValidationError("The Agent Gateway HTTP route is invalid.")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ValidationError("The Agent Gateway HTTP header is invalid.")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or name in headers:
            raise ValidationError("The Agent Gateway HTTP header is duplicated.")
        headers[name] = value
    if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise ValidationError("The Agent Gateway HTTP content type is invalid.")
    if "transfer-encoding" in headers:
        raise ValidationError("Chunked Agent Gateway requests are not accepted.")
    try:
        content_length = int(headers["content-length"])
    except (KeyError, ValueError) as exc:
        raise ValidationError("The Agent Gateway HTTP content length is invalid.") from exc
    if not 1 <= content_length <= MAX_MESSAGE_BYTES:
        raise ValidationError("The Agent Gateway HTTP body size is invalid.")
    return path, headers, content_length


async def _http_reply(writer: asyncio.StreamWriter, status: int, document: dict) -> None:
    body = json.dumps(document, separators=(",", ":")).encode()
    reason = "OK" if status == 200 else "Bad Request"
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n".encode()
        + body
    )
    await writer.drain()


async def _http_binary_reply(
    writer: asyncio.StreamWriter,
    body: bytes,
    digest: str,
) -> None:
    writer.write(
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"X-Content-SHA256: {digest}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n".encode()
        + body
    )
    await writer.drain()


async def _handle_http_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    peer_certificate: bytes | None,
) -> None:
    from ipms.apps.agent_pki.services import (
        confirm_inventory,
        confirm_software_inventory,
        confirm_telemetry,
        enroll_agent,
        validate_peer_certificate,
    )
    from ipms.apps.agent_pki.lifecycle import (
        lifecycle_artifact,
        offer_lifecycle_job,
        record_lifecycle_result,
    )
    from ipms.apps.agent_pki.hyperv_actions import (
        offer_hyperv_action_job,
        record_hyperv_action_result,
    )

    header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
    path, _, content_length = _parse_http_request(header)
    body = await asyncio.wait_for(reader.readexactly(content_length), timeout=30)
    document = _bounded_json(body)
    if path == "/v1/enroll":
        if peer_certificate:
            raise ValidationError("Enrollment does not accept an existing client certificate.")
        if document.get("type") != "enroll":
            raise ValidationError("The enrollment message is invalid.")
        enrollment, certificate, chain = await _database_call_async(
            enroll_agent,
            raw_token=str(document.get("bootstrap_token", "")),
            csr_pem=str(document.get("csr_pem", "")),
        )
        await _http_reply(
            writer,
            200,
            {
                "type": "enrollment_complete",
                "device_uri": enrollment.device_uri,
                "certificate_pem": certificate,
                "certificate_chain_pem": chain,
            },
        )
        return
    if not peer_certificate:
        raise ValidationError("A client certificate is required.")
    enrollment = await _database_call_async(
        validate_peer_certificate,
        peer_certificate,
    )
    if document.get("device_uri") != enrollment.device_uri:
        raise ValidationError("The Agent message identity is invalid.")
    if path == "/v1/lifecycle-artifact":
        if document.get("type") != "lifecycle_artifact":
            raise ValidationError("The Agent lifecycle artifact request is invalid.")
        binary, digest = await _database_call_async(
            lifecycle_artifact,
            enrollment,
            job_id=str(document.get("job_id", "")),
        )
        await _http_binary_reply(writer, binary, digest)
        return
    if path == "/v1/lifecycle-result":
        if document.get("type") != "lifecycle_result":
            raise ValidationError("The Agent lifecycle result is invalid.")
        await _database_call_async(
            record_lifecycle_result,
            enrollment,
            job_id=str(document.get("job_id", "")),
            result=str(document.get("result", "")),
            result_code=str(document.get("result_code", "")),
        )
        await _http_reply(
            writer,
            200,
            {"type": "accepted", "correlation_id": document.get("correlation_id")},
        )
        return
    if path == "/v1/hyperv-action-result":
        if document.get("type") != "hyperv_action_result":
            raise ValidationError("The Hyper-V virtual machine action result is invalid.")
        await _database_call_async(
            record_hyperv_action_result,
            enrollment,
            job_id=str(document.get("job_id", "")),
            result=str(document.get("result", "")),
            result_code=str(document.get("result_code", "")),
        )
        await _http_reply(
            writer,
            200,
            {"type": "accepted", "correlation_id": document.get("correlation_id")},
        )
        return
    if path == "/v1/inventory" and document.get("type") == "inventory":
        await _database_call_async(
            confirm_inventory,
            enrollment,
            inventory=document.get("inventory"),
            agent_version=str(document.get("agent_version", "")),
        )
    elif (
        path == "/v1/software-inventory"
        and document.get("type") == "software_inventory"
    ):
        await _database_call_async(
            confirm_software_inventory,
            enrollment,
            document=document.get("software_inventory"),
            agent_version=str(document.get("agent_version", "")),
        )
    elif path == "/v1/telemetry" and document.get("type") == "telemetry":
        await _database_call_async(
            confirm_telemetry,
            enrollment,
            telemetry=document.get("telemetry"),
            agent_version=str(document.get("agent_version", "")),
        )
    else:
        raise ValidationError("The Agent HTTP message type is invalid.")
    response = {
        "type": "accepted",
        "correlation_id": document.get("correlation_id"),
    }
    assignment = await _database_call_async(offer_lifecycle_job, enrollment)
    if assignment:
        response["lifecycle"] = assignment
    else:
        hyperv_action = await _database_call_async(offer_hyperv_action_job, enrollment)
        if hyperv_action:
            response["hyperv_action"] = hyperv_action
    await _http_reply(writer, 200, response)


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    from ipms.apps.agent_pki.services import (
        confirm_inventory,
        confirm_software_inventory,
        confirm_telemetry,
        enroll_agent,
        renew_agent_certificate,
        validate_peer_certificate,
    )

    peer = writer.get_extra_info("peername")
    ssl_object = writer.get_extra_info("ssl_object")
    enrollment = None
    try:
        if ssl_object is None:
            raise ValidationError("The Agent Gateway ALPN is invalid.")
        protocol = _connection_protocol(ssl_object.selected_alpn_protocol())
        peer_certificate = ssl_object.getpeercert(binary_form=True)
        if protocol == "http":
            await _handle_http_connection(reader, writer, peer_certificate)
            return
        line = await asyncio.wait_for(reader.readline(), timeout=15)
        document = _bounded_json(line)
        if not peer_certificate:
            if document["type"] != "enroll":
                raise ValidationError("A client certificate is required.")
            enrollment, certificate, chain = await _database_call_async(
                enroll_agent,
                raw_token=str(document.get("bootstrap_token", "")),
                csr_pem=str(document.get("csr_pem", "")),
            )
            await _reply(
                writer,
                {
                    "type": "enrollment_complete",
                    "device_uri": enrollment.device_uri,
                    "certificate_pem": certificate,
                    "certificate_chain_pem": chain,
                },
            )
            return
        enrollment = await _database_call_async(
            validate_peer_certificate,
            peer_certificate,
        )
        while True:
            if document["type"] not in ALLOWED_AGENT_MESSAGES:
                raise ValidationError("The Agent message type is not allowed.")
            if document.get("device_uri") != enrollment.device_uri:
                raise ValidationError("The message device URI does not match the certificate.")
            if document["type"] == "inventory":
                await _database_call_async(
                    confirm_inventory,
                    enrollment,
                    inventory=document.get("inventory"),
                    agent_version=str(document.get("agent_version", "")),
                )
            if document["type"] == "software_inventory":
                await _database_call_async(
                    confirm_software_inventory,
                    enrollment,
                    document=document.get("software_inventory"),
                    agent_version=str(document.get("agent_version", "")),
                )
            if document["type"] == "telemetry":
                await _database_call_async(
                    confirm_telemetry,
                    enrollment,
                    telemetry=document.get("telemetry"),
                    agent_version=str(document.get("agent_version", "")),
                )
            if document["type"] == "certificate_renewal":
                certificate, chain = await _database_call_async(
                    renew_agent_certificate,
                    enrollment=enrollment,
                    csr_pem=str(document.get("csr_pem", "")),
                )
                await _reply(
                    writer,
                    {
                        "type": "certificate_renewed",
                        "certificate_pem": certificate,
                        "certificate_chain_pem": chain,
                    },
                )
                return
            await _reply(
                writer,
                {"type": "accepted", "correlation_id": document.get("correlation_id")},
            )
            line = await asyncio.wait_for(reader.readline(), timeout=120)
            if not line:
                return
            document = _bounded_json(line)
    except (ValidationError, asyncio.TimeoutError) as exc:
        reason = (
            "; ".join(exc.messages)
            if isinstance(exc, ValidationError)
            else "Gateway request timeout"
        )
        logger.warning("Agent Gateway request rejected: %s", reason, extra={"peer": str(peer)})
        if ssl_object is not None and ssl_object.selected_alpn_protocol() in {
            "http/1.1",
            None,
        }:
            await _http_reply(
                writer,
                400,
                {"type": "rejected", "code": "identity_or_policy_rejected"},
            )
        else:
            await _reply(writer, {"type": "rejected", "code": "identity_or_policy_rejected"})
    except Exception:
        logger.exception("Agent Gateway connection failed", extra={"peer": str(peer)})
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError, ssl.SSLError):
            await writer.wait_closed()


async def run() -> None:
    runtime_directory = Path(os.environ["IPMS_AGENT_GATEWAY_RUNTIME_DIRECTORY"])
    host = os.environ.get("IPMS_AGENT_GATEWAY_BIND", "0.0.0.0")
    port = int(os.environ.get("IPMS_AGENT_GATEWAY_PORT", "9419"))
    server = await asyncio.start_server(
        handle_connection,
        host=host,
        port=port,
        ssl=build_tls_context(runtime_directory),
        limit=MAX_MESSAGE_BYTES + 1,
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ipms_control_plane.settings.gateway")
    django.setup()
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())


if __name__ == "__main__":
    main()
