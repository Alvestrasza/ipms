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


MAX_MESSAGE_BYTES = 65_536
ALLOWED_AGENT_MESSAGES = {
    "hello",
    "inventory",
    "acknowledgement",
    "health",
    "certificate_renewal",
}
logger = logging.getLogger("ipms.agent_gateway")


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
    context.set_alpn_protocols(["ipms-agent/1"])
    return context


async def _reply(writer: asyncio.StreamWriter, document: dict) -> None:
    writer.write(json.dumps(document, separators=(",", ":")).encode() + b"\n")
    await writer.drain()


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    from ipms.apps.agent_pki.services import (
        confirm_inventory,
        enroll_agent,
        renew_agent_certificate,
        validate_peer_certificate,
    )

    peer = writer.get_extra_info("peername")
    ssl_object = writer.get_extra_info("ssl_object")
    enrollment = None
    try:
        if ssl_object is None or ssl_object.selected_alpn_protocol() != "ipms-agent/1":
            raise ValidationError("The Agent Gateway ALPN is invalid.")
        peer_certificate = ssl_object.getpeercert(binary_form=True)
        line = await asyncio.wait_for(reader.readline(), timeout=15)
        document = _bounded_json(line)
        if not peer_certificate:
            if document["type"] != "enroll":
                raise ValidationError("A client certificate is required.")
            enrollment, certificate, chain = await sync_to_async(enroll_agent)(
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
        enrollment = await sync_to_async(validate_peer_certificate)(peer_certificate)
        while True:
            if document["type"] not in ALLOWED_AGENT_MESSAGES:
                raise ValidationError("The Agent message type is not allowed.")
            if document.get("device_uri") != enrollment.device_uri:
                raise ValidationError("The message device URI does not match the certificate.")
            if document["type"] == "inventory":
                await sync_to_async(confirm_inventory)(enrollment)
            if document["type"] == "certificate_renewal":
                certificate, chain = await sync_to_async(renew_agent_certificate)(
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
        logger.warning(
            "Agent Gateway request rejected",
            extra={"peer": str(peer), "reason": exc.__class__.__name__},
        )
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
