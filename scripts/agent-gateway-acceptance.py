#!/usr/bin/env python3
"""Perform a synthetic pinned enrollment and first mTLS inventory exchange."""

import argparse
import hashlib
import json
import socket
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


MAX_MESSAGE_BYTES = 65_536


def receive_document(stream) -> dict:
    line = stream.makefile("rb", buffering=0).readline(MAX_MESSAGE_BYTES + 1)
    if not line or len(line) > MAX_MESSAGE_BYTES:
        raise RuntimeError("The Gateway response size is invalid.")
    document = json.loads(line)
    if not isinstance(document, dict):
        raise RuntimeError("The Gateway response envelope is invalid.")
    return document


def verify_pin(stream, expected_fingerprint: str) -> None:
    certificate = stream.getpeercert(binary_form=True)
    actual = hashlib.sha256(certificate).hexdigest()
    if actual.casefold() != expected_fingerprint.casefold():
        raise RuntimeError("The Gateway certificate fingerprint does not match the pin.")
    if stream.selected_alpn_protocol() != "ipms-agent/1":
        raise RuntimeError("The Gateway did not negotiate the IPMS Agent protocol.")


def connect(context: ssl.SSLContext, host: str, port: int):
    connection = socket.create_connection((host, port), timeout=15)
    try:
        return context.wrap_socket(connection, server_hostname=host)
    except Exception:
        connection.close()
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bootstrap_document", type=Path)
    args = parser.parse_args()
    bootstrap = json.loads(args.bootstrap_document.read_text(encoding="utf-8"))
    host = bootstrap["gateway_dns_name"]
    port = int(bootstrap["gateway_port"])
    expected_fingerprint = bootstrap["gateway_fingerprint_sha256"]
    device_uri = bootstrap["device_uri"]

    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(private_key, hashes.SHA256())
    )
    enrollment_request = {
        "type": "enroll",
        "bootstrap_token": bootstrap["bootstrap_token"],
        "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }
    bootstrap_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    bootstrap_context.minimum_version = ssl.TLSVersion.TLSv1_3
    bootstrap_context.check_hostname = False
    bootstrap_context.verify_mode = ssl.CERT_NONE
    bootstrap_context.set_alpn_protocols(["ipms-agent/1"])
    with connect(bootstrap_context, host, port) as stream:
        verify_pin(stream, expected_fingerprint)
        stream.sendall(json.dumps(enrollment_request, separators=(",", ":")).encode() + b"\n")
        enrollment_response = receive_document(stream)
    if enrollment_response.get("type") != "enrollment_complete":
        raise RuntimeError("The Gateway rejected the synthetic enrollment.")
    if enrollment_response.get("device_uri") != device_uri:
        raise RuntimeError("The issued Agent identity does not match the enrollment.")

    certificate_pem = enrollment_response["certificate_pem"]
    chain_pem = enrollment_response["certificate_chain_pem"]
    certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
    if (
        certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        != private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ):
        raise RuntimeError("The issued certificate does not match the local device key.")

    with tempfile.TemporaryDirectory(prefix="ipms-agent-acceptance-") as directory:
        temporary = Path(directory)
        certificate_path = temporary / "agent-chain.pem"
        key_path = temporary / "agent.key"
        certificate_path.write_text(certificate_pem + chain_pem, encoding="ascii")
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        authenticated_context = ssl.create_default_context(cadata=chain_pem)
        authenticated_context.minimum_version = ssl.TLSVersion.TLSv1_3
        authenticated_context.set_alpn_protocols(["ipms-agent/1"])
        authenticated_context.load_cert_chain(certificate_path, key_path)
        with connect(authenticated_context, host, port) as stream:
            verify_pin(stream, expected_fingerprint)
            inventory = {
                "type": "inventory",
                "device_uri": device_uri,
                "correlation_id": "synthetic-acceptance",
                "inventory": {},
            }
            stream.sendall(json.dumps(inventory, separators=(",", ":")).encode() + b"\n")
            inventory_response = receive_document(stream)
    if inventory_response.get("type") != "accepted":
        raise RuntimeError("The Gateway rejected the first synthetic inventory.")
    print(json.dumps({"device_uri": device_uri, "enrollment": "accepted", "inventory": "accepted"}))


if __name__ == "__main__":
    main()
