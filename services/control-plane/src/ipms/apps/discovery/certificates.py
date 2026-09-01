from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import timezone
from urllib.parse import urlsplit

from cryptography import x509
from django.core import signing


CERTIFICATE_TRUST_SALT = "ipms.bmc-certificate-trust.v1"
CERTIFICATE_TRUST_MAX_AGE_SECONDS = 10 * 60


class CertificateProbeError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class CertificateObservation:
    fingerprint_sha256: str
    subject: str
    issuer: str
    serial_number: str
    valid_from: str
    valid_until: str
    dns_names: tuple[str, ...]
    trusted_by_system: bool

    def public_document(self) -> dict[str, str | bool | tuple[str, ...]]:
        return asdict(self)


@dataclass(frozen=True)
class WindowsHttpObservation:
    reachable: bool

    def public_document(self) -> dict[str, bool]:
        return asdict(self)


def _private_addresses(hostname: str, port: int) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        addresses = tuple(
            dict.fromkeys(
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            )
        )
    except socket.gaierror as exc:
        raise CertificateProbeError("target_unresolved") from exc
    if not addresses:
        raise CertificateProbeError("target_unresolved")
    if any(
        not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        for address in addresses
    ):
        raise CertificateProbeError("target_not_private")
    return addresses


def _peer_certificate(
    *,
    hostname: str,
    port: int,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    context: ssl.SSLContext,
    timeout: float,
) -> bytes:
    with socket.create_connection((str(address), port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as secured:
            certificate = secured.getpeercert(binary_form=True)
    if not certificate:
        raise CertificateProbeError("certificate_unavailable")
    return certificate


def _peer_certificate_from_addresses(
    *,
    hostname: str,
    port: int,
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...],
    context: ssl.SSLContext,
    timeout: float,
) -> bytes:
    timed_out = False
    connection_failed = False
    for address in addresses:
        try:
            return _peer_certificate(
                hostname=hostname,
                port=port,
                address=address,
                context=context,
                timeout=timeout,
            )
        except ssl.SSLCertVerificationError:
            raise
        except (TimeoutError, socket.timeout):
            timed_out = True
        except (ssl.SSLError, OSError):
            connection_failed = True
    if connection_failed:
        raise CertificateProbeError("connection_failed")
    if timed_out:
        raise CertificateProbeError("connection_timeout")
    raise CertificateProbeError("connection_failed")


def probe_bmc_certificate(base_url: str, *, timeout: float = 10) -> CertificateObservation:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise CertificateProbeError("invalid_endpoint")
    port = parsed.port or 443
    addresses = _private_addresses(parsed.hostname, port)

    trusted_by_system = True
    try:
        der = _peer_certificate_from_addresses(
            hostname=parsed.hostname,
            port=port,
            addresses=addresses,
            context=ssl.create_default_context(),
            timeout=timeout,
        )
    except ssl.SSLCertVerificationError:
        trusted_by_system = False
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        der = _peer_certificate_from_addresses(
            hostname=parsed.hostname,
            port=port,
            addresses=addresses,
            context=context,
            timeout=timeout,
        )

    certificate = x509.load_der_x509_certificate(der)
    try:
        dns_names = tuple(
            certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        )
    except x509.ExtensionNotFound:
        dns_names = ()
    return CertificateObservation(
        fingerprint_sha256=hashlib.sha256(der).hexdigest(),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=f"{certificate.serial_number:X}",
        valid_from=certificate.not_valid_before_utc.astimezone(timezone.utc).isoformat(),
        valid_until=certificate.not_valid_after_utc.astimezone(timezone.utc).isoformat(),
        dns_names=dns_names[:16],
        trusted_by_system=trusted_by_system,
    )


def probe_windows_http_endpoint(
    base_url: str,
    *,
    timeout: float = 10,
) -> WindowsHttpObservation:
    parsed = urlsplit(base_url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise CertificateProbeError("invalid_endpoint")
    port = parsed.port or 5985
    addresses = _private_addresses(parsed.hostname, port)
    path = parsed.path or "/wsman"
    timed_out = False
    connection_failed = False
    remote_management_unavailable = False
    for address in addresses:
        connection = http.client.HTTPConnection(str(address), port, timeout=timeout)
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": parsed.hostname,
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            response.read(4096)
        except (TimeoutError, socket.timeout):
            timed_out = True
            continue
        except (OSError, http.client.HTTPException):
            connection_failed = True
            continue
        finally:
            connection.close()
        if response.status in {401, 405}:
            return WindowsHttpObservation(reachable=True)
        remote_management_unavailable = True
    if remote_management_unavailable:
        raise CertificateProbeError("remote_management_unavailable")
    if connection_failed:
        raise CertificateProbeError("connection_failed")
    if timed_out:
        raise CertificateProbeError("connection_timeout")
    raise CertificateProbeError("connection_failed")


def request_bmc_certificate_probe(
    base_url: str,
    *,
    timeout: float,
    port: int,
    token: str,
) -> CertificateObservation:
    """Request a probe from the localhost-only, network-isolated helper."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout + 5)
    try:
        connection.request(
            "POST",
            "/probe",
            body=json.dumps({"base_url": base_url, "timeout": timeout}),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        body = response.read(32 * 1024 + 1)
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise CertificateProbeError("certificate_probe_unavailable") from exc
    finally:
        connection.close()
    if len(body) > 32 * 1024:
        raise CertificateProbeError("certificate_probe_invalid_response")
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificateProbeError("certificate_probe_invalid_response") from exc
    if response.status != 200:
        code = document.get("error") if isinstance(document, dict) else None
        safe_code = (
            code
            if isinstance(code, str) and len(code) <= 64
            else "certificate_probe_failed"
        )
        raise CertificateProbeError(safe_code)
    try:
        return CertificateObservation(
            fingerprint_sha256=str(document["fingerprint_sha256"]),
            subject=str(document["subject"]),
            issuer=str(document["issuer"]),
            serial_number=str(document["serial_number"]),
            valid_from=str(document["valid_from"]),
            valid_until=str(document["valid_until"]),
            dns_names=tuple(str(value) for value in document.get("dns_names", ()))[:16],
            trusted_by_system=bool(document["trusted_by_system"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CertificateProbeError("certificate_probe_invalid_response") from exc


def request_windows_http_probe(
    base_url: str,
    *,
    timeout: float,
    port: int,
    token: str,
) -> WindowsHttpObservation:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout + 5)
    try:
        connection.request(
            "POST",
            "/probe/windows-http",
            body=json.dumps({"base_url": base_url, "timeout": timeout}),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        body = response.read(4096 + 1)
    except (OSError, TimeoutError, http.client.HTTPException) as exc:
        raise CertificateProbeError("certificate_probe_unavailable") from exc
    finally:
        connection.close()
    if len(body) > 4096:
        raise CertificateProbeError("certificate_probe_invalid_response")
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CertificateProbeError("certificate_probe_invalid_response") from exc
    if response.status != 200:
        code = document.get("error") if isinstance(document, dict) else None
        safe_code = (
            code
            if isinstance(code, str) and len(code) <= 64
            else "certificate_probe_failed"
        )
        raise CertificateProbeError(safe_code)
    if not isinstance(document, dict) or document.get("reachable") is not True:
        raise CertificateProbeError("certificate_probe_invalid_response")
    return WindowsHttpObservation(reachable=True)


def create_certificate_trust_token(
    *,
    tenant_id: str,
    base_url: str,
    observation: CertificateObservation,
) -> str:
    return signing.dumps(
        {
            "tenant_id": tenant_id,
            "base_url": base_url,
            "fingerprint_sha256": observation.fingerprint_sha256,
            "trusted_by_system": observation.trusted_by_system,
        },
        salt=CERTIFICATE_TRUST_SALT,
        compress=True,
    )


def load_certificate_trust_token(token: str) -> dict[str, str | bool]:
    try:
        document = signing.loads(
            token,
            salt=CERTIFICATE_TRUST_SALT,
            max_age=CERTIFICATE_TRUST_MAX_AGE_SECONDS,
        )
    except signing.SignatureExpired as exc:
        raise CertificateProbeError("certificate_trust_expired") from exc
    except signing.BadSignature as exc:
        raise CertificateProbeError("certificate_trust_invalid") from exc
    if not isinstance(document, dict):
        raise CertificateProbeError("certificate_trust_invalid")
    return document
