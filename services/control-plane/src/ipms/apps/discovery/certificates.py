from __future__ import annotations

import hashlib
import ipaddress
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


def _private_addresses(hostname: str, port: int) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        addresses = tuple(
            {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(
                    hostname,
                    port,
                    type=socket.SOCK_STREAM,
                )
            }
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


def probe_bmc_certificate(base_url: str, *, timeout: float = 10) -> CertificateObservation:
    parsed = urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise CertificateProbeError("invalid_endpoint")
    port = parsed.port or 443
    addresses = _private_addresses(parsed.hostname, port)
    address = addresses[0]

    trusted_by_system = True
    try:
        _peer_certificate(
            hostname=parsed.hostname,
            port=port,
            address=address,
            context=ssl.create_default_context(),
            timeout=timeout,
        )
    except ssl.SSLCertVerificationError:
        trusted_by_system = False
    except (TimeoutError, socket.timeout) as exc:
        raise CertificateProbeError("connection_timeout") from exc
    except (ssl.SSLError, OSError) as exc:
        raise CertificateProbeError("connection_failed") from exc

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        der = _peer_certificate(
            hostname=parsed.hostname,
            port=port,
            address=address,
            context=context,
            timeout=timeout,
        )
    except (TimeoutError, socket.timeout) as exc:
        raise CertificateProbeError("connection_timeout") from exc
    except (ssl.SSLError, OSError) as exc:
        raise CertificateProbeError("connection_failed") from exc

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
