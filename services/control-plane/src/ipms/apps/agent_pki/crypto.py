import base64
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils import timezone


DEVICE_URI_PATTERN = re.compile(
    r"^urn:ipms:agent:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


@dataclass(frozen=True)
class CertificateMaterial:
    certificate_pem: str
    chain_pem: str
    private_key_pem: bytes
    fingerprint_sha256: str
    serial_number: str
    not_before: object
    not_after: object


def _master_key() -> bytes:
    try:
        key = base64.b64decode(settings.AGENT_PKI_MASTER_KEY, validate=True)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured(
            "IPMS_AGENT_PKI_MASTER_KEY must be base64-encoded."
        ) from exc
    if len(key) != 32:
        raise ImproperlyConfigured(
            "IPMS_AGENT_PKI_MASTER_KEY must decode to exactly 32 bytes."
        )
    return key


def encrypt_private_key(private_key_pem: bytes, *, associated_data: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_master_key()).encrypt(nonce, private_key_pem, associated_data)
    return nonce, ciphertext


def decrypt_private_key(nonce: bytes, ciphertext: bytes, *, associated_data: bytes):
    plaintext = AESGCM(_master_key()).decrypt(nonce, ciphertext, associated_data)
    return serialization.load_pem_private_key(plaintext, password=None)


def issuer_associated_data(tenant_id, issuer_id) -> bytes:
    return f"ipms:agent-pki:v1:{tenant_id}:issuer:{issuer_id}".encode()


def gateway_associated_data(tenant_id, identity_id) -> bytes:
    return f"ipms:agent-pki:v1:{tenant_id}:gateway:{identity_id}".encode()


def certificate_fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def _private_key_pem(private_key) -> bytes:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Alvestrasza Corporation"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def create_managed_hierarchy(gateway_dns_name: str, recovery_passphrase: bytes):
    if not gateway_dns_name or urlsplit(f"//{gateway_dns_name}").hostname != gateway_dns_name:
        raise ValidationError("The Agent Gateway DNS name is invalid.")
    if len(recovery_passphrase) < 20:
        raise ValidationError("The Root recovery passphrase must contain at least 20 bytes.")

    now = timezone.now()
    root_key = ec.generate_private_key(ec.SECP384R1())
    root_subject = _name("IPMS Agent Root CA")
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), False)
        .sign(root_key, hashes.SHA384())
    )

    issuer_key = ec.generate_private_key(ec.SECP384R1())
    issuer_subject = _name("IPMS Agent Issuing CA")
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_subject)
        .issuer_name(root_cert.subject)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1095))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), False)
        .sign(root_key, hashes.SHA384())
    )

    gateway_key = ec.generate_private_key(ec.SECP256R1())
    gateway_cert = _issue_leaf(
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
        public_key=gateway_key.public_key(),
        common_name="IPMS Agent Gateway",
        san=x509.SubjectAlternativeName([x509.DNSName(gateway_dns_name)]),
        eku=ExtendedKeyUsageOID.SERVER_AUTH,
        lifetime=timedelta(days=90),
    )
    root_recovery_pem = root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(recovery_passphrase),
    ) + root_cert.public_bytes(serialization.Encoding.PEM)
    return root_cert, issuer_key, issuer_cert, gateway_key, gateway_cert, root_recovery_pem


def load_managed_root_recovery(recovery_pem: bytes, recovery_passphrase: bytes):
    if len(recovery_pem) > 65_536:
        raise ValidationError("The Root recovery bundle exceeds the maximum size.")
    marker = b"-----BEGIN CERTIFICATE-----"
    certificate_offset = recovery_pem.find(marker)
    if certificate_offset < 0:
        raise ValidationError("The Root recovery bundle is incomplete.")
    try:
        root_key = serialization.load_pem_private_key(
            recovery_pem[:certificate_offset],
            password=recovery_passphrase,
        )
        root_cert = x509.load_pem_x509_certificate(recovery_pem[certificate_offset:])
    except (TypeError, ValueError) as exc:
        raise ValidationError("The Root recovery bundle or passphrase is invalid.") from exc
    if not isinstance(root_key, ec.EllipticCurvePrivateKey):
        raise ValidationError("The managed Root private-key algorithm is invalid.")
    if (
        root_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        != root_cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ):
        raise ValidationError("The Root recovery key and certificate do not match.")
    return root_key, root_cert


def issue_managed_issuer(root_key, root_cert):
    now = timezone.now()
    issuer_key = ec.generate_private_key(ec.SECP384R1())
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("IPMS Agent Issuing CA"))
        .issuer_name(root_cert.subject)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1095))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            False,
        )
        .sign(root_key, hashes.SHA384())
    )
    return issuer_key, issuer_cert


def issue_gateway_identity(issuer_key, issuer_cert, gateway_dns_name: str):
    gateway_key = ec.generate_private_key(ec.SECP256R1())
    gateway_cert = _issue_leaf(
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
        public_key=gateway_key.public_key(),
        common_name="IPMS Agent Gateway",
        san=x509.SubjectAlternativeName([x509.DNSName(gateway_dns_name)]),
        eku=ExtendedKeyUsageOID.SERVER_AUTH,
        lifetime=timedelta(days=90),
    )
    return gateway_key, gateway_cert


def _issue_leaf(*, issuer_key, issuer_cert, public_key, common_name, san, eku, lifetime):
    now = timezone.now()
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + lifetime)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
        .add_extension(san, critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
        .sign(issuer_key, hashes.SHA384())
    )


def validate_agent_csr(csr_pem: str):
    csr_pem = csr_pem.replace(
        "-----BEGIN NEW CERTIFICATE REQUEST-----",
        "-----BEGIN CERTIFICATE REQUEST-----",
    ).replace(
        "-----END NEW CERTIFICATE REQUEST-----",
        "-----END CERTIFICATE REQUEST-----",
    )
    if len(csr_pem.encode("utf-8")) > 16_384:
        raise ValidationError("The CSR exceeds the maximum size.")
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValidationError("The CSR is not valid PEM.") from exc
    if not csr.is_signature_valid:
        raise ValidationError("The CSR signature is invalid.")
    public_key = csr.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 3072:
            raise ValidationError("RSA Agent keys must be at least 3072 bits.")
        algorithm = f"rsa-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1"}:
            raise ValidationError("The Agent EC curve is not allowed.")
        algorithm = public_key.curve.name
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        algorithm = "ed25519"
    else:
        raise ValidationError("The Agent public-key algorithm is not allowed.")
    return csr, algorithm


def issue_agent_certificate(*, issuer_key, issuer_cert, csr, device_uri: str, lifetime_days: int):
    if not DEVICE_URI_PATTERN.fullmatch(device_uri):
        raise ValidationError("The Agent device URI is invalid.")
    return _issue_leaf(
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
        public_key=csr.public_key(),
        common_name="IPMS Agent",
        san=x509.SubjectAlternativeName([x509.UniformResourceIdentifier(device_uri)]),
        eku=ExtendedKeyUsageOID.CLIENT_AUTH,
        lifetime=timedelta(days=lifetime_days),
    )


def atomic_write_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
