import hashlib
import secrets
import uuid
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent

from .crypto import (
    _issue_leaf,
    atomic_write_private,
    certificate_fingerprint,
    create_managed_hierarchy,
    decrypt_private_key,
    encrypt_private_key,
    gateway_associated_data,
    issue_gateway_identity,
    issue_agent_certificate,
    issue_managed_issuer,
    issuer_associated_data,
    load_managed_root_recovery,
    validate_agent_csr,
)
from .models import (
    AgentEnrollment,
    AgentEnrollmentToken,
    AgentGatewayIdentity,
    AgentIssuer,
    AgentPkiPolicy,
    AgentRevocation,
)


def _pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _load_private_key(private_key_pem: bytes, password: bytes | None):
    try:
        return serialization.load_pem_private_key(private_key_pem, password=password)
    except (TypeError, ValueError) as exc:
        raise ValidationError("The imported private key or passphrase is invalid.") from exc


def _public_key_bytes(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ) if hasattr(key, "public_key") else key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _validate_ca_certificate(certificate: x509.Certificate, *, require_path_zero: bool) -> None:
    try:
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValidationError("The imported CA certificate profile is incomplete.") from exc
    if not basic.ca or (require_path_zero and basic.path_length != 0):
        raise ValidationError("The imported certificate is not a dedicated issuing CA.")
    if not usage.key_cert_sign or not usage.crl_sign:
        raise ValidationError("The imported CA key usage is invalid.")
    now = timezone.now()
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValidationError("The imported CA certificate is not currently valid.")


def _validate_gateway_certificate(certificate: x509.Certificate, key, dns_name: str) -> None:
    if _public_key_bytes(key) != _public_key_bytes(certificate.public_key()):
        raise ValidationError("The Gateway certificate and private key do not match.")
    try:
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValidationError("The Gateway certificate profile is incomplete.") from exc
    if basic.ca or not usage.digital_signature or usage.key_cert_sign:
        raise ValidationError("The Gateway certificate key usage is invalid.")
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku or len(eku) != 1:
        raise ValidationError("The Gateway certificate EKU is invalid.")
    if dns_name not in san.get_values_for_type(x509.DNSName):
        raise ValidationError("The Gateway certificate DNS identity is invalid.")
    now = timezone.now()
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValidationError("The Gateway certificate is not currently valid.")


@transaction.atomic
def configure_external_issuing_pki(
    *,
    tenant,
    gateway_dns_name: str,
    issuer_certificate_pem: bytes,
    issuer_private_key_pem: bytes,
    issuer_private_key_password: bytes | None,
    chain_pem: bytes,
    actor: str,
):
    if AgentPkiPolicy.objects.filter(tenant=tenant).exists():
        raise ValidationError("Agent PKI is already configured for this tenant.")
    try:
        issuer_cert = x509.load_pem_x509_certificate(issuer_certificate_pem)
        chain_cert = x509.load_pem_x509_certificate(chain_pem)
    except ValueError as exc:
        raise ValidationError("The external issuing CA certificate chain is invalid.") from exc
    issuer_key = _load_private_key(issuer_private_key_pem, issuer_private_key_password)
    _validate_ca_certificate(issuer_cert, require_path_zero=True)
    _validate_ca_certificate(chain_cert, require_path_zero=False)
    if _public_key_bytes(issuer_key) != _public_key_bytes(issuer_cert.public_key()):
        raise ValidationError("The external issuing CA certificate and key do not match.")
    try:
        issuer_cert.verify_directly_issued_by(chain_cert)
    except ValueError as exc:
        raise ValidationError("The external issuing CA chain is not valid.") from exc
    policy = AgentPkiPolicy.objects.create(
        tenant=tenant,
        trust_mode=AgentPkiPolicy.TrustMode.EXTERNAL_ISSUING_CA,
        gateway_dns_name=gateway_dns_name,
        root_certificate_pem=_pem(chain_cert),
        root_fingerprint_sha256=certificate_fingerprint(chain_cert),
    )
    issuer = AgentIssuer(id=uuid.uuid4(), tenant=tenant, policy=policy, external=True)
    issuer.private_key_nonce, issuer.private_key_ciphertext = encrypt_private_key(
        issuer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        associated_data=issuer_associated_data(tenant.id, issuer.id),
    )
    issuer.certificate_pem = _pem(issuer_cert)
    issuer.chain_pem = _pem(chain_cert)
    issuer.fingerprint_sha256 = certificate_fingerprint(issuer_cert)
    issuer.serial_number = format(issuer_cert.serial_number, "x")
    issuer.not_before = issuer_cert.not_valid_before_utc
    issuer.not_after = issuer_cert.not_valid_after_utc
    issuer.save()
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
    _store_gateway_identity(
        tenant=tenant,
        policy=policy,
        issuer=issuer,
        certificate=gateway_cert,
        private_key=gateway_key,
        chain_pem=issuer.certificate_pem + issuer.chain_pem,
    )
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent_pki.external_issuer.import",
        object_type="agent_pki_policy",
        object_id=policy.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"trust_mode": policy.trust_mode, "gateway_dns_name": gateway_dns_name},
    )
    return policy


def _store_gateway_identity(*, tenant, policy, issuer, certificate, private_key, chain_pem):
    identity = AgentGatewayIdentity(id=uuid.uuid4(), tenant=tenant, policy=policy, issuer=issuer)
    identity.private_key_nonce, identity.private_key_ciphertext = encrypt_private_key(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        associated_data=gateway_associated_data(tenant.id, identity.id),
    )
    identity.certificate_pem = _pem(certificate)
    identity.chain_pem = chain_pem
    identity.fingerprint_sha256 = certificate_fingerprint(certificate)
    identity.not_before = certificate.not_valid_before_utc
    identity.not_after = certificate.not_valid_after_utc
    identity.save()
    return identity


@transaction.atomic
def configure_external_certificate_pki(
    *,
    tenant,
    gateway_dns_name: str,
    gateway_certificate_pem: bytes,
    gateway_private_key_pem: bytes,
    gateway_private_key_password: bytes | None,
    gateway_chain_pem: bytes,
    agent_issuer_certificate_pem: bytes,
    actor: str,
):
    if AgentPkiPolicy.objects.filter(tenant=tenant).exists():
        raise ValidationError("Agent PKI is already configured for this tenant.")
    try:
        gateway_cert = x509.load_pem_x509_certificate(gateway_certificate_pem)
        gateway_chain = x509.load_pem_x509_certificates(gateway_chain_pem)
        agent_issuer_cert = x509.load_pem_x509_certificate(agent_issuer_certificate_pem)
    except ValueError as exc:
        raise ValidationError("The external certificate material is invalid.") from exc
    gateway_key = _load_private_key(gateway_private_key_pem, gateway_private_key_password)
    _validate_gateway_certificate(gateway_cert, gateway_key, gateway_dns_name)
    if not gateway_chain:
        raise ValidationError("The Gateway certificate chain is empty.")
    _validate_ca_certificate(gateway_chain[0], require_path_zero=False)
    try:
        gateway_cert.verify_directly_issued_by(gateway_chain[0])
    except ValueError as exc:
        raise ValidationError("The Gateway certificate chain is not valid.") from exc
    _validate_ca_certificate(agent_issuer_cert, require_path_zero=False)
    policy = AgentPkiPolicy.objects.create(
        tenant=tenant,
        trust_mode=AgentPkiPolicy.TrustMode.EXTERNAL_CERTIFICATES,
        gateway_dns_name=gateway_dns_name,
        root_certificate_pem=_pem(agent_issuer_cert),
        root_fingerprint_sha256=certificate_fingerprint(agent_issuer_cert),
    )
    issuer = AgentIssuer.objects.create(
        tenant=tenant,
        policy=policy,
        status=AgentIssuer.Status.ACTIVE,
        certificate_pem=_pem(agent_issuer_cert),
        chain_pem="",
        fingerprint_sha256=certificate_fingerprint(agent_issuer_cert),
        serial_number=format(agent_issuer_cert.serial_number, "x"),
        external=True,
        not_before=agent_issuer_cert.not_valid_before_utc,
        not_after=agent_issuer_cert.not_valid_after_utc,
    )
    _store_gateway_identity(
        tenant=tenant,
        policy=policy,
        issuer=None,
        certificate=gateway_cert,
        private_key=gateway_key,
        chain_pem=gateway_chain_pem.decode("ascii"),
    )
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent_pki.external_certificates.import",
        object_type="agent_pki_policy",
        object_id=policy.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"trust_mode": policy.trust_mode, "gateway_dns_name": gateway_dns_name},
    )
    return policy, issuer


@transaction.atomic
def import_external_agent_certificate(
    *, tenant, display_name: str, certificate_pem: bytes, actor: str
):
    policy = AgentPkiPolicy.objects.get(
        tenant=tenant,
        trust_mode=AgentPkiPolicy.TrustMode.EXTERNAL_CERTIFICATES,
    )
    issuer = AgentIssuer.objects.get(tenant=tenant, status=AgentIssuer.Status.ACTIVE)
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem)
        issuer_certificate = x509.load_pem_x509_certificate(
            issuer.certificate_pem.encode("ascii")
        )
        certificate.verify_directly_issued_by(issuer_certificate)
        basic = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (ValueError, x509.ExtensionNotFound) as exc:
        raise ValidationError("The external Agent certificate is invalid.") from exc
    if basic.ca or not usage.digital_signature or usage.key_cert_sign:
        raise ValidationError("The external Agent certificate key usage is invalid.")
    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku or len(eku) != 1:
        raise ValidationError("The external Agent certificate EKU is invalid.")
    device_uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(device_uris) != 1:
        raise ValidationError("The external Agent device URI is invalid.")
    from .crypto import DEVICE_URI_PATTERN

    if not DEVICE_URI_PATTERN.fullmatch(device_uris[0]):
        raise ValidationError("The external Agent device URI is invalid.")
    now = timezone.now()
    if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
        raise ValidationError("The external Agent certificate is not currently valid.")
    enrollment = AgentEnrollment.objects.create(
        tenant=tenant,
        device_id=uuid.UUID(device_uris[0].removeprefix("urn:ipms:agent:")),
        device_uri=device_uris[0],
        display_name=display_name,
        status=AgentEnrollment.Status.ACTIVE,
        issuer=issuer,
        certificate_pem=_pem(certificate),
        certificate_fingerprint_sha256=certificate_fingerprint(certificate),
        certificate_serial_number=format(certificate.serial_number, "x"),
        certificate_not_before=certificate.not_valid_before_utc,
        certificate_not_after=certificate.not_valid_after_utc,
        key_algorithm=certificate.public_key_algorithm_oid.dotted_string,
    )
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent.external_certificate.import",
        object_type="agent_enrollment",
        object_id=enrollment.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"trust_mode": policy.trust_mode},
    )
    return enrollment


def _audit(*, tenant, actor: str, action: str, object_type: str, object_id, outcome, details=None):
    AuditEvent.objects.create(
        tenant=tenant,
        actor=actor,
        action=action,
        object_type=object_type,
        object_id=str(object_id),
        outcome=outcome,
        details=details or {},
    )


@transaction.atomic
def bootstrap_managed_pki(*, tenant, gateway_dns_name: str, recovery_output: Path, recovery_passphrase: bytes, actor: str):
    if AgentPkiPolicy.objects.filter(tenant=tenant).exists():
        raise ValidationError("Agent PKI is already configured for this tenant.")
    root_cert, issuer_key, issuer_cert, gateway_key, gateway_cert, recovery = (
        create_managed_hierarchy(gateway_dns_name, recovery_passphrase)
    )
    atomic_write_private(recovery_output, recovery)
    policy = AgentPkiPolicy.objects.create(
        tenant=tenant,
        trust_mode=AgentPkiPolicy.TrustMode.IPMS_MANAGED,
        gateway_dns_name=gateway_dns_name,
        root_certificate_pem=_pem(root_cert),
        root_fingerprint_sha256=certificate_fingerprint(root_cert),
        root_recovery_exported_at=timezone.now(),
    )
    issuer = AgentIssuer(id=uuid.uuid4(), tenant=tenant, policy=policy)
    issuer.private_key_nonce, issuer.private_key_ciphertext = encrypt_private_key(
        issuer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        associated_data=issuer_associated_data(tenant.id, issuer.id),
    )
    issuer.certificate_pem = _pem(issuer_cert)
    issuer.chain_pem = _pem(root_cert)
    issuer.fingerprint_sha256 = certificate_fingerprint(issuer_cert)
    issuer.serial_number = format(issuer_cert.serial_number, "x")
    issuer.not_before = issuer_cert.not_valid_before_utc
    issuer.not_after = issuer_cert.not_valid_after_utc
    issuer.save()
    identity = AgentGatewayIdentity(id=uuid.uuid4(), tenant=tenant, policy=policy, issuer=issuer)
    identity.private_key_nonce, identity.private_key_ciphertext = encrypt_private_key(
        gateway_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        associated_data=gateway_associated_data(tenant.id, identity.id),
    )
    identity.certificate_pem = _pem(gateway_cert)
    identity.chain_pem = _pem(issuer_cert) + _pem(root_cert)
    identity.fingerprint_sha256 = certificate_fingerprint(gateway_cert)
    identity.not_before = gateway_cert.not_valid_before_utc
    identity.not_after = gateway_cert.not_valid_after_utc
    identity.save()
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent_pki.bootstrap",
        object_type="agent_pki_policy",
        object_id=policy.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"trust_mode": policy.trust_mode, "gateway_dns_name": gateway_dns_name},
    )
    return policy


def _replace_gateway_identity(*, policy, issuer, issuer_key, issuer_cert) -> None:
    identity = AgentGatewayIdentity.objects.select_for_update().get(policy=policy)
    gateway_key, gateway_cert = issue_gateway_identity(
        issuer_key,
        issuer_cert,
        policy.gateway_dns_name,
    )
    identity.private_key_nonce, identity.private_key_ciphertext = encrypt_private_key(
        gateway_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        associated_data=gateway_associated_data(policy.tenant_id, identity.id),
    )
    identity.issuer = issuer
    identity.certificate_pem = _pem(gateway_cert)
    identity.chain_pem = issuer.certificate_pem + issuer.chain_pem
    identity.fingerprint_sha256 = certificate_fingerprint(gateway_cert)
    identity.not_before = gateway_cert.not_valid_before_utc
    identity.not_after = gateway_cert.not_valid_after_utc
    identity.rotated_at = timezone.now()
    identity.save()


@transaction.atomic
def rotate_managed_issuer(
    *, tenant, recovery_bundle: bytes, recovery_passphrase: bytes, actor: str
):
    policy = AgentPkiPolicy.objects.select_for_update().get(tenant=tenant)
    if policy.trust_mode != AgentPkiPolicy.TrustMode.IPMS_MANAGED:
        raise ValidationError("Managed issuer rotation requires IPMS-managed trust mode.")
    root_key, root_cert = load_managed_root_recovery(
        recovery_bundle,
        recovery_passphrase,
    )
    if (
        certificate_fingerprint(root_cert) != policy.root_fingerprint_sha256
        or _pem(root_cert) != policy.root_certificate_pem
    ):
        raise ValidationError("The Root recovery bundle does not belong to this tenant.")
    old_issuer = AgentIssuer.objects.select_for_update().get(
        tenant=tenant,
        status=AgentIssuer.Status.ACTIVE,
    )
    issuer_key, issuer_cert = issue_managed_issuer(root_key, root_cert)
    issuer = AgentIssuer(id=uuid.uuid4(), tenant=tenant, policy=policy)
    issuer.private_key_nonce, issuer.private_key_ciphertext = encrypt_private_key(
        issuer_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        associated_data=issuer_associated_data(tenant.id, issuer.id),
    )
    issuer.certificate_pem = _pem(issuer_cert)
    issuer.chain_pem = policy.root_certificate_pem
    issuer.fingerprint_sha256 = certificate_fingerprint(issuer_cert)
    issuer.serial_number = format(issuer_cert.serial_number, "x")
    issuer.not_before = issuer_cert.not_valid_before_utc
    issuer.not_after = issuer_cert.not_valid_after_utc
    issuer.save()
    old_issuer.status = AgentIssuer.Status.OVERLAP
    old_issuer.save(update_fields=("status",))
    _replace_gateway_identity(
        policy=policy,
        issuer=issuer,
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
    )
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent_pki.issuer.rotate",
        object_type="agent_issuer",
        object_id=issuer.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"previous_issuer_id": str(old_issuer.id)},
    )
    return issuer


@transaction.atomic
def rollback_managed_issuer(*, tenant, issuer_id, actor: str):
    policy = AgentPkiPolicy.objects.select_for_update().get(tenant=tenant)
    if policy.trust_mode != AgentPkiPolicy.TrustMode.IPMS_MANAGED:
        raise ValidationError("Managed issuer rollback requires IPMS-managed trust mode.")
    current = AgentIssuer.objects.select_for_update().get(
        tenant=tenant,
        status=AgentIssuer.Status.ACTIVE,
    )
    target = AgentIssuer.objects.select_for_update().get(
        id=issuer_id,
        tenant=tenant,
        status=AgentIssuer.Status.OVERLAP,
    )
    if not target.private_key_nonce or not target.private_key_ciphertext:
        raise ValidationError("The rollback issuer has no protected private key.")
    target_key = decrypt_private_key(
        bytes(target.private_key_nonce),
        bytes(target.private_key_ciphertext),
        associated_data=issuer_associated_data(tenant.id, target.id),
    )
    target_cert = x509.load_pem_x509_certificate(target.certificate_pem.encode("ascii"))
    current.status = AgentIssuer.Status.OVERLAP
    current.save(update_fields=("status",))
    target.status = AgentIssuer.Status.ACTIVE
    target.save(update_fields=("status",))
    _replace_gateway_identity(
        policy=policy,
        issuer=target,
        issuer_key=target_key,
        issuer_cert=target_cert,
    )
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent_pki.issuer.rollback",
        object_type="agent_issuer",
        object_id=target.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"replaced_issuer_id": str(current.id)},
    )
    return target


@transaction.atomic
def retire_overlap_issuer(*, tenant, issuer_id, actor: str):
    issuer = AgentIssuer.objects.select_for_update().get(
        id=issuer_id,
        tenant=tenant,
        status=AgentIssuer.Status.OVERLAP,
    )
    if AgentEnrollment.objects.filter(
        issuer=issuer,
        status=AgentEnrollment.Status.ACTIVE,
        certificate_not_after__gt=timezone.now(),
    ).exists():
        raise ValidationError("The issuer still has unexpired active Agent certificates.")
    issuer.status = AgentIssuer.Status.RETIRED
    issuer.retired_at = timezone.now()
    issuer.save(update_fields=("status", "retired_at"))
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent_pki.issuer.retire",
        object_type="agent_issuer",
        object_id=issuer.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
    )
    return issuer


@transaction.atomic
def create_enrollment_token(*, tenant, display_name: str, actor: str, lifetime_minutes: int = 30):
    if not 5 <= lifetime_minutes <= 1440:
        raise ValidationError("Enrollment token lifetime must be between 5 and 1440 minutes.")
    policy = AgentPkiPolicy.objects.select_related("gateway_identity").get(tenant=tenant)
    if policy.trust_mode == AgentPkiPolicy.TrustMode.EXTERNAL_CERTIFICATES:
        raise ValidationError(
            "Bootstrap tokens are unavailable in external-certificate mode."
        )
    device_id = uuid.uuid4()
    enrollment = AgentEnrollment.objects.create(
        tenant=tenant,
        device_id=device_id,
        device_uri=f"urn:ipms:agent:{device_id}",
        display_name=display_name,
    )
    raw_token = secrets.token_urlsafe(32)
    AgentEnrollmentToken.objects.create(
        tenant=tenant,
        enrollment=enrollment,
        token_digest=hashlib.sha256(raw_token.encode()).hexdigest(),
        gateway_fingerprint_sha256=policy.gateway_identity.fingerprint_sha256,
        expires_at=timezone.now() + timedelta(minutes=lifetime_minutes),
        created_by=actor,
    )
    _audit(
        tenant=tenant,
        actor=actor,
        action="agent.enrollment_token.create",
        object_type="agent_enrollment",
        object_id=enrollment.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"expires_in_minutes": lifetime_minutes},
    )
    return enrollment, raw_token, policy.gateway_identity.fingerprint_sha256


@transaction.atomic
def enroll_agent(*, raw_token: str, csr_pem: str):
    digest = hashlib.sha256(raw_token.encode()).hexdigest()
    token = (
        AgentEnrollmentToken.objects.select_for_update()
        .select_related("enrollment", "tenant")
        .filter(token_digest=digest, used_at__isnull=True, expires_at__gt=timezone.now())
        .first()
    )
    if token is None:
        raise ValidationError("The enrollment token is invalid or expired.")
    enrollment = token.enrollment
    if enrollment.status != AgentEnrollment.Status.PENDING:
        raise ValidationError("The enrollment is not pending.")
    issuer = AgentIssuer.objects.select_for_update().get(
        tenant=token.tenant,
        status=AgentIssuer.Status.ACTIVE,
    )
    if not issuer.private_key_nonce or not issuer.private_key_ciphertext:
        raise ValidationError("The active issuer cannot issue Agent certificates.")
    csr, key_algorithm = validate_agent_csr(csr_pem)
    issuer_cert = x509.load_pem_x509_certificate(issuer.certificate_pem.encode("ascii"))
    issuer_key = decrypt_private_key(
        bytes(issuer.private_key_nonce),
        bytes(issuer.private_key_ciphertext),
        associated_data=issuer_associated_data(token.tenant.id, issuer.id),
    )
    policy = issuer.policy
    certificate = issue_agent_certificate(
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
        csr=csr,
        device_uri=enrollment.device_uri,
        lifetime_days=policy.certificate_lifetime_days,
    )
    enrollment.status = AgentEnrollment.Status.ACTIVE
    enrollment.issuer = issuer
    enrollment.certificate_pem = _pem(certificate)
    enrollment.certificate_fingerprint_sha256 = certificate_fingerprint(certificate)
    enrollment.certificate_serial_number = format(certificate.serial_number, "x")
    enrollment.certificate_not_before = certificate.not_valid_before_utc
    enrollment.certificate_not_after = certificate.not_valid_after_utc
    enrollment.key_algorithm = key_algorithm
    enrollment.save()
    token.used_at = timezone.now()
    token.save(update_fields=("used_at",))
    _audit(
        tenant=token.tenant,
        actor=enrollment.device_uri,
        action="agent.enroll",
        object_type="agent_enrollment",
        object_id=enrollment.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"key_algorithm": key_algorithm},
    )
    return enrollment, enrollment.certificate_pem, issuer.certificate_pem + issuer.chain_pem


def validate_peer_certificate(certificate_der: bytes):
    certificate = x509.load_der_x509_certificate(certificate_der)
    try:
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as exc:
        raise ValidationError("The Agent certificate profile is incomplete.") from exc
    from cryptography.x509.oid import ExtendedKeyUsageOID

    if ExtendedKeyUsageOID.CLIENT_AUTH not in eku or len(eku) != 1:
        raise ValidationError("The Agent certificate EKU is invalid.")
    device_uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    if len(device_uris) != 1:
        raise ValidationError("The Agent certificate device URI is invalid.")
    serial = format(certificate.serial_number, "x")
    enrollment = AgentEnrollment.objects.select_related("tenant", "issuer").filter(
        device_uri=device_uris[0],
        certificate_serial_number=serial,
        status=AgentEnrollment.Status.ACTIVE,
    ).first()
    if enrollment is None or AgentRevocation.objects.filter(enrollment=enrollment).exists():
        raise ValidationError("The Agent identity is not active.")
    if enrollment.issuer.tenant_id != enrollment.tenant_id:
        raise ValidationError("The Agent issuer tenant binding is invalid.")
    if enrollment.issuer.status not in {AgentIssuer.Status.ACTIVE, AgentIssuer.Status.OVERLAP}:
        raise ValidationError("The Agent issuer is not accepted.")
    if certificate_fingerprint(certificate) != enrollment.certificate_fingerprint_sha256:
        raise ValidationError("The Agent certificate does not match the enrollment.")
    return enrollment


@transaction.atomic
def renew_agent_certificate(*, enrollment: AgentEnrollment, csr_pem: str):
    enrollment = AgentEnrollment.objects.select_for_update().select_related("tenant").get(
        id=enrollment.id,
        status=AgentEnrollment.Status.ACTIVE,
    )
    policy = AgentPkiPolicy.objects.get(tenant=enrollment.tenant)
    if enrollment.certificate_not_after is None:
        raise ValidationError("The Agent certificate expiry is unavailable.")
    if enrollment.certificate_not_after > timezone.now() + timedelta(
        days=policy.renewal_window_days
    ):
        raise ValidationError("The Agent certificate is not in its renewal window.")
    issuer = AgentIssuer.objects.get(
        tenant=enrollment.tenant,
        status=AgentIssuer.Status.ACTIVE,
    )
    if not issuer.private_key_nonce or not issuer.private_key_ciphertext:
        raise ValidationError("The active issuer cannot renew Agent certificates.")
    csr, key_algorithm = validate_agent_csr(csr_pem)
    issuer_cert = x509.load_pem_x509_certificate(issuer.certificate_pem.encode("ascii"))
    issuer_key = decrypt_private_key(
        bytes(issuer.private_key_nonce),
        bytes(issuer.private_key_ciphertext),
        associated_data=issuer_associated_data(enrollment.tenant.id, issuer.id),
    )
    certificate = issue_agent_certificate(
        issuer_key=issuer_key,
        issuer_cert=issuer_cert,
        csr=csr,
        device_uri=enrollment.device_uri,
        lifetime_days=policy.certificate_lifetime_days,
    )
    enrollment.issuer = issuer
    enrollment.certificate_pem = _pem(certificate)
    enrollment.certificate_fingerprint_sha256 = certificate_fingerprint(certificate)
    enrollment.certificate_serial_number = format(certificate.serial_number, "x")
    enrollment.certificate_not_before = certificate.not_valid_before_utc
    enrollment.certificate_not_after = certificate.not_valid_after_utc
    enrollment.key_algorithm = key_algorithm
    enrollment.save()
    _audit(
        tenant=enrollment.tenant,
        actor=enrollment.device_uri,
        action="agent.certificate.renew",
        object_type="agent_enrollment",
        object_id=enrollment.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"key_algorithm": key_algorithm},
    )
    return enrollment.certificate_pem, issuer.certificate_pem + issuer.chain_pem


def _bounded_inventory_string(
    inventory: dict,
    name: str,
    maximum: int,
    *,
    required: bool = False,
) -> str:
    value = inventory.get(name, "")
    if not isinstance(value, str) or len(value) > maximum or (required and not value.strip()):
        raise ValidationError(f"The Agent inventory field is invalid: {name}.")
    return value.strip()


@transaction.atomic
def confirm_inventory(
    enrollment: AgentEnrollment,
    *,
    inventory: object,
    agent_version: str,
) -> None:
    from ipms.apps.discovery.models import WindowsServer

    if not isinstance(inventory, dict) or len(inventory) > 32:
        raise ValidationError("The Agent inventory document is invalid.")
    if (
        inventory.get("schema_version") != "1"
        or inventory.get("pack") != "windows-server-core"
    ):
        raise ValidationError("The Agent inventory schema or Management Pack is invalid.")
    if not isinstance(agent_version, str) or not 1 <= len(agent_version) <= 64:
        raise ValidationError("The Agent version is invalid.")
    hostname = _bounded_inventory_string(inventory, "hostname", 255, required=True)
    os_product = _bounded_inventory_string(inventory, "os_product", 255)
    os_build = _bounded_inventory_string(inventory, "os_build", 64)
    architecture = _bounded_inventory_string(inventory, "architecture", 32)
    logical_processors = inventory.get("logical_processors")
    memory_bytes = inventory.get("memory_total_bytes")
    gateway_port = inventory.get("agent_gateway_port")
    if not isinstance(logical_processors, int) or not 1 <= logical_processors <= 65_535:
        raise ValidationError("The Agent logical processor count is invalid.")
    if not isinstance(memory_bytes, int) or not 1 <= memory_bytes <= 2**63 - 1:
        raise ValidationError("The Agent memory size is invalid.")
    if not isinstance(gateway_port, int) or not 1 <= gateway_port <= 65_535:
        raise ValidationError("The Agent Gateway port is invalid.")
    now = timezone.now()
    updates = {"last_seen_at": now}
    if enrollment.first_inventory_at is None:
        updates["first_inventory_at"] = now
    AgentEnrollment.objects.filter(id=enrollment.id).update(**updates)
    WindowsServer.objects.update_or_create(
        tenant=enrollment.tenant,
        inventory_source=WindowsServer.InventorySource.AGENT,
        source_id=enrollment.device_uri,
        defaults={
            "server_type": WindowsServer.ServerType.PHYSICAL,
            "hostname": hostname,
            "operating_system": os_product,
            "os_build": os_build,
            "architecture": architecture,
            "logical_processors": logical_processors,
            "memory_bytes": memory_bytes,
            "agent_version": agent_version,
            "agent_state": WindowsServer.AgentState.ONLINE,
            "health": WindowsServer.Health.HEALTHY,
            "management_packs": ["windows-server-core"],
            "detail_snapshot": {
                "schema_version": "1",
                "agent_gateway_port": gateway_port,
            },
            "last_seen_at": now,
            "discovered_at": now,
        },
    )


@transaction.atomic
def revoke_agent(*, enrollment: AgentEnrollment, actor: str, reason: str):
    if enrollment.status == AgentEnrollment.Status.REVOKED:
        return enrollment.revocation
    enrollment.status = AgentEnrollment.Status.REVOKED
    enrollment.save(update_fields=("status", "updated_at"))
    revocation = AgentRevocation.objects.create(
        tenant=enrollment.tenant,
        enrollment=enrollment,
        certificate_serial_number=enrollment.certificate_serial_number,
        reason=reason,
        revoked_by=actor,
    )
    _audit(
        tenant=enrollment.tenant,
        actor=actor,
        action="agent.revoke",
        object_type="agent_enrollment",
        object_id=enrollment.id,
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"reason": reason},
    )
    return revocation


def export_gateway_runtime(*, tenant, directory: Path) -> None:
    identity = AgentGatewayIdentity.objects.select_related("issuer").get(tenant=tenant)
    private_key = decrypt_private_key(
        bytes(identity.private_key_nonce),
        bytes(identity.private_key_ciphertext),
        associated_data=gateway_associated_data(tenant.id, identity.id),
    )
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    accepted_issuers = AgentIssuer.objects.filter(
        tenant=tenant,
        status__in=(AgentIssuer.Status.ACTIVE, AgentIssuer.Status.OVERLAP),
    )
    trust_pem = "".join(issuer.certificate_pem + issuer.chain_pem for issuer in accepted_issuers)
    atomic_write_private(directory / "gateway.key", key_pem)
    atomic_write_private(
        directory / "gateway-chain.pem",
        (identity.certificate_pem + identity.chain_pem).encode("ascii"),
    )
    atomic_write_private(directory / "agent-trust.pem", trust_pem.encode("ascii"))
    for path in (
        directory / "gateway.key",
        directory / "gateway-chain.pem",
        directory / "agent-trust.pem",
    ):
        path.chmod(0o640)
