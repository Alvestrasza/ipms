import hashlib
import json
import os
import ssl
import tempfile
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant

from .crypto import (
    DEVICE_URI_PATTERN,
    create_managed_hierarchy,
    issue_agent_certificate,
)
from .gateway import (
    _bounded_json,
    _connection_protocol,
    _parse_http_request,
    build_tls_context,
)
from .models import AgentEnrollment, AgentEnrollmentToken, AgentIssuer, AgentPkiPolicy
from .services import (
    bootstrap_managed_pki,
    configure_external_certificate_pki,
    configure_external_issuing_pki,
    create_enrollment_token,
    confirm_inventory,
    enroll_agent,
    export_gateway_runtime,
    import_external_agent_certificate,
    retire_overlap_issuer,
    revoke_agent,
    rollback_managed_issuer,
    rotate_managed_issuer,
    renew_agent_certificate,
    validate_peer_certificate,
)


def create_csr(private_key=None) -> tuple[object, str]:
    private_key = private_key or ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(private_key, hashes.SHA256())
    )
    return private_key, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


class ManagedAgentPkiTests(TestCase):
    def setUp(self) -> None:
        self.tenant = Tenant.objects.create(slug="example", display_name="Example")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.recovery = Path(self.temp.name) / "root-recovery.pem"
        self.policy = bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="gateway.example.invalid",
            recovery_output=self.recovery,
            recovery_passphrase=b"test-only-recovery-passphrase",
            actor="test-operator",
        )

    def test_bootstrap_keeps_only_encrypted_runtime_keys_and_one_time_recovery(self) -> None:
        issuer = AgentIssuer.objects.get(tenant=self.tenant)
        gateway = self.policy.gateway_identity
        recovery = self.recovery.read_bytes()

        self.assertEqual(self.policy.trust_mode, AgentPkiPolicy.TrustMode.IPMS_MANAGED)
        self.assertTrue(recovery.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertNotIn(b"BEGIN PRIVATE KEY", recovery)
        self.assertNotIn(b"PRIVATE KEY", bytes(issuer.private_key_ciphertext))
        self.assertNotIn(b"PRIVATE KEY", bytes(gateway.private_key_ciphertext))
        if os.name != "nt":
            self.assertEqual(self.recovery.stat().st_mode & 0o777, 0o600)
        self.assertFalse(
            AuditEvent.objects.filter(details__has_key="root_certificate_pem").exists()
        )

        with self.assertRaisesMessage(ValidationError, "already configured"):
            bootstrap_managed_pki(
                tenant=self.tenant,
                gateway_dns_name="gateway.example.invalid",
                recovery_output=Path(self.temp.name) / "second.pem",
                recovery_passphrase=b"test-only-recovery-passphrase",
                actor="test-operator",
            )

    def test_one_time_token_enrolls_unique_device_certificate(self) -> None:
        enrollment, raw_token, fingerprint = create_enrollment_token(
            tenant=self.tenant,
            display_name="Synthetic Windows Server",
            actor="test-operator",
        )
        token = AgentEnrollmentToken.objects.get(enrollment=enrollment)
        _, csr_pem = create_csr()
        enrolled, certificate_pem, chain_pem = enroll_agent(
            raw_token=raw_token,
            csr_pem=csr_pem,
        )
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode())

        self.assertRegex(enrollment.device_uri, DEVICE_URI_PATTERN)
        self.assertEqual(token.token_digest, hashlib.sha256(raw_token.encode()).hexdigest())
        self.assertNotEqual(token.token_digest, raw_token)
        self.assertEqual(fingerprint, self.policy.gateway_identity.fingerprint_sha256)
        self.assertEqual(enrolled.status, AgentEnrollment.Status.ACTIVE)
        self.assertIn(
            ExtendedKeyUsageOID.CLIENT_AUTH,
            certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,
        )
        self.assertEqual(
            certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.UniformResourceIdentifier),
            [enrollment.device_uri],
        )
        self.assertNotIn("PRIVATE KEY", certificate_pem + chain_pem)
        self.assertIsNotNone(validate_peer_certificate(certificate.public_bytes(serialization.Encoding.DER)))

        with self.assertRaisesMessage(ValidationError, "invalid or expired"):
            enroll_agent(raw_token=raw_token, csr_pem=csr_pem)

    def test_weak_agent_key_is_rejected_without_consuming_token(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Weak Agent",
            actor="test-operator",
        )
        _, csr_pem = create_csr(
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
        )
        with self.assertRaisesMessage(ValidationError, "at least 3072"):
            enroll_agent(raw_token=raw_token, csr_pem=csr_pem)
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.PENDING)
        self.assertIsNone(enrollment.bootstrap_tokens.get().used_at)

    def test_windows_certenroll_pem_label_is_accepted(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Windows CertEnroll Agent",
            actor="test-operator",
        )
        _, csr_pem = create_csr()
        windows_csr = csr_pem.replace(
            "BEGIN CERTIFICATE REQUEST",
            "BEGIN NEW CERTIFICATE REQUEST",
        ).replace(
            "END CERTIFICATE REQUEST",
            "END NEW CERTIFICATE REQUEST",
        )
        enrolled, _, _ = enroll_agent(raw_token=raw_token, csr_pem=windows_csr)
        self.assertEqual(enrolled.id, enrollment.id)
        self.assertEqual(enrolled.status, AgentEnrollment.Status.ACTIVE)

    def test_windows_certenroll_certificate_pem_label_is_accepted(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Windows CertEnroll Legacy Agent",
            actor="test-operator",
        )
        _, csr_pem = create_csr()
        windows_csr = csr_pem.replace(
            "BEGIN CERTIFICATE REQUEST",
            "BEGIN CERTIFICATE",
        ).replace(
            "END CERTIFICATE REQUEST",
            "END CERTIFICATE",
        )
        enrolled, _, _ = enroll_agent(raw_token=raw_token, csr_pem=windows_csr)
        self.assertEqual(enrolled.id, enrollment.id)
        self.assertEqual(enrolled.status, AgentEnrollment.Status.ACTIVE)

    def test_revocation_immediately_blocks_existing_certificate(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Revoked Agent",
            actor="test-operator",
        )
        _, csr_pem = create_csr()
        enrollment, certificate_pem, _ = enroll_agent(raw_token=raw_token, csr_pem=csr_pem)
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode())
        certificate_der = certificate.public_bytes(serialization.Encoding.DER)
        self.assertEqual(validate_peer_certificate(certificate_der).id, enrollment.id)

        revoke_agent(enrollment=enrollment, actor="test-operator", reason="compromised")
        with self.assertRaisesMessage(ValidationError, "not active"):
            validate_peer_certificate(certificate_der)

    def test_revocation_command_requires_the_enrollment_tenant(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Tenant-scoped revocation",
            actor="test-operator",
        )
        enrollment, _, _ = enroll_agent(raw_token=raw_token, csr_pem=create_csr()[1])
        other_tenant = Tenant.objects.create(slug="other", display_name="Other")
        with self.assertRaises(CommandError):
            call_command(
                "revoke_agent",
                tenant_slug=other_tenant.slug,
                device_uri=enrollment.device_uri,
                reason="test",
                actor="test-operator",
            )
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.ACTIVE)
        call_command(
            "revoke_agent",
            tenant_slug=self.tenant.slug,
            device_uri=enrollment.device_uri,
            reason="test",
            actor="test-operator",
        )
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, AgentEnrollment.Status.REVOKED)

    def test_renewal_requires_window_and_replaces_certificate_identity(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Renewing Agent",
            actor="test-operator",
        )
        _, csr_pem = create_csr()
        enrollment, original_pem, _ = enroll_agent(raw_token=raw_token, csr_pem=csr_pem)
        with self.assertRaisesMessage(ValidationError, "not in its renewal window"):
            renew_agent_certificate(enrollment=enrollment, csr_pem=create_csr()[1])

        AgentEnrollment.objects.filter(id=enrollment.id).update(
            certificate_not_after=enrollment.certificate_not_before
        )
        enrollment.refresh_from_db()
        renewed_pem, _ = renew_agent_certificate(
            enrollment=enrollment,
            csr_pem=create_csr()[1],
        )
        self.assertNotEqual(original_pem, renewed_pem)

    def test_gateway_runtime_uses_tls13_client_validation_and_no_web_secret(self) -> None:
        runtime = Path(self.temp.name) / "runtime"
        export_gateway_runtime(tenant=self.tenant, directory=runtime)
        context = build_tls_context(runtime)

        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(context.verify_mode, ssl.CERT_OPTIONAL)
        if os.name != "nt":
            self.assertEqual((runtime / "gateway.key").stat().st_mode & 0o777, 0o600)
        self.assertTrue((runtime / "agent-trust.pem").read_text().startswith("-----BEGIN CERTIFICATE-----"))

    def test_gateway_envelope_is_bounded_and_rejects_non_objects(self) -> None:
        self.assertEqual(_bounded_json(b'{"type":"hello"}\n')["type"], "hello")
        with self.assertRaises(ValidationError):
            _bounded_json(json.dumps(["hello"]).encode())
        with self.assertRaises(ValidationError):
            _bounded_json(b"{" + b"x" * 65_536)

    def test_http_compatibility_route_is_strict_and_bounded(self) -> None:
        path, headers, length = _parse_http_request(
            b"POST /v1/inventory HTTP/1.1\r\n"
            b"Host: gateway.example.invalid\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 42\r\n\r\n"
        )
        self.assertEqual(path, "/v1/inventory")
        self.assertEqual(headers["host"], "gateway.example.invalid")
        self.assertEqual(length, 42)
        with self.assertRaises(ValidationError):
            _parse_http_request(
                b"GET /v1/inventory HTTP/1.1\r\nContent-Length: 1\r\n\r\n"
            )

    def test_gateway_routes_winhttp_without_alpn_only_to_bounded_http(self) -> None:
        self.assertEqual(_connection_protocol(None), "http")
        self.assertEqual(_connection_protocol("http/1.1"), "http")
        self.assertEqual(_connection_protocol("ipms-agent/1"), "stream")
        with self.assertRaisesMessage(ValidationError, "ALPN is invalid"):
            _connection_protocol("unexpected-protocol")

    def test_inventory_updates_only_the_certificate_tenant_server(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Inventory Agent",
            actor="test-operator",
        )
        enrollment, _, _ = enroll_agent(raw_token=raw_token, csr_pem=create_csr()[1])
        confirm_inventory(
            enrollment,
            agent_version="0.1.17",
            inventory={
                "schema_version": "1",
                "pack": "windows-server-core",
                "agent_gateway_port": 9419,
                "hostname": "windows-test",
                "os_product": "Windows 10 Enterprise LTSC 2024",
                "os_name": "Microsoft Windows 11 Enterprise LTSC",
                "os_build": "26100",
                "architecture": "x64",
                "manufacturer": "Microsoft Corporation",
                "model": "Virtual Machine",
                "machine_type": "virtual",
                "logical_processors": 4,
                "memory_total_bytes": 8 * 1024**3,
            },
        )
        server = WindowsServer.objects.get(source_id=enrollment.device_uri)
        self.assertEqual(server.tenant, self.tenant)
        self.assertEqual(server.hostname, "windows-test")
        self.assertEqual(server.operating_system, "Microsoft Windows 11 Enterprise LTSC")
        self.assertEqual(server.server_type, WindowsServer.ServerType.VIRTUAL)
        self.assertEqual(server.manufacturer, "Microsoft Corporation")
        self.assertEqual(server.model, "Virtual Machine")
        self.assertEqual(server.agent_state, WindowsServer.AgentState.ONLINE)
        self.assertEqual(server.management_packs, ["windows-server-core"])
        with self.assertRaises(ValidationError):
            confirm_inventory(enrollment, agent_version="0.1.17", inventory={})

        invalid_inventory = {
            "schema_version": "1",
            "pack": "windows-server-core",
            "agent_gateway_port": 9419,
            "hostname": "windows-test",
            "machine_type": "container",
            "logical_processors": 4,
            "memory_total_bytes": 8 * 1024**3,
        }
        with self.assertRaisesMessage(ValidationError, "machine type is invalid"):
            confirm_inventory(
                enrollment,
                agent_version="0.1.23",
                inventory=invalid_inventory,
            )

    def test_managed_issuer_rotation_keeps_overlap_and_supports_rollback(self) -> None:
        old_issuer = AgentIssuer.objects.get(
            tenant=self.tenant,
            status=AgentIssuer.Status.ACTIVE,
        )
        old_gateway_fingerprint = self.policy.gateway_identity.fingerprint_sha256
        new_issuer = rotate_managed_issuer(
            tenant=self.tenant,
            recovery_bundle=self.recovery.read_bytes(),
            recovery_passphrase=b"test-only-recovery-passphrase",
            actor="test-operator",
        )
        old_issuer.refresh_from_db()
        self.policy.gateway_identity.refresh_from_db()
        self.assertEqual(old_issuer.status, AgentIssuer.Status.OVERLAP)
        self.assertEqual(new_issuer.status, AgentIssuer.Status.ACTIVE)
        self.assertNotEqual(
            old_gateway_fingerprint,
            self.policy.gateway_identity.fingerprint_sha256,
        )

        rolled_back = rollback_managed_issuer(
            tenant=self.tenant,
            issuer_id=old_issuer.id,
            actor="test-operator",
        )
        new_issuer.refresh_from_db()
        self.assertEqual(rolled_back.status, AgentIssuer.Status.ACTIVE)
        self.assertEqual(new_issuer.status, AgentIssuer.Status.OVERLAP)

    def test_overlap_retirement_waits_for_unexpired_agent_certificates(self) -> None:
        enrollment, raw_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Overlap Agent",
            actor="test-operator",
        )
        enrollment, _, _ = enroll_agent(raw_token=raw_token, csr_pem=create_csr()[1])
        old_issuer = enrollment.issuer
        rotate_managed_issuer(
            tenant=self.tenant,
            recovery_bundle=self.recovery.read_bytes(),
            recovery_passphrase=b"test-only-recovery-passphrase",
            actor="test-operator",
        )
        with self.assertRaisesMessage(ValidationError, "unexpired active"):
            retire_overlap_issuer(
                tenant=self.tenant,
                issuer_id=old_issuer.id,
                actor="test-operator",
            )


class ExternalAgentPkiTests(TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        (
            self.root_cert,
            self.issuer_key,
            self.issuer_cert,
            self.gateway_key,
            self.gateway_cert,
            _,
        ) = create_managed_hierarchy(
            "gateway.example.invalid",
            b"test-only-recovery-passphrase",
        )

    def pem(self, certificate) -> bytes:
        return certificate.public_bytes(serialization.Encoding.PEM)

    def key_pem(self, key) -> bytes:
        return key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def test_external_issuing_ca_is_validated_and_runtime_key_is_reencrypted(self) -> None:
        tenant = Tenant.objects.create(slug="external-issuer", display_name="External")
        policy = configure_external_issuing_pki(
            tenant=tenant,
            gateway_dns_name="gateway.example.invalid",
            issuer_certificate_pem=self.pem(self.issuer_cert),
            issuer_private_key_pem=self.key_pem(self.issuer_key),
            issuer_private_key_password=None,
            chain_pem=self.pem(self.root_cert),
            actor="test-operator",
        )
        issuer = policy.issuers.get()
        self.assertEqual(policy.trust_mode, AgentPkiPolicy.TrustMode.EXTERNAL_ISSUING_CA)
        self.assertTrue(issuer.external)
        self.assertNotIn(b"PRIVATE KEY", bytes(issuer.private_key_ciphertext))
        self.assertEqual(policy.gateway_identity.issuer, issuer)

    def test_external_issuing_ca_rejects_mismatched_private_key(self) -> None:
        tenant = Tenant.objects.create(slug="mismatch", display_name="Mismatch")
        with self.assertRaisesMessage(ValidationError, "do not match"):
            configure_external_issuing_pki(
                tenant=tenant,
                gateway_dns_name="gateway.example.invalid",
                issuer_certificate_pem=self.pem(self.issuer_cert),
                issuer_private_key_pem=self.key_pem(ec.generate_private_key(ec.SECP384R1())),
                issuer_private_key_password=None,
                chain_pem=self.pem(self.root_cert),
                actor="test-operator",
            )

    def test_external_certificate_mode_imports_only_preissued_agent_identity(self) -> None:
        tenant = Tenant.objects.create(slug="external-cert", display_name="External Cert")
        configure_external_certificate_pki(
            tenant=tenant,
            gateway_dns_name="gateway.example.invalid",
            gateway_certificate_pem=self.pem(self.gateway_cert),
            gateway_private_key_pem=self.key_pem(self.gateway_key),
            gateway_private_key_password=None,
            gateway_chain_pem=self.pem(self.issuer_cert) + self.pem(self.root_cert),
            agent_issuer_certificate_pem=self.pem(self.issuer_cert),
            actor="test-operator",
        )
        with self.assertRaisesMessage(ValidationError, "unavailable"):
            create_enrollment_token(
                tenant=tenant,
                display_name="Blocked Token Agent",
                actor="test-operator",
            )

        device_id = uuid.uuid4()
        _, csr_pem = create_csr()
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        agent_certificate = issue_agent_certificate(
            issuer_key=self.issuer_key,
            issuer_cert=self.issuer_cert,
            csr=csr,
            device_uri=f"urn:ipms:agent:{device_id}",
            lifetime_days=30,
        )
        enrollment = import_external_agent_certificate(
            tenant=tenant,
            display_name="Preissued Agent",
            certificate_pem=self.pem(agent_certificate),
            actor="test-operator",
        )
        self.assertEqual(enrollment.status, AgentEnrollment.Status.ACTIVE)
        self.assertEqual(enrollment.device_id, device_id)
