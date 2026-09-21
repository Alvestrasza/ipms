# File Name: test_onboarding.py
# Version: v0.2.76 | Created: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant PKI custody, multi-tenant Gateway and package readiness tests.

import asyncio
import hashlib
import json
import socket
import ssl
import threading
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership

from .gateway import GatewayTlsRegistry
from .models import AgentPkiPolicy, AgentPkiRecoveryMaterial
from .onboarding import (
    agent_package_status,
    tenant_agent_onboarding_status,
    verify_gateway_isolation,
)
from .services import (
    bootstrap_managed_pki,
    confirm_managed_pki_recovery,
    create_enrollment_token,
    download_managed_pki_recovery,
    export_all_gateway_runtime,
    prepare_managed_pki,
)


class AgentOnboardingTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(
            slug="hgs-only",
            display_name="HGS only",
            purpose=Tenant.Purpose.HGS,
        )
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_recovery_must_be_downloaded_and_confirmed_before_enrollment(self):
        policy, material = prepare_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="hgs-gateway.example.invalid",
            gateway_port=9419,
            recovery_passphrase=b"separate-test-passphrase-value",
            actor="platform-test",
        )
        self.assertIsNone(policy.root_recovery_exported_at)
        with self.assertRaisesMessage(ValidationError, "recovery export"):
            create_enrollment_token(
                tenant=self.tenant,
                display_name="Blocked server",
                actor="tenant-test",
            )
        recovery, digest = download_managed_pki_recovery(
            tenant=self.tenant,
            actor="platform-test",
        )
        self.assertTrue(recovery.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"))
        self.assertEqual(digest, hashlib.sha256(recovery).hexdigest())
        with self.assertRaisesMessage(ValidationError, "digest"):
            confirm_managed_pki_recovery(
                tenant=self.tenant,
                bundle_sha256="0" * 64,
                actor="platform-test",
            )
        self.assertTrue(AgentPkiRecoveryMaterial.objects.filter(id=material.id).exists())
        confirm_managed_pki_recovery(
            tenant=self.tenant,
            bundle_sha256=digest,
            actor="platform-test",
        )
        policy.refresh_from_db()
        self.assertIsNotNone(policy.root_recovery_exported_at)
        self.assertFalse(AgentPkiRecoveryMaterial.objects.filter(id=material.id).exists())
        enrollment, _, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Allowed server",
            actor="tenant-test",
        )
        self.assertEqual(enrollment.tenant, self.tenant)

    def test_manifest_keeps_per_tenant_identity_and_reloads_new_tenant(self):
        first_recovery = Path(self.temp.name) / "first.pem"
        bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="hgs-gateway.example.invalid",
            recovery_output=first_recovery,
            recovery_passphrase=b"first-separate-passphrase",
            actor="platform-test",
        )
        runtime = Path(self.temp.name) / "runtime"
        first_manifest = export_all_gateway_runtime(directory=runtime)
        registry = GatewayTlsRegistry(runtime)
        selected = type("SelectedTls", (), {"context": None})()
        registry.select(selected, "hgs-gateway.example.invalid", None)
        self.assertEqual(selected.ipms_gateway_tenant_id, str(self.tenant.id))

        second = Tenant.objects.create(slug="second", display_name="Second")
        bootstrap_managed_pki(
            tenant=second,
            gateway_dns_name="second-gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "second.pem",
            recovery_passphrase=b"second-separate-passphrase",
            actor="platform-test",
        )
        second_manifest = export_all_gateway_runtime(directory=runtime)
        selected_second = type("SelectedTls", (), {"context": None})()
        registry.select(selected_second, "second-gateway.example.invalid", None)
        self.assertEqual(selected_second.ipms_gateway_tenant_id, str(second.id))
        self.assertNotEqual(first_manifest["revision"], second_manifest["revision"])
        saved = json.loads((runtime / "gateway-manifest.json").read_text())
        self.assertEqual(len(saved["tenants"]), 2)
        for item in saved["tenants"]:
            material = runtime / item["relative_directory"]
            self.assertTrue((material / "gateway-chain.pem").is_file())
            self.assertTrue((material / "gateway.key").is_file())
            self.assertTrue((material / "agent-trust.pem").is_file())

    def test_gateway_verification_checks_every_configured_tenant(self):
        bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="hgs-gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "recovery.pem",
            recovery_passphrase=b"separate-test-passphrase-value",
            actor="platform-test",
        )
        fingerprint = self.tenant.agent_pki_policy.gateway_identity.fingerprint_sha256
        with patch(
            "ipms.apps.agent_pki.onboarding._probe_gateway",
            return_value=fingerprint,
        ):
            result = verify_gateway_isolation(requested_tenant=self.tenant)
        self.assertTrue(result["all_tenants_preserved"])
        self.assertEqual(result["probe_mode"], "tenant_dns")
        policy = AgentPkiPolicy.objects.get(tenant=self.tenant)
        self.assertEqual(policy.gateway_last_verified_fingerprint_sha256, fingerprint)
        self.assertEqual(policy.gateway_last_verification_error, "")

    def test_sni_presents_the_matching_tenant_gateway_identity(self):
        first = bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="hgs-gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "first-sni.pem",
            recovery_passphrase=b"first-separate-passphrase",
            actor="platform-test",
        )
        second_tenant = Tenant.objects.create(slug="second-sni", display_name="Second SNI")
        second = bootstrap_managed_pki(
            tenant=second_tenant,
            gateway_dns_name="second-gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "second-sni.pem",
            recovery_passphrase=b"second-separate-passphrase",
            actor="platform-test",
        )
        runtime = Path(self.temp.name) / "sni-runtime"
        export_all_gateway_runtime(directory=runtime)
        registry = GatewayTlsRegistry(runtime)
        server_context = registry.default_context
        selected_tenants: list[str] = []

        def select_tenant(ssl_object, server_name, initial_context):
            registry.select(ssl_object, server_name, initial_context)
            selected_tenants.append(ssl_object.ipms_gateway_tenant_id)

        server_context.set_servername_callback(select_tenant)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(2)
        port = listener.getsockname()[1]
        errors: list[Exception] = []

        def serve():
            try:
                for _ in range(2):
                    connection, _ = listener.accept()
                    try:
                        with server_context.wrap_socket(connection, server_side=True) as tls:
                            tls.recv(1)
                    except (ConnectionAbortedError, ConnectionResetError):
                        pass
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        observed_fingerprints = []
        for server_name in (
            "hgs-gateway.example.invalid",
            "second-gateway.example.invalid",
        ):
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                with context.wrap_socket(connection, server_hostname=server_name) as tls:
                    observed_fingerprints.append(
                        hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                    )
                    tls.sendall(b"x")
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(selected_tenants, [str(self.tenant.id), str(second_tenant.id)])
        self.assertEqual(
            observed_fingerprints,
            [
                first.gateway_identity.fingerprint_sha256,
                second.gateway_identity.fingerprint_sha256,
            ],
        )

    def test_asyncio_gateway_exposes_selected_tenant_to_request_handler(self):
        policy = bootstrap_managed_pki(
            tenant=self.tenant,
            gateway_dns_name="async-gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "async-recovery.pem",
            recovery_passphrase=b"async-separate-passphrase",
            actor="platform-test",
        )
        runtime = Path(self.temp.name) / "async-runtime"
        export_all_gateway_runtime(directory=runtime)
        server_context = GatewayTlsRegistry(runtime)
        context = server_context.default_context
        context.set_servername_callback(server_context.select)

        async def exercise():
            selected = []
            accepted = asyncio.Event()

            async def handler(reader, writer):
                ssl_object = writer.get_extra_info("ssl_object")
                selected.append(ssl_object.ipms_gateway_tenant_id)
                accepted.set()
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(
                handler,
                "127.0.0.1",
                0,
                ssl=context,
            )
            port = server.sockets[0].getsockname()[1]
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            client_context.minimum_version = ssl.TLSVersion.TLSv1_3
            _, writer = await asyncio.open_connection(
                "127.0.0.1",
                port,
                ssl=client_context,
                server_hostname="async-gateway.example.invalid",
            )
            certificate = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            await asyncio.wait_for(accepted.wait(), timeout=3)
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()
            return selected, hashlib.sha256(certificate).hexdigest()

        selected, fingerprint = asyncio.run(exercise())
        self.assertEqual(selected, [str(self.tenant.id)])
        self.assertEqual(fingerprint, policy.gateway_identity.fingerprint_sha256)

    def test_hgs_package_requires_hash_match_and_agent_049(self):
        package = Path(self.temp.name) / "ipms-agent.zip"
        package.write_bytes(b"verified-package")
        digest = hashlib.sha256(package.read_bytes()).hexdigest()
        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(package),
            AGENT_WINDOWS_PACKAGE_SHA256=digest,
            AGENT_WINDOWS_VERSION="0.2.49",
        ):
            self.assertTrue(agent_package_status(tenant=self.tenant)["ready"])
        with override_settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(package),
            AGENT_WINDOWS_PACKAGE_SHA256=digest,
            AGENT_WINDOWS_VERSION="0.2.48",
        ):
            status = agent_package_status(tenant=self.tenant)
        self.assertFalse(status["ready"])
        self.assertEqual(status["reason"], "package_hgs_version_too_old")

    def test_existing_independent_administrator_satisfies_onboarding_readiness(self):
        administrator = get_user_model().objects.create_user(
            "existing-tenant-administrator",
            password="Existing-administrator-59!",
        )
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=administrator,
            role=TenantMembership.Role.TENANT_ADMIN,
        )

        status = tenant_agent_onboarding_status(tenant=self.tenant)

        self.assertIsNone(self.tenant.initial_administrator_created_at)
        self.assertTrue(status["administrator_ready"])


class AgentOnboardingApiTests(TestCase):
    password = "Platform-test-password-59!"

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "platform-onboarding",
            password=self.password,
        )
        PlatformAdministrator.objects.create(user=self.user)
        self.tenant = Tenant.objects.create(
            slug="hgs-api",
            display_name="HGS API",
            purpose=Tenant.Purpose.HGS,
            initial_administrator_created_at=timezone.now(),
        )
        self.client.force_login(self.user)
        self.endpoint = f"/api/v1/platform/tenants/{self.tenant.id}/agent-onboarding/"
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.package = Path(self.temp.name) / "ipms-agent.zip"
        self.package.write_bytes(b"api-package")
        self.digest = hashlib.sha256(self.package.read_bytes()).hexdigest()

    def settings_context(self):
        return self.settings(
            AGENT_WINDOWS_PACKAGE_PATH=str(self.package),
            AGENT_WINDOWS_PACKAGE_SHA256=self.digest,
            AGENT_WINDOWS_VERSION="0.2.49",
            AGENT_GATEWAY_PORT=9419,
        )

    def test_platform_operator_completes_recovery_and_gateway_readiness(self):
        with self.settings_context():
            missing = self.client.get(self.endpoint)
            self.assertEqual(missing.status_code, 200)
            self.assertEqual(missing.json()["pki"]["state"], "missing")
            created = self.client.post(
                self.endpoint,
                {
                    "gateway_dns_name": "hgs-api-gateway.example.invalid",
                    "recovery_passphrase": "separate-api-passphrase-value",
                    "recovery_passphrase_confirmation": "separate-api-passphrase-value",
                },
                content_type="application/json",
            )
            self.assertEqual(created.status_code, 201, created.content)
            self.assertEqual(created.json()["pki"]["state"], "recovery_pending")
            recovery = self.client.get(self.endpoint + "recovery/")
            self.assertEqual(recovery.status_code, 200)
            self.assertEqual(recovery["Cache-Control"], "no-store")
            recovery_digest = hashlib.sha256(recovery.content).hexdigest()
            self.assertEqual(recovery["X-IPMS-Recovery-SHA256"], recovery_digest)
            confirmed = self.client.post(
                self.endpoint + "recovery/",
                {"bundle_sha256": recovery_digest},
                content_type="application/json",
            )
            self.assertEqual(confirmed.status_code, 200, confirmed.content)
            self.assertEqual(confirmed.json()["pki"]["state"], "ready")
            fingerprint = AgentPkiPolicy.objects.get(
                tenant=self.tenant
            ).gateway_identity.fingerprint_sha256
            with patch(
                "ipms.apps.agent_pki.onboarding._probe_gateway",
                return_value=fingerprint,
            ):
                verified = self.client.post(
                    self.endpoint + "verify-gateway/",
                    {},
                    content_type="application/json",
                )
            self.assertEqual(verified.status_code, 200, verified.content)
            self.assertTrue(verified.json()["verification"]["all_tenants_preserved"])
            self.assertTrue(verified.json()["onboarding"]["ready_for_enrollment"])

    def test_duplicate_gateway_name_cannot_cross_tenants(self):
        other = Tenant.objects.create(
            slug="other-api",
            display_name="Other API",
            initial_administrator_created_at=timezone.now(),
        )
        bootstrap_managed_pki(
            tenant=other,
            gateway_dns_name="reserved-gateway.example.invalid",
            recovery_output=Path(self.temp.name) / "other-recovery.pem",
            recovery_passphrase=b"other-separate-passphrase",
            actor="test",
        )
        with self.settings_context():
            response = self.client.post(
                self.endpoint,
                {
                    "gateway_dns_name": "RESERVED-GATEWAY.EXAMPLE.INVALID",
                    "recovery_passphrase": "separate-api-passphrase-value",
                    "recovery_passphrase_confirmation": "separate-api-passphrase-value",
                },
                content_type="application/json",
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "gateway_dns_name_unavailable")
