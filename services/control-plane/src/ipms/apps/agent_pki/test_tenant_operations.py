import asyncio
import json
import uuid
import threading
import time
from unittest import skipUnless
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import connection, connections, transaction
from django.test import SimpleTestCase, TestCase, TransactionTestCase
from django.utils import timezone

from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership
from ipms.apps.tenancy.operations import apply_tenant_status_change
from ipms.apps.discovery.models import (
    DiscoveryJob,
    HyperVConsoleSession,
    HyperVVirtualMachineActionJob,
)
from .models import (
    AgentEnrollment,
    AgentEnrollmentToken,
    AgentLifecycleJob,
    WindowsAgentDeployment,
    WindowsAgentDeploymentSecret,
)
from .services import create_enrollment_token, enroll_agent, validate_peer_certificate
from . import gateway, services
from .test_console_transport import ConsoleWriter, request
from . import tests as pki_fixtures


class SuspendedAgentPkiTests(TestCase):
    setUp = pki_fixtures.ManagedAgentPkiTests.setUp

    def test_suspended_tenant_rejects_existing_peer_and_unused_enrollment(self):
        enrollment, token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Existing",
            actor="test-operator",
        )
        _, certificate, _ = enroll_agent(
            raw_token=token, csr_pem=pki_fixtures.create_csr()[1]
        )
        _, pending_token, _ = create_enrollment_token(
            tenant=self.tenant,
            display_name="Pending",
            actor="test-operator",
        )
        self.tenant.status = Tenant.Status.SUSPENDED
        self.tenant.save(update_fields=("status",))
        der = x509.load_pem_x509_certificate(certificate.encode()).public_bytes(
            serialization.Encoding.DER
        )
        with self.assertRaises(ValidationError):
            validate_peer_certificate(der)
        with self.assertRaises(ValidationError):
            enroll_agent(raw_token=pending_token, csr_pem=pki_fixtures.create_csr()[1])
        self.assertEqual(
            validate_peer_certificate(der, allow_suspended_report=True).id,
            enrollment.id,
        )
        with self.assertRaises(ValidationError):
            create_enrollment_token(
                tenant=self.tenant, display_name="Forbidden", actor="test-operator"
            )
        with self.assertRaises(ValidationError):
            services.renew_agent_certificate(
                enrollment=enrollment, csr_pem=pki_fixtures.create_csr()[1]
            )
        for function, arguments in (
            (services.confirm_inventory, {"inventory": {}, "agent_version": "0.2.26"}),
            (services.confirm_telemetry, {"telemetry": {}, "agent_version": "0.2.26"}),
            (
                services.confirm_software_inventory,
                {"document": {}, "agent_version": "0.2.26"},
            ),
            (services.confirm_heartbeat, {}),
        ):
            with (
                self.subTest(function=function.__name__),
                self.assertRaises(ValidationError),
            ):
                function(enrollment, **arguments)
        enrollment.refresh_from_db()
        self.assertIsNone(enrollment.last_heartbeat_at)

    def test_suspension_consumes_pending_token_permanently_but_preserves_active_identity(
        self,
    ):
        active, token, _ = create_enrollment_token(
            tenant=self.tenant, display_name="Active", actor="test-operator"
        )
        _, certificate, _ = enroll_agent(
            raw_token=token, csr_pem=pki_fixtures.create_csr()[1]
        )
        pending, pending_token, _ = create_enrollment_token(
            tenant=self.tenant, display_name="Pending", actor="test-operator"
        )
        with transaction.atomic():
            tenant = Tenant.objects.select_for_update(no_key=True).get(
                pk=self.tenant.id
            )
            tenant.status = "suspended"
            tenant.save(update_fields=("status",))
            apply_tenant_status_change(tenant, "active", "platform-admin")
        pending.refresh_from_db()
        self.assertEqual(pending.status, "removed")
        self.assertFalse(
            AgentEnrollmentToken.objects.filter(
                enrollment=pending, used_at__isnull=True
            ).exists()
        )
        Tenant.objects.filter(pk=self.tenant.id).update(status="active")
        with self.assertRaises(ValidationError):
            enroll_agent(raw_token=pending_token, csr_pem=pki_fixtures.create_csr()[1])
        der = x509.load_pem_x509_certificate(certificate.encode()).public_bytes(
            serialization.Encoding.DER
        )
        self.assertEqual(validate_peer_certificate(der).id, active.id)


class QueuedAuthorityTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="guard", display_name="Guard")
        self.user = get_user_model().objects.create_user("queued-owner")
        self.membership = TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.user,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            display_name="Agent",
            device_uri="urn:ipms:agent:11111111-1111-1111-1111-111111111111",
            status=AgentEnrollment.Status.ACTIVE,
        )

    def test_revoked_requester_cannot_receive_queued_lifecycle_job(self):
        from .lifecycle import offer_lifecycle_job

        job = AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="uninstall",
            requested_by=self.user.username,
        )
        self.membership.is_active = False
        self.membership.save(update_fields=("is_active",))
        self.assertIsNone(offer_lifecycle_job(self.enrollment))
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.membership.is_active = True
        self.membership.save(update_fields=("is_active",))
        self.assertIsNone(offer_lifecycle_job(self.enrollment))

    def action(self, *, status="queued", actor=None):
        return HyperVVirtualMachineActionJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="pause",
            status=status,
            vm_source_id=str(uuid.uuid4()),
            vm_name="Synthetic VM",
            requested_by=actor or self.user.username,
        )

    def suspend(self):
        with transaction.atomic():
            tenant = Tenant.objects.select_for_update(no_key=True).get(
                pk=self.tenant.id
            )
            tenant.status = "suspended"
            tenant.save(update_fields=("status",))
            return apply_tenant_status_change(tenant, "active", "platform-admin")

    def test_missing_and_platform_requesters_are_never_system_actors(self):
        from .lifecycle import offer_lifecycle_job
        from .hyperv_actions import offer_hyperv_action_job

        platform = get_user_model().objects.create_user("platform")
        PlatformAdministrator.objects.create(user=platform)
        for actor in ("alice-scheduler", platform.username):
            lifecycle = AgentLifecycleJob.objects.create(
                tenant=self.tenant,
                enrollment=self.enrollment,
                action="uninstall",
                requested_by=actor,
            )
            action = self.action(actor=actor)
            self.assertIsNone(offer_lifecycle_job(self.enrollment))
            self.assertIsNone(offer_hyperv_action_job(self.enrollment))
            for job in (lifecycle, action):
                job.refresh_from_db()
                self.assertEqual(job.status, "cancelled")
                self.assertIsNotNone(job.authority_revoked_at)

    def test_suspension_closes_sessions_cancels_queues_and_does_not_replay(self):
        from .lifecycle import offer_lifecycle_job
        from .hyperv_actions import offer_hyperv_action_job

        lifecycle = AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="uninstall",
            requested_by=self.user.username,
        )
        action = self.action()
        discovery = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type="ilo_redfish",
            requested_by=self.user.username,
        )
        deployment = WindowsAgentDeployment.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            requested_by=self.user.username,
            target_address="example.invalid",
        )
        WindowsAgentDeploymentSecret.objects.create(
            deployment=deployment,
            tenant=self.tenant,
            nonce=b"synthetic",
            ciphertext=b"synthetic",
        )
        console = HyperVConsoleSession.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            vm_source_id="test-vm",
            vm_name="Test",
            requested_by=self.user.username,
            frame_png=b"synthetic-frame",
            lease_expires_at=timezone.now() + timedelta(minutes=1),
            last_activity_at=timezone.now(),
        )
        other_tenant = Tenant.objects.create(
            slug="unaffected", display_name="Unaffected"
        )
        other = DiscoveryJob.objects.create(
            tenant=other_tenant, connector_type="ilo_redfish", requested_by="other"
        )
        self.suspend()
        for job, status in (
            (lifecycle, "cancelled"),
            (action, "cancelled"),
            (discovery, "failed"),
            (deployment, "failed"),
            (console, "closed"),
            (other, "queued"),
        ):
            job.refresh_from_db()
            self.assertEqual(job.status, status)
        self.assertEqual(bytes(console.frame_png), b"")
        self.assertFalse(
            WindowsAgentDeploymentSecret.objects.filter(deployment=deployment).exists()
        )
        self.assertEqual(self.suspend()["lifecycle_jobs"], 0)
        Tenant.objects.filter(pk=self.tenant.pk).update(status="active")
        self.assertIsNone(offer_lifecycle_job(self.enrollment))
        self.assertIsNone(offer_hyperv_action_job(self.enrollment))

    def test_delivered_jobs_only_settle_and_cannot_be_offered_or_downloaded(self):
        from .lifecycle import (
            offer_lifecycle_job,
            record_lifecycle_result,
            lifecycle_artifact,
        )
        from .hyperv_actions import offer_hyperv_action_job, record_hyperv_action_result

        lifecycle = AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="update",
            requested_by=self.user.username,
            status="delivered",
            artifact_sha256="a" * 64,
        )
        action = self.action(status="delivered")
        self.suspend()
        for job in (lifecycle, action):
            job.refresh_from_db()
            self.assertEqual(job.status, "delivered")
            self.assertIsNotNone(job.authority_revoked_at)
        self.assertIsNone(offer_lifecycle_job(self.enrollment))
        self.assertIsNone(offer_hyperv_action_job(self.enrollment))
        with (
            self.assertRaises(ValidationError),
            patch(
                "ipms.apps.agent_pki.lifecycle.current_windows_agent_artifact"
            ) as artifact,
        ):
            lifecycle_artifact(self.enrollment, job_id=str(lifecycle.id))
        artifact.assert_not_called()
        for job, recorder in (
            (lifecycle, record_lifecycle_result),
            (action, record_hyperv_action_result),
        ):
            recorder(
                self.enrollment,
                job_id=str(job.id),
                result="running",
                result_code="accepted",
            )
            recorder(
                self.enrollment,
                job_id=str(job.id),
                result="succeeded",
                result_code="completed",
            )
            job.refresh_from_db()
            self.assertEqual(job.status, "succeeded")
            self.assertIsNotNone(job.authority_revoked_at)
        Tenant.objects.filter(pk=self.tenant.pk).update(status="active")
        self.assertIsNone(offer_lifecycle_job(self.enrollment))
        self.assertIsNone(offer_hyperv_action_job(self.enrollment))

    def test_queued_job_cannot_claim_to_have_started(self):
        from .lifecycle import record_lifecycle_result
        from .hyperv_actions import record_hyperv_action_result

        lifecycle = AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="uninstall",
            requested_by=self.user.username,
        )
        for job, recorder in (
            (lifecycle, record_lifecycle_result),
            (self.action(), record_hyperv_action_result),
        ):
            with self.assertRaises(ValidationError):
                recorder(
                    self.enrollment,
                    job_id=str(job.id),
                    result="running",
                    result_code="accepted",
                )

    def test_discovery_unsupported_candidate_does_not_starve_supported_queue(self):
        from ipms.apps.discovery.services import process_discovery_queue

        unsupported = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type=DiscoveryJob.ConnectorType.HYPER_V,
            requested_by=self.user.username,
        )
        supported = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
            requested_by=self.user.username,
        )
        with patch("ipms.apps.discovery.services.process_discovery_job") as execute:
            self.assertEqual(process_discovery_queue(limit=1), 1)
        self.assertEqual(execute.call_args.args[0].id, supported.id)
        unsupported.refresh_from_db()
        self.assertEqual(unsupported.status, "queued")

    def test_workers_fail_closed_before_network_when_requester_is_revoked(self):
        from ipms.apps.discovery.services import (
            process_discovery_queue,
            process_discovery_job,
        )
        from .deployment import _claim_next_deployment, process_deployment

        self.membership.delete()
        discovery = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
            requested_by=self.user.username,
        )
        deployment = WindowsAgentDeployment.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            requested_by=self.user.username,
            target_address="example.invalid",
        )
        WindowsAgentDeploymentSecret.objects.create(
            deployment=deployment, tenant=self.tenant, nonce=b"test", ciphertext=b"test"
        )
        with (
            patch("ipms.apps.discovery.services.process_discovery_job") as discover,
            patch("ipms.apps.agent_pki.deployment.load_deployment_secret") as secret,
        ):
            self.assertEqual(process_discovery_queue(limit=1), 1)
            self.assertIsNone(_claim_next_deployment())
            discover.assert_not_called()
            secret.assert_not_called()
        for job in (discovery, deployment):
            job.refresh_from_db()
            self.assertEqual(job.status, "failed")
            self.assertEqual(job.error_code, "execution_authority_withdrawn")
        self.assertFalse(
            WindowsAgentDeploymentSecret.objects.filter(deployment=deployment).exists()
        )
        with (
            patch("ipms.apps.discovery.services._validate_private_target") as target,
            patch("ipms.apps.agent_pki.deployment.load_deployment_secret") as secret,
        ):
            process_discovery_job(discovery)
            process_deployment(deployment)
            target.assert_not_called()
            secret.assert_not_called()


class SuspendedDispatchLockTests(TransactionTestCase):
    setUp = QueuedAuthorityTests.setUp

    @skipUnless(
        connection.vendor == "postgresql", "Requires PostgreSQL row-lock semantics"
    )
    def test_suspension_fences_a_waiting_dispatch_before_it_can_deliver(self):
        from .lifecycle import offer_lifecycle_job

        job = AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="uninstall",
            requested_by=self.user.username,
        )
        ready = threading.Event()
        results = []
        backend_pid = []

        def offer():
            try:
                with connections["default"].cursor() as cursor:
                    cursor.execute("SELECT pg_backend_pid()")
                    backend_pid.append(cursor.fetchone()[0])
                ready.set()
                results.append(offer_lifecycle_job(self.enrollment))
            except Exception as error:
                results.append(error)
            finally:
                connections.close_all()

        worker = threading.Thread(target=offer, daemon=True)
        try:
            with transaction.atomic():
                tenant = Tenant.objects.select_for_update(no_key=True).get(
                    pk=self.tenant.id
                )
                worker.start()
                self.assertTrue(ready.wait(3))
                deadline = time.monotonic() + 3
                waiting = False
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                            [backend_pid[0]],
                        )
                        observed = cursor.fetchone()
                    if observed and observed[0] == "Lock":
                        waiting = True
                        break
                    time.sleep(0.025)
                self.assertTrue(
                    waiting, "Dispatch must wait on the existing tenant lock."
                )
                tenant.status = "suspended"
                tenant.save(update_fields=("status",))
                apply_tenant_status_change(tenant, "active", "platform-admin")
        finally:
            if worker.ident is not None:
                worker.join(5)
        self.assertFalse(
            worker.is_alive(), "The suspension/dispatch lock order must not deadlock."
        )
        self.assertEqual(results, [None])
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.assertIsNone(job.delivered_at)


class SuspendedGatewayTests(SimpleTestCase):
    async def test_legacy_connection_revalidates_after_first_message(self):
        reader = asyncio.StreamReader()
        message = (
            json.dumps(
                {"type": "telemetry", "device_uri": "test-device", "telemetry": {}}
            ).encode()
            + b"\n"
        )
        reader.feed_data(message * 2)
        reader.feed_eof()
        writer = ConsoleWriter()
        writer.get_extra_info = lambda name: (
            SimpleNamespace(
                selected_alpn_protocol=lambda: "ipms-agent/1",
                getpeercert=lambda **kwargs: b"certificate",
            )
            if name == "ssl_object"
            else None
        )
        ingested = 0

        async def call(function, *args, **kwargs):
            nonlocal ingested
            if function.__name__ == "validate_peer_certificate":
                if ingested:
                    raise ValidationError("tenant_inactive")
                return SimpleNamespace(device_uri="test-device")
            self.assertEqual(function.__name__, "confirm_telemetry")
            ingested += 1

        with patch.object(gateway, "_database_call_async", call):
            await gateway.handle_connection(reader, writer)
        self.assertEqual(ingested, 1)
        self.assertEqual(bytes(writer.output).count(b'"type":"accepted"'), 1)
        self.assertIn(b'"type":"rejected"', bytes(writer.output))
        self.assertTrue(writer.closed)

    async def test_suspended_http_exception_is_exact_report_only_and_never_offers_work(
        self,
    ):
        for path, kind, permitted in (
            ("/v1/lifecycle-result", "lifecycle_result", True),
            ("/v1/hyperv-action-result", "hyperv_action_result", True),
            ("/v1/lifecycle-result", "inventory", False),
            ("/v1/hyperv-console", "lifecycle_result", False),
            ("/v1/inventory", "inventory", False),
        ):
            reader = asyncio.StreamReader()
            reader.feed_data(
                request(
                    path=path,
                    type=kind,
                    job_id="synthetic",
                    result="running",
                    result_code="accepted",
                )
            )
            reader.feed_eof()
            writer = ConsoleWriter()
            calls = []

            async def call(function, *args, **kwargs):
                calls.append(function.__name__)
                if function.__name__ == "validate_peer_certificate":
                    self.assertEqual(
                        kwargs.get("allow_suspended_report", False), permitted
                    )
                    if not permitted:
                        raise ValidationError("tenant_inactive")
                    return SimpleNamespace(device_uri="test-device")
                self.assertIn(
                    function.__name__,
                    ("record_lifecycle_result", "record_hyperv_action_result"),
                )

            with patch.object(gateway, "_database_call_async", call):
                await gateway.handle_connection(reader, writer)
            self.assertIn(
                b"HTTP/1.1 200" if permitted else b"HTTP/1.1 400", bytes(writer.output)
            )
            self.assertEqual(len(calls), 2 if permitted else 1)
