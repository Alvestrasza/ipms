"""Existing Agent redeployment cannot bypass durable VM management fences."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
from unittest.mock import patch

from django.db import close_old_connections, connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from .deployment import _claim_next_deployment, process_deployment
from .hyperv_management import claim_management_job, offer_management_job
from .models import (
    AgentEnrollment,
    WindowsAgentDeployment,
    WindowsAgentDeploymentSecret,
)
from .test_hyperv_management import ManagementFixture


class MaintenanceFixture(ManagementFixture):
    def setUp(self):
        super().setUp()
        self.original = WindowsAgentDeployment.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            display_name="Existing host",
            target_address="management-alias.example.invalid",
            requested_by=self.actor.username,
            status="succeeded",
            completed_at=timezone.now(),
        )

    def pending(self, **changes):
        import uuid

        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri=f"urn:ipms:agent:{uuid.uuid4()}",
            display_name="Pending maintenance",
            platform="windows",
            status="pending",
        )
        return WindowsAgentDeployment.objects.create(
            tenant=self.tenant,
            enrollment=enrollment,
            display_name="Maintenance",
            target_address=changes.pop(
                "target_address", self.original.target_address.upper()
            ),
            requested_by=self.actor.username,
            **changes,
        )


class ManagementMaintenanceTests(MaintenanceFixture, TestCase):
    def test_generic_redeployment_cannot_claim_host_with_active_management(self):
        job = self.create()
        self.claim(job)
        pending = self.pending()
        WindowsAgentDeploymentSecret.objects.create(
            deployment=pending,
            tenant=self.tenant,
            nonce=b"fixture",
            ciphertext=b"fixture",
        )
        self.assertIsNone(_claim_next_deployment())
        pending.refresh_from_db()
        self.assertEqual(pending.status, "failed")
        self.assertEqual(pending.error_code, "agent_management_operation_pending")
        self.assertFalse(
            WindowsAgentDeploymentSecret.objects.filter(deployment=pending).exists()
        )

    def test_queued_and_running_endpoint_reservations_prevent_new_management(self):
        pending = self.pending()
        self.assert_denied("management_operation_conflict", self.create)
        claimed = _claim_next_deployment()
        self.assertEqual(claimed.pk, pending.pk)
        self.assert_denied("management_operation_conflict", self.create)
        pending.status = "failed"
        pending.save(update_fields=("status",))
        self.assertIsNotNone(self.create())

    def test_pending_deployment_prevents_a_previously_delivered_management_claim(self):
        job = self.create()
        offer_management_job(self.enrollment)
        self.pending()
        result = claim_management_job(self.enrollment, job.pk, job.input_digest)
        self.assertFalse(result["authorized"])
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")

    def test_worker_entry_rechecks_before_credentials_network_or_file_operations(self):
        job = self.create()
        self.claim(job)
        pending = self.pending(status="running")
        with patch("ipms.apps.agent_pki.deployment._artifact") as artifact, patch(
            "ipms.apps.agent_pki.deployment.load_deployment_secret"
        ) as secret:
            process_deployment(pending)
        artifact.assert_not_called()
        secret.assert_not_called()
        pending.refresh_from_db()
        self.assertEqual(pending.error_code, "agent_management_operation_pending")

    def test_direct_enrollment_bindings_are_reserved_without_address_match(self):
        self.pending(
            target_address="different.example.invalid",
            lifecycle_bootstrap_enrollment=self.enrollment,
        )
        self.assert_denied("management_operation_conflict", self.create)

    def test_unrelated_endpoint_does_not_block_management(self):
        self.pending(target_address="unrelated.example.invalid")
        self.assertIsNotNone(self.create())

    def test_inventory_endpoint_is_fail_closed_without_historical_deployment_match(
        self,
    ):
        job = self.create()
        self.claim(job)
        pending = self.pending(target_address=self.host.fqdn.upper())
        self.assertIsNone(_claim_next_deployment())
        pending.refresh_from_db()
        self.assertEqual(pending.error_code, "agent_management_operation_pending")

    def test_endpoint_match_never_blocks_another_tenant(self):
        from ipms.apps.tenancy.models import Tenant, TenantMembership

        other = Tenant.objects.create(slug="maintenance-other", display_name="Other")
        TenantMembership.objects.create(
            tenant=other, user=self.actor, role="tenant_admin"
        )
        pending = self.pending()
        pending.tenant = other
        pending.enrollment.tenant = other
        pending.enrollment.save(update_fields=("tenant",))
        pending.save(update_fields=("tenant",))
        self.assertIsNotNone(self.create())
        self.assertEqual(_claim_next_deployment().pk, pending.pk)


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks.")
class ManagementMaintenanceConcurrencyTests(MaintenanceFixture, TransactionTestCase):
    def test_queued_reservation_fences_both_simultaneous_claim_and_new_management(self):
        pending = self.pending()
        barrier = Barrier(2, timeout=10)

        def claim():
            close_old_connections()
            try:
                barrier.wait()
                return _claim_next_deployment().pk
            finally:
                close_old_connections()

        def management():
            close_old_connections()
            try:
                barrier.wait()
                self.assert_denied("management_operation_conflict", self.create)
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(claim)
            second = pool.submit(management)
            self.assertEqual(first.result(timeout=20), pending.pk)
            second.result(timeout=20)
