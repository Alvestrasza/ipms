"""Management operations exercise real tenant, enrollment and job boundaries."""

from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
import uuid
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection, transaction
from django.test import Client, TestCase, TransactionTestCase
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import (
    HyperVConsoleSession,
    HyperVManagementJob,
    HyperVManagementSnapshot,
    HyperVVirtualMachine,
    WindowsServer,
)
from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership
from .hyperv_management import (
    active_management_jobs,
    claim_management_job,
    create_management_job,
    management_job_status,
    management_payload,
    offer_management_job,
    record_management_result,
    withdraw_management_jobs,
)
from .hyperv_management_schema import validate_snapshot
from .models import AgentEnrollment, AgentLifecycleJob


class ManagementFixture:
    def setUp(self):
        super().setUp()
        self.actor = get_user_model().objects.create_user(
            "management-admin", password="Disposable-management-password-49!"
        )
        self.tenant = Tenant.objects.create(
            slug="management", display_name="Management"
        )
        self.member = TenantMembership.objects.create(
            tenant=self.tenant, user=self.actor, role="tenant_admin"
        )
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:11111111-1111-4111-8111-111111111111",
            display_name="Management host",
            platform="windows",
            status="active",
            last_heartbeat_at=timezone.now(),
        )
        self.host = WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=self.enrollment.device_uri,
            inventory_source="agent",
            server_type="physical",
            hostname="management-host",
            fqdn="management-host.example.invalid",
            operating_system="Microsoft Windows Server",
            hyperv_inventory_status="collected",
            agent_version="0.2.27",
            agent_state="online",
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.vm = HyperVVirtualMachine.objects.create(
            tenant=self.tenant,
            host=self.host,
            source_id="22222222-2222-4222-8222-222222222222",
            name="Disposable management VM",
            state="running",
            observed_at=timezone.now(),
        )
        self.client.force_login(self.actor)

    def endpoint(self, suffix=""):
        return f"/api/v1/hyper-v/virtual-machines/{self.vm.pk}/management/{suffix}"

    def headers(self):
        return {"HTTP_X_IPMS_TENANT_ID": str(self.tenant.pk)}

    def snapshot(self):
        return {
            "schema_version": 1,
            "vm_source_id": self.vm.source_id,
            "vm_name": self.vm.name,
            "state": "running",
            "revision": "a" * 64,
            "settings": {
                "name": self.vm.name,
                "notes": "Disposable fixture only",
                "configuration_version": "12.0",
                "generation": 2,
                "processor": {
                    "count": 2,
                    "reservation_milli_percent": 0,
                    "limit_milli_percent": 100000,
                    "weight": 100,
                    "compatibility_for_migration": False,
                },
                "memory": {
                    "startup_mib": 2048,
                    "minimum_mib": 512,
                    "maximum_mib": 4096,
                    "dynamic_enabled": True,
                    "buffer_percent": 20,
                    "weight": 5000,
                },
                "automatic_start_action": 2,
                "automatic_start_delay": None,
                "automatic_stop_action": 4,
                "checkpoint_policy": 5,
            },
            "checkpoints": [],
            "devices": {"network_adapters": [], "storage": []},
            "capabilities": {
                "inspect": True,
                "checkpoint_create": True,
                "checkpoint_delete": True,
                "checkpoint_apply": True,
                "settings_update": False,
            },
            "collection_status": {
                "settings": "collected",
                "checkpoints": "collected",
                "devices": "not-reported",
            },
        }

    def create(self, operation="inspect", parameters=None, **changes):
        return create_management_job(
            virtual_machine=self.vm,
            actor=self.actor,
            request_id=changes.pop("request_id", uuid.uuid4()),
            operation=operation,
            expected_revision=changes.pop(
                "expected_revision", "" if operation == "inspect" else "a" * 64
            ),
            parameters=parameters
            or ({} if operation == "inspect" else {"policy": "configured"}),
            **changes,
        )

    def claim(self, job):
        offer = offer_management_job(self.enrollment)
        self.assertEqual(offer["job_id"], str(job.pk))
        return claim_management_job(self.enrollment, job.pk, job.input_digest)

    def complete(self, job, *, snapshot=None, **changes):
        return record_management_result(
            self.enrollment,
            job_id=job.pk,
            status=changes.pop("status", "succeeded"),
            phase=changes.pop("phase", "completed"),
            progress=changes.pop("progress", 100),
            result_code=changes.pop("result_code", "completed"),
            snapshot=snapshot,
            **changes,
        )

    def inspect(self, document=None):
        job = self.create()
        self.claim(job)
        self.complete(job, snapshot=document or self.snapshot())
        return job

    def checkpoint(self, suffix="1", parent_id=None):
        return {
            "id": f"33333333-3333-4333-8333-{int(suffix):012d}",
            "parent_id": parent_id,
            "name": "Checkpoint " + suffix,
            "created_at": "2026-09-06T09:00:00Z",
            "type": "unknown",
            "is_current": False,
            "can_apply": True,
            "can_delete": True,
        }

    def assert_denied(self, code, call, *args, **kwargs):
        with self.assertRaises(PublicApiError) as caught:
            call(*args, **kwargs)
        self.assertEqual(caught.exception.public_code, code)


class ManagementContractTests(ManagementFixture, TestCase):
    def test_public_refresh_claim_result_and_snapshot_reload(self):
        request_id = str(uuid.uuid4())
        response = self.client.post(
            self.endpoint("refresh/"),
            {"request_id": request_id},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 202, response.content)
        job = HyperVManagementJob.objects.get(pk=response.json()["id"])
        page = self.client.get(self.endpoint(), **self.headers()).json()
        self.assertEqual(page["active_operation"]["id"], str(job.pk))
        offer = offer_management_job(self.enrollment)
        self.assertEqual(offer["mode"], "claim")
        self.assertNotIn("authorized", offer)
        granted = claim_management_job(self.enrollment, job.pk, job.input_digest)
        self.assertTrue(granted["authorized"])
        self.assertEqual(granted["lease_seconds"], 15)
        job.refresh_from_db()
        self.assertEqual(
            job.execution_lease_expires_at - job.started_at, timedelta(seconds=15)
        )
        self.complete(job, snapshot=self.snapshot())
        page = self.client.get(self.endpoint(), **self.headers()).json()
        self.assertTrue(page["fresh"])
        self.assertEqual(page["snapshot"]["revision"], "a" * 64)
        self.assertIsNone(page["active_operation"])
        self.assertEqual(page["latest_operation"]["id"], str(job.pk))
        self.assertEqual(page["latest_operation"]["status"], "succeeded")
        self.assertNotIn("input_digest", response.json())
        self.assertNotIn("parameters", response.json())

    def test_idempotent_request_id_binds_actor_tenant_vm_and_inputs(self):
        request_id = uuid.uuid4()
        first = self.create(request_id=request_id)
        self.assertEqual(self.create(request_id=request_id).pk, first.pk)
        self.assertEqual(
            AuditEvent.objects.filter(action="hyperv.management.queue").count(), 1
        )
        self.assert_denied(
            "management_request_conflict",
            self.create,
            "checkpoint_create",
            request_id=request_id,
        )
        other = get_user_model().objects.create_user("second-management-admin")
        TenantMembership.objects.create(
            user=other, tenant=self.tenant, role="tenant_admin"
        )
        self.assert_denied(
            "management_request_conflict",
            create_management_job,
            virtual_machine=self.vm,
            actor=other,
            request_id=request_id,
            operation="inspect",
        )

    def test_second_claim_observes_and_never_regrants_execution(self):
        job = self.create()
        self.assertTrue(self.claim(job)["authorized"])
        again = claim_management_job(self.enrollment, job.pk, job.input_digest)
        self.assertFalse(again["authorized"])
        self.assertEqual(again["mode"], "observe")
        self.assertEqual(
            AuditEvent.objects.filter(action="hyperv.management.claim").count(), 1
        )

    def test_journal_lookup_is_read_only_and_requires_exact_agent_binding(self):
        job = self.create()
        audit_count = AuditEvent.objects.count()
        self.assertEqual(
            management_job_status(self.enrollment, job.pk)["mode"], "queued"
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "queued")
        self.assertIsNone(job.delivered_at)
        self.assertEqual(AuditEvent.objects.count(), audit_count)
        self.assert_denied(
            "invalid_request",
            management_job_status,
            self.enrollment,
            str(job.pk).upper(),
        )
        self.assert_denied(
            "management_job_not_found",
            management_job_status,
            self.enrollment,
            uuid.uuid4(),
        )
        self.claim(job)
        self.tenant.status = "suspended"
        self.tenant.save(update_fields=("status",))
        self.assertEqual(
            management_job_status(self.enrollment, job.pk)["mode"], "observe"
        )
        self.complete(job, status="failed", result_code="provider_failed")
        self.assertEqual(
            management_job_status(self.enrollment, job.pk)["mode"], "failed"
        )
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(status="revoked")
        self.assert_denied(
            "management_agent_unavailable",
            management_job_status,
            self.enrollment,
            job.pk,
        )

    def test_cancelled_journal_lookup_does_not_authorize_after_tenant_reactivation(
        self,
    ):
        job = self.create()
        with transaction.atomic():
            Tenant.objects.select_for_update(no_key=True).get(pk=self.tenant.pk)
            withdraw_management_jobs(tenant_id=self.tenant.pk)
        result = management_job_status(self.enrollment, job.pk)
        self.assertEqual(result["mode"], "cancelled")
        self.assertNotIn("authorized", result)
        self.assert_denied(
            "management_job_not_claimable",
            claim_management_job,
            self.enrollment,
            job.pk,
            job.input_digest,
        )

    def test_claim_digest_invalid_uuid_and_result_before_claim_fail_closed(self):
        job = self.create()
        offer_management_job(self.enrollment)
        self.assert_denied(
            "management_input_mismatch",
            claim_management_job,
            self.enrollment,
            job.pk,
            "b" * 64,
        )
        self.assert_denied(
            "invalid_request",
            claim_management_job,
            self.enrollment,
            "not-a-uuid",
            job.input_digest,
        )
        self.assert_denied(
            "management_result_transition_invalid",
            self.complete,
            job,
            snapshot=self.snapshot(),
        )
        self.assert_denied(
            "invalid_request",
            record_management_result,
            self.enrollment,
            job_id="not-a-uuid",
            status="succeeded",
            phase="completed",
            progress=100,
            result_code="completed",
            snapshot=self.snapshot(),
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "delivered")

    def test_identical_terminal_result_retry_has_no_extra_audit_or_freshness(self):
        job = self.create()
        self.claim(job)
        document = self.snapshot()
        self.complete(job, snapshot=document)
        first = HyperVManagementSnapshot.objects.get(virtual_machine=self.vm)
        audit_count = AuditEvent.objects.count()
        self.complete(job, snapshot=deepcopy(document))
        current = HyperVManagementSnapshot.objects.get(virtual_machine=self.vm)
        self.assertEqual(current.observed_at, first.observed_at)
        self.assertEqual(current.updated_at, first.updated_at)
        self.assertEqual(AuditEvent.objects.count(), audit_count)
        self.assert_denied(
            "management_result_conflict",
            self.complete,
            job,
            snapshot=document,
            result_code="different_result",
        )

    def test_delayed_result_does_not_freshen_old_inspection(self):
        job = self.create()
        self.claim(job)
        HyperVManagementJob.objects.filter(pk=job.pk).update(
            started_at=timezone.now() - timedelta(seconds=61)
        )
        self.complete(job, snapshot=self.snapshot())
        self.assertFalse(management_payload(self.vm)["fresh"])
        self.assert_denied(
            "management_snapshot_stale", self.create, "checkpoint_create"
        )

    def test_no_snapshot_no_revision_or_false_capability_cannot_mutate(self):
        self.assert_denied(
            "management_snapshot_stale", self.create, "checkpoint_create"
        )
        document = self.snapshot()
        document["capabilities"]["checkpoint_create"] = False
        self.inspect(document)
        self.assert_denied(
            "management_operation_unsupported", self.create, "checkpoint_create"
        )
        self.assert_denied(
            "management_revision_changed",
            self.create,
            "checkpoint_create",
            expected_revision="b" * 64,
        )
        self.assert_denied(
            "invalid_request",
            self.create,
            "checkpoint_create",
            expected_revision="12.0",
        )
        self.assert_denied(
            "invalid_request",
            self.create,
            "settings_update",
            parameters={"section": "processor", "count": 8},
        )

    def test_typed_checkpoint_parameters_confirmation_and_descendant_ack(self):
        document = self.snapshot()
        parent = self.checkpoint()
        child = self.checkpoint("2", parent["id"])
        document["checkpoints"] = [parent, child]
        self.inspect(document)
        self.assert_denied(
            "invalid_request",
            self.create,
            "checkpoint_create",
            parameters={"policy": "configured", "script": "forbidden"},
        )
        self.assert_denied(
            "management_checkpoint_tree_changed",
            self.create,
            "checkpoint_delete",
            parameters={
                "checkpoint_id": parent["id"],
                "acknowledged_checkpoint_ids": [parent["id"]],
            },
        )
        self.assert_denied(
            "management_confirmation_mismatch",
            self.create,
            "checkpoint_apply",
            parameters={
                "checkpoint_id": parent["id"],
                "confirmation_vm_name": "Wrong VM",
                "confirmation_checkpoint_name": parent["name"],
            },
        )
        job = self.create(
            "checkpoint_delete",
            parameters={
                "checkpoint_id": parent["id"],
                "acknowledged_checkpoint_ids": [child["id"], parent["id"]],
            },
        )
        self.assertEqual(
            job.parameters["acknowledged_checkpoint_ids"],
            sorted([child["id"], parent["id"]]),
        )
        self.assertTrue(self.claim(job)["authorized"])

    def test_checkpoint_apply_blocks_open_console_but_inspection_does_not(self):
        document = self.snapshot()
        checkpoint = self.checkpoint()
        document["checkpoints"] = [checkpoint]
        console = HyperVConsoleSession.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            virtual_machine=self.vm,
            vm_source_id=self.vm.source_id,
            vm_name=self.vm.name,
            requested_by=self.actor.username,
            last_activity_at=timezone.now(),
            lease_expires_at=timezone.now() + timedelta(seconds=30),
        )
        self.inspect(document)
        parameters = {
            "checkpoint_id": checkpoint["id"],
            "confirmation_vm_name": self.vm.name,
            "confirmation_checkpoint_name": checkpoint["name"],
        }
        self.assert_denied(
            "management_console_active",
            self.create,
            "checkpoint_apply",
            parameters=parameters,
        )
        console.status = "closed"
        console.save(update_fields=("status",))
        self.assertTrue(
            self.claim(self.create("checkpoint_apply", parameters=parameters))[
                "authorized"
            ]
        )

    def test_snapshot_and_vm_are_rechecked_at_claim_not_only_submission(self):
        self.inspect()
        job = self.create("checkpoint_create")
        offer_management_job(self.enrollment)
        HyperVManagementSnapshot.objects.filter(virtual_machine=self.vm).update(
            observed_at=timezone.now() - timedelta(seconds=61)
        )
        result = claim_management_job(self.enrollment, job.pk, job.input_digest)
        self.assertFalse(result["authorized"])
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(job.result_code, "management_snapshot_stale")

    def test_old_lifecycle_and_new_management_jobs_conflict_both_directions(self):
        from .hyperv_actions import create_hyperv_action_job

        old = create_hyperv_action_job(
            virtual_machine=self.vm, action="pause", actor=self.actor.username
        )
        self.assert_denied("management_operation_conflict", self.create)
        old.status = "failed"
        old.save(update_fields=("status",))
        self.create()
        from django.core.exceptions import ValidationError

        with self.assertRaises(ValidationError):
            create_hyperv_action_job(
                virtual_machine=self.vm, action="pause", actor=self.actor.username
            )

    def test_requires_reconciliation_blocks_reexecution_and_conflicting_jobs(self):
        job = self.create()
        self.claim(job)
        self.complete(
            job,
            status="requires_reconciliation",
            progress=None,
            result_code="provider_outcome_unknown",
        )
        self.assertTrue(
            active_management_jobs(self.tenant.pk).filter(pk=job.pk).exists()
        )
        self.assert_denied("management_operation_conflict", self.create)
        self.assertEqual(offer_management_job(self.enrollment)["mode"], "observe")
        self.assertFalse(
            claim_management_job(self.enrollment, job.pk, job.input_digest)[
                "authorized"
            ]
        )
        self.assert_denied(
            "management_result_transition_invalid",
            self.complete,
            job,
            status="running",
            progress=40,
        )

    def test_withdrawn_started_work_remains_observable_without_inventory_mutation(self):
        job = self.create()
        self.claim(job)
        with transaction.atomic():
            Tenant.objects.select_for_update(no_key=True).get(pk=self.tenant.pk)
            self.assertEqual(
                withdraw_management_jobs(
                    tenant_id=self.tenant.pk,
                    actor_id=self.actor.pk,
                    reason="password_changed",
                ),
                1,
            )
        self.assertEqual(offer_management_job(self.enrollment)["mode"], "observe")
        self.complete(job, snapshot=self.snapshot())
        job.refresh_from_db()
        self.assertEqual(job.status, "succeeded")
        self.assertIsNotNone(job.authority_revoked_at)
        self.assertFalse(
            HyperVManagementSnapshot.objects.filter(virtual_machine=self.vm).exists()
        )

    def test_current_actor_permission_and_suspended_tenant_prevent_execution(self):
        job = self.create()
        offer_management_job(self.enrollment)
        self.member.is_active = False
        self.member.save(update_fields=("is_active",))
        result = claim_management_job(self.enrollment, job.pk, job.input_digest)
        self.assertFalse(result["authorized"])
        job.refresh_from_db()
        self.assertIsNotNone(job.authority_revoked_at)
        self.member.is_active = True
        self.member.save(update_fields=("is_active",))
        self.assert_denied(
            "management_job_not_claimable",
            claim_management_job,
            self.enrollment,
            job.pk,
            job.input_digest,
        )
        second = self.create()
        self.tenant.status = "suspended"
        self.tenant.save(update_fields=("status",))
        self.assertIsNone(offer_management_job(self.enrollment))
        second.refresh_from_db()
        self.assertEqual(second.status, "cancelled")

    def test_new_permissions_not_inherited_by_operator_and_cross_tenant_hidden(self):
        self.inspect()
        self.member.role = "operator"
        self.member.save(update_fields=("role",))
        document = {
            "request_id": str(uuid.uuid4()),
            "operation": "checkpoint_create",
            "expected_revision": "a" * 64,
            "parameters": {"policy": "configured"},
        }
        response = self.client.post(
            self.endpoint("operations/"),
            document,
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "forbidden")
        other = Tenant.objects.create(slug="management-other", display_name="Other")
        TenantMembership.objects.create(
            tenant=other, user=self.actor, role="tenant_admin"
        )
        response = self.client.get(self.endpoint(), HTTP_X_IPMS_TENANT_ID=str(other.pk))
        self.assertEqual(response.status_code, 404)
        platform = get_user_model().objects.create_user("management-platform")
        PlatformAdministrator.objects.create(user=platform)
        self.client.force_login(platform)
        self.assertEqual(
            self.client.get(self.endpoint(), **self.headers()).status_code, 404
        )

    def test_cookie_mutations_require_csrf_and_forbidden_fields_rejected(self):
        protected = Client(enforce_csrf_checks=True)
        protected.force_login(self.actor)
        response = protected.post(
            self.endpoint("refresh/"),
            {"request_id": str(uuid.uuid4())},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 403)
        response = self.client.post(
            self.endpoint("refresh/"),
            {"request_id": str(uuid.uuid4()), "vm_source_id": str(uuid.uuid4())},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 400)

    def test_old_offline_wrong_platform_or_revoked_agent_cannot_receive_jobs(self):
        job = self.create()
        self.host.agent_version = "0.2.26"
        self.host.save(update_fields=("agent_version",))
        self.assertIsNone(offer_management_job(self.enrollment))
        self.assert_denied(
            "management_agent_upgrade_required",
            claim_management_job,
            self.enrollment,
            job.pk,
            job.input_digest,
        )
        self.host.agent_version = "0.2.27"
        self.host.save(update_fields=("agent_version",))
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(
            last_heartbeat_at=timezone.now() - timedelta(minutes=5)
        )
        self.assertIsNone(offer_management_job(self.enrollment))
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(status="revoked")
        self.assert_denied(
            "management_agent_unavailable", self.complete, job, snapshot=self.snapshot()
        )

    def test_result_is_bound_to_original_agent_and_requires_snapshot_for_success(self):
        job = self.create()
        self.claim(job)
        self.assert_denied("management_snapshot_required", self.complete, job)
        other = AgentEnrollment.objects.create(
            tenant=self.tenant,
            device_uri="urn:ipms:agent:99999999-9999-4999-8999-999999999999",
            display_name="Other",
            platform="windows",
            status="active",
        )
        WindowsServer.objects.create(
            tenant=self.tenant,
            source_id=other.device_uri,
            inventory_source="agent",
            hostname="other",
            agent_version="0.2.27",
            discovered_at=timezone.now(),
            last_seen_at=timezone.now(),
        )
        self.assert_denied(
            "management_job_not_found",
            claim_management_job,
            other,
            job.pk,
            job.input_digest,
        )
        self.assert_denied(
            "management_job_not_found", management_job_status, other, job.pk
        )
        self.assert_denied(
            "management_job_not_found",
            record_management_result,
            other,
            job_id=job.pk,
            status="succeeded",
            phase="completed",
            progress=100,
            result_code="completed",
            snapshot=self.snapshot(),
        )
        document = self.snapshot()
        document["vm_source_id"] = str(uuid.uuid4())
        self.assert_denied(
            "management_snapshot_identity_mismatch",
            self.complete,
            job,
            snapshot=document,
        )

    def test_false_provider_section_and_checkpoint_flags_cannot_authorize(self):
        document = self.snapshot()
        document["collection_status"]["checkpoints"] = "unavailable"
        self.inspect(document)
        self.assert_denied(
            "management_snapshot_unavailable", self.create, "checkpoint_create"
        )
        document = self.snapshot()
        checkpoint = self.checkpoint()
        checkpoint["can_apply"] = False
        checkpoint["can_delete"] = False
        document["checkpoints"] = [checkpoint]
        self.inspect(document)
        self.assert_denied(
            "management_operation_unsupported",
            self.create,
            "checkpoint_apply",
            parameters={
                "checkpoint_id": checkpoint["id"],
                "confirmation_vm_name": self.vm.name,
                "confirmation_checkpoint_name": checkpoint["name"],
            },
        )
        self.assert_denied(
            "management_operation_unsupported",
            self.create,
            "checkpoint_delete",
            parameters={
                "checkpoint_id": checkpoint["id"],
                "acknowledged_checkpoint_ids": [checkpoint["id"]],
            },
        )

    def test_result_rejects_boolean_progress_and_noncanonical_job_identity(self):
        job = self.create()
        self.claim(job)
        self.assert_denied(
            "invalid_request",
            self.complete,
            job,
            snapshot=self.snapshot(),
            progress=True,
        )
        self.assert_denied(
            "invalid_request",
            claim_management_job,
            self.enrollment,
            "{" + str(job.pk) + "}",
            job.input_digest,
        )
        self.assert_denied(
            "invalid_request",
            record_management_result,
            self.enrollment,
            job_id=str(job.pk).replace("-", ""),
            status="succeeded",
            phase="completed",
            progress=100,
            result_code="completed",
            snapshot=self.snapshot(),
        )

    def test_agent_lifecycle_job_blocks_new_management_and_fresh_claim(self):
        lifecycle = AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            requested_by=self.actor.username,
            action="update",
        )
        self.assert_denied("management_operation_conflict", self.create)
        lifecycle.status = "succeeded"
        lifecycle.save(update_fields=("status",))
        job = self.create()
        offer_management_job(self.enrollment)
        lifecycle.status = "running"
        lifecycle.save(update_fields=("status",))
        result = claim_management_job(self.enrollment, job.pk, job.input_digest)
        self.assertFalse(result["authorized"])
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(job.result_code, "management_operation_conflict")

    def test_schema_rejects_arbitrary_objects_duplicates_cycles_and_false_empty_devices(
        self,
    ):
        valid = self.snapshot()
        self.assertEqual(validate_snapshot(valid), valid)
        invalid_documents = []
        document = deepcopy(valid)
        document["settings"]["wmi_path"] = "not-an-execution-selector"
        invalid_documents.append(document)
        document = deepcopy(valid)
        document["settings"]["processor"]["count"] = True
        invalid_documents.append(document)
        document = deepcopy(valid)
        document["capabilities"]["checkpoint_apply"] = "true"
        invalid_documents.append(document)
        document = deepcopy(valid)
        document["collection_status"]["devices"] = "collected"
        invalid_documents.append(document)
        document = deepcopy(valid)
        document["checkpoints"] = [self.checkpoint(), self.checkpoint()]
        invalid_documents.append(document)
        document = deepcopy(valid)
        item = self.checkpoint()
        item["parent_id"] = item["id"]
        document["checkpoints"] = [item]
        invalid_documents.append(document)
        document = deepcopy(valid)
        document["settings"]["notes"] = "x" * 50000
        invalid_documents.append(document)
        document = deepcopy(valid)
        item = self.checkpoint()
        item["created_at"] = "2026-99-99T00:00:00Z"
        document["checkpoints"] = [item]
        invalid_documents.append(document)
        for document in invalid_documents:
            self.assert_denied("invalid_request", validate_snapshot, document)


class ManagementBaselineTests(ManagementFixture, TestCase):
    def test_inspector_reports_not_reported_instead_of_fabricating_settings(self):
        response = self.client.get(self.endpoint(), **self.headers())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(response.json()["snapshot"])
        self.assertEqual(response.json()["collection_status"], "not-reported")
        self.assertIsNone(response.json()["latest_operation"])


class ManagementSettingsTests(ManagementFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.vm.state = "stopped"
        self.vm.save(update_fields=("state",))

    def snapshot(self):
        document = super().snapshot()
        document["state"] = "stopped"
        document["capabilities"]["settings_update"] = True
        return document

    def parameters(self, section="general"):
        return {
            "section": section,
            "values": {
                "general": {"name": "Renamed disposable VM", "notes": "Revised notes"},
                "processor": {"count": 4},
                "memory": {
                    "startup_mib": 4096,
                    "minimum_mib": 1024,
                    "maximum_mib": 8192,
                    "dynamic_enabled": True,
                },
            }[section],
        }

    def test_general_rename_requires_exact_success_observation_and_preserves_job_identity(
        self,
    ):
        self.inspect()
        old_name = self.vm.name
        parameters = self.parameters()
        job = self.create("settings_update", parameters=parameters)
        self.assertTrue(self.claim(job)["authorized"])
        self.assert_denied(
            "management_snapshot_identity_mismatch",
            self.complete,
            job,
            snapshot=self.snapshot(),
        )
        document = self.snapshot()
        document["vm_name"] = parameters["values"]["name"]
        document["settings"].update(parameters["values"])
        document["revision"] = "b" * 64
        self.complete(job, snapshot=document)
        self.vm.refresh_from_db()
        job.refresh_from_db()
        self.assertEqual(self.vm.name, parameters["values"]["name"])
        self.assertEqual(job.vm_name, old_name)
        self.assertEqual(job.parameters, parameters)
        self.assertEqual(management_payload(self.vm)["snapshot"]["revision"], "b" * 64)
        count = AuditEvent.objects.count()
        self.complete(job, snapshot=document)
        self.assertEqual(AuditEvent.objects.count(), count)

    def test_failed_rename_does_not_change_inventory_and_non_settings_cannot_rename(
        self,
    ):
        self.inspect()
        old_name = self.vm.name
        job = self.create("settings_update", parameters=self.parameters())
        self.claim(job)
        self.complete(
            job,
            snapshot=self.snapshot(),
            status="failed",
            result_code="provider_failed",
        )
        self.vm.refresh_from_db()
        self.assertEqual(self.vm.name, old_name)
        other = self.create()
        self.claim(other)
        document = self.snapshot()
        document["vm_name"] = "Unrequested rename"
        self.assert_denied(
            "management_snapshot_identity_mismatch",
            self.complete,
            other,
            snapshot=document,
        )

    def test_settings_require_own_permission_provider_capability_and_stopped_state(
        self,
    ):
        self.inspect()
        self.member.role = "operator"
        self.member.save(update_fields=("role",))
        response = self.client.post(
            self.endpoint("operations/"),
            {
                "request_id": str(uuid.uuid4()),
                "operation": "settings_update",
                "expected_revision": "a" * 64,
                "parameters": self.parameters(),
            },
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 403)
        self.member.role = "tenant_admin"
        self.member.save(update_fields=("role",))
        document = self.snapshot()
        document["capabilities"]["settings_update"] = False
        self.inspect(document)
        self.assert_denied(
            "management_operation_unsupported",
            self.create,
            "settings_update",
            parameters=self.parameters(),
        )
        self.vm.state = "running"
        self.vm.save(update_fields=("state",))
        document = self.snapshot()
        document["state"] = "running"
        self.inspect(document)
        self.assert_denied(
            "management_vm_must_be_stopped",
            self.create,
            "settings_update",
            parameters=self.parameters(),
        )

    def test_settings_do_not_require_a_collected_checkpoint_tree(self):
        document = self.snapshot()
        document["collection_status"]["checkpoints"] = "unavailable"
        self.inspect(document)
        job = self.create("settings_update", parameters=self.parameters("processor"))
        self.assertTrue(self.claim(job)["authorized"])
        document["settings"]["processor"]["count"] = 4
        self.complete(job, snapshot=document)

    def test_typed_settings_reject_missing_extra_and_out_of_range_values(self):
        from .hyperv_management_schema import validate_parameters

        invalid_parameters = [
            {"section": "processor", "values": {"count": True}},
            {"section": "processor", "values": {"count": 0}},
            {"section": "processor", "values": {"count": 2049}},
            {
                "section": "processor",
                "values": {"count": 4, "wmi_property": "forbidden"},
            },
            {"section": "general", "values": {"name": " ", "notes": ""}},
            {"section": "general", "values": {"name": "VM\nother", "notes": ""}},
            {"section": "general", "values": {"name": "VM", "notes": "x" * 4097}},
            {"section": "general", "values": {"name": "VM", "notes": "\u00e9" * 2049}},
            {"section": "general", "values": {"name": "x" * 101, "notes": ""}},
            {"section": "general", "values": {"name": "\U0001f600" * 51, "notes": ""}},
            {"section": "general", "values": {"name": "\u754c" * 86, "notes": ""}},
            {"section": "general", "values": {"name": "\ud800", "notes": ""}},
            {"section": "general", "values": {"name": "VM", "notes": "\ud800"}},
            {"section": "general", "values": {"name": "VM"}},
            {"section": "network", "values": {}},
            {"section": "processor", "values": {"count": 4}, "stop_first": True},
        ]
        for key, value in (
            ("startup_mib", 0),
            ("minimum_mib", 8192),
            ("maximum_mib", 1024),
            ("maximum_mib", 2**40 + 1),
            ("dynamic_enabled", "true"),
        ):
            parameters = self.parameters("memory")
            parameters["values"][key] = value
            invalid_parameters.append(parameters)
        for parameters in invalid_parameters:
            self.assert_denied(
                "invalid_request", validate_parameters, "settings_update", parameters
            )
        for section in ("general", "processor", "memory"):
            parameters = self.parameters(section)
            self.assertEqual(
                validate_parameters("settings_update", parameters), parameters
            )

    def test_memory_section_updates_only_its_single_typed_object(self):
        self.inspect()
        parameters = self.parameters("memory")
        job = self.create("settings_update", parameters=parameters)
        self.claim(job)
        document = self.snapshot()
        document["settings"]["memory"].update(parameters["values"])
        self.complete(job, snapshot=document)
        self.vm.refresh_from_db()
        self.assertEqual(self.vm.name, job.vm_name)
        self.assertEqual(
            management_payload(self.vm)["snapshot"]["settings"]["memory"][
                "startup_mib"
            ],
            4096,
        )

    def test_success_without_requested_section_values_is_not_recorded_as_completed(
        self,
    ):
        for section in ("general", "processor", "memory"):
            self.inspect()
            parameters = self.parameters(section)
            job = self.create("settings_update", parameters=parameters)
            self.claim(job)
            document = self.snapshot()
            if section == "general":
                document["vm_name"] = parameters["values"]["name"]
                document["settings"]["name"] = parameters["values"]["name"]
            before_audit = AuditEvent.objects.count()
            self.assert_denied(
                "management_snapshot_postcondition_mismatch",
                self.complete,
                job,
                snapshot=document,
            )
            job.refresh_from_db()
            self.assertEqual(job.status, "running")
            self.assertIsNone(job.completed_at)
            self.assertEqual(AuditEvent.objects.count(), before_audit)
            self.complete(
                job, status="failed", result_code="provider_postcondition_failed"
            )


class LiveSettingsContractTests(ManagementFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.host.agent_version = "0.2.28"
        self.host.save(update_fields=("agent_version",))

    def snapshot(self):
        document = super().snapshot()
        document["schema_version"] = 2
        document["capabilities"]["settings_update"] = True
        return document

    def parameters(self, section="general", values=None):
        return {
            "section": section,
            "values": values or {"notes": "Updated online"},
            "expected_state": "running",
        }

    def test_online_notes_patch_survives_queue_claim_and_exact_result_without_rename(
        self,
    ):
        self.inspect()
        parameters = self.parameters()
        response = self.client.post(
            self.endpoint("operations/"),
            {
                "request_id": str(uuid.uuid4()),
                "operation": "settings_update",
                "expected_revision": "a" * 64,
                "parameters": parameters,
            },
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 202, response.content)
        job = HyperVManagementJob.objects.get(pk=response.json()["id"])
        self.assertEqual(job.parameters, parameters)
        self.assertTrue(self.claim(job)["authorized"])
        document = self.snapshot()
        document["settings"]["notes"] = "Updated online"
        self.complete(job, snapshot=document)
        job.refresh_from_db()
        self.vm.refresh_from_db()
        self.assertEqual(job.status, "succeeded")
        self.assertEqual(self.vm.state, "running")
        self.assertEqual(self.vm.name, job.vm_name)

    def test_online_memory_patch_cannot_report_success_after_power_change(self):
        self.inspect()
        parameters = self.parameters("memory", {"maximum_mib": 8192})
        job = self.create("settings_update", parameters=parameters)
        self.claim(job)
        document = self.snapshot()
        document["settings"]["memory"]["maximum_mib"] = 8192
        document["state"] = "stopped"
        self.assert_denied(
            "management_snapshot_postcondition_mismatch",
            self.complete,
            job,
            snapshot=document,
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "running")
        document["state"] = "running"
        self.complete(job, snapshot=document)

    def test_upgrade_gate_and_forbidden_live_fields_are_enforced_on_server(self):
        self.inspect()
        self.host.agent_version = "0.2.27"
        self.host.save(update_fields=("agent_version",))
        self.assert_denied(
            "management_agent_upgrade_required",
            self.create,
            "settings_update",
            parameters=self.parameters(),
        )
        self.host.agent_version = "0.2.28"
        self.host.save(update_fields=("agent_version",))
        self.assert_denied(
            "management_setting_not_editable",
            self.create,
            "settings_update",
            parameters=self.parameters("processor", {"count": 8}),
        )

    def test_revoked_permission_and_changed_state_prevent_delivery(self):
        self.inspect()
        job = self.create("settings_update", parameters=self.parameters())
        self.vm.state = "stopped"
        self.vm.save(update_fields=("state",))
        self.assertIsNone(offer_management_job(self.enrollment))
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")
        self.vm.state = "running"
        self.vm.save(update_fields=("state",))
        self.inspect()
        job = self.create("settings_update", parameters=self.parameters())
        self.member.role = "read_only"
        self.member.save(update_fields=("role",))
        self.assertIsNone(offer_management_job(self.enrollment))
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks.")
class ManagementConcurrencyTests(ManagementFixture, TransactionTestCase):
    def parallel(self, first, second):
        barrier = Barrier(2, timeout=10)

        def run(operation):
            close_old_connections()
            try:
                barrier.wait()
                return operation()
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(run, operation) for operation in (first, second)]
            return [future.result(timeout=20) for future in pending]

    def test_simultaneous_claims_grant_exactly_one_execution_lease(self):
        job = self.create()
        offer_management_job(self.enrollment)
        call = lambda: claim_management_job(self.enrollment, job.pk, job.input_digest)
        results = self.parallel(call, call)
        self.assertEqual(sorted(item["authorized"] for item in results), [False, True])
        self.assertEqual({item["mode"] for item in results}, {"execute", "observe"})
        self.assertEqual(
            AuditEvent.objects.filter(action="hyperv.management.claim").count(), 1
        )

    def test_old_power_and_new_management_creation_share_one_conflict_lock(self):
        from .hyperv_actions import create_hyperv_action_job

        def management():
            try:
                self.create()
                return "management_created"
            except PublicApiError as exc:
                self.assertEqual(exc.public_code, "management_operation_conflict")
                return "conflict"

        def power():
            try:
                create_hyperv_action_job(
                    virtual_machine=self.vm, action="pause", actor=self.actor.username
                )
                return "power_created"
            except ValidationError as exc:
                self.assertIn("management operation is already active", str(exc))
                return "conflict"

        results = self.parallel(management, power)
        self.assertEqual(results.count("conflict"), 1, results)
        self.assertEqual(sum(item.endswith("_created") for item in results), 1, results)
