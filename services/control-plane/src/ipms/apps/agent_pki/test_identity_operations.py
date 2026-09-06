import uuid
from datetime import timedelta
from importlib import import_module
from types import SimpleNamespace

from django.conf import settings
from django.contrib.auth import get_user, get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import (
    DiscoveryJob,
    HyperVConsoleInputEvent,
    HyperVConsoleSession,
    HyperVVirtualMachineActionJob,
)
from ipms.apps.tenancy import operations
from ipms.apps.tenancy.models import Tenant, TenantMembership
from ipms.apps.tenancy.rbac import effective_tenant_permissions
from .models import (
    AgentEnrollment,
    AgentLifecycleJob,
    WindowsAgentDeployment,
    WindowsAgentDeploymentSecret,
)
from .test_native_console import NativeFixture
from .native_console import authorize_browser


class IdentityOperationWithdrawalTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(
            slug="identity-jobs", display_name="Identity jobs"
        )
        self.user = get_user_model().objects.create_user(
            "identity-owner", password="synthetic-password"
        )
        self.other = get_user_model().objects.create_user("identity-other")
        for user in (self.user, self.other):
            TenantMembership.objects.create(
                tenant=self.tenant, user=user, role="tenant_admin"
            )
        self.enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            display_name="Synthetic Agent",
            device_uri="urn:ipms:agent:" + str(uuid.uuid4()),
            status="active",
        )

    def withdraw(self, reason="username_changed"):
        with transaction.atomic():
            list(
                Tenant.objects.select_for_update(no_key=True)
                .filter(memberships__user=self.user)
                .order_by("id")
            )
            user = (
                get_user_model()
                .objects.select_for_update(no_key=True)
                .get(pk=self.user.pk)
            )
            return operations.withdraw_identity_operations(user, reason=reason)

    def lifecycle(self, *, status="queued", actor=None):
        return AgentLifecycleJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            action="uninstall",
            requested_by=actor or self.user.username,
            status=status,
        )

    def action(self, *, status="queued", actor=None):
        return HyperVVirtualMachineActionJob.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            vm_source_id=str(uuid.uuid4()),
            vm_name="Synthetic VM",
            requested_by=actor or self.user.username,
            action="pause",
            status=status,
        )

    def deployment(self, *, status="queued", actor=None):
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant,
            display_name="Deployment",
            device_uri="urn:ipms:agent:" + str(uuid.uuid4()),
        )
        job = WindowsAgentDeployment.objects.create(
            tenant=self.tenant,
            enrollment=enrollment,
            target_address="synthetic.example.invalid",
            requested_by=actor or self.user.username,
            status=status,
        )
        WindowsAgentDeploymentSecret.objects.create(
            tenant=self.tenant, deployment=job, nonce=b"test", ciphertext=b"test"
        )
        return job

    def console(
        self, *, owner=None, actor=None, status="active", transport="thumbnail"
    ):
        return HyperVConsoleSession.objects.create(
            tenant=self.tenant,
            enrollment=self.enrollment,
            owner=owner,
            requested_by=actor or self.user.username,
            vm_source_id=str(uuid.uuid4()),
            vm_name="Synthetic VM",
            transport=transport,
            status=status,
            lease_expires_at=timezone.now() + timedelta(minutes=1),
            last_activity_at=timezone.now(),
            frame_png=b"synthetic-private-frame",
        )

    def test_queued_operations_are_cancelled_without_changing_historical_actors(self):
        lifecycle, action = self.lifecycle(), self.action()
        discovery = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type="ilo_redfish",
            requested_by=self.user.username,
        )
        deployment = self.deployment()
        audit = AuditEvent.objects.create(
            tenant=self.tenant,
            actor=self.user.username,
            action="synthetic.history",
            outcome="succeeded",
        )
        snapshot = AuditEvent.objects.filter(pk=audit.pk).values().get()
        counts = self.withdraw()
        for job, status in (
            (lifecycle, "cancelled"),
            (action, "cancelled"),
            (discovery, "failed"),
            (deployment, "failed"),
        ):
            job.refresh_from_db()
            self.assertEqual(job.status, status)
            self.assertEqual(job.requested_by, "identity-owner")
            self.assertIsNotNone(job.completed_at)
        self.assertFalse(
            WindowsAgentDeploymentSecret.objects.filter(deployment=deployment).exists()
        )
        self.assertEqual(
            AuditEvent.objects.filter(pk=audit.pk).values().get(), snapshot
        )
        self.assertEqual(
            counts,
            {
                "discovery_jobs": 1,
                "deployments": 1,
                "lifecycle_jobs": 1,
                "vm_actions": 1,
                "console_sessions": 0,
                "console_inputs": 0,
                "management_jobs": 0,
            },
        )
        self.assertFalse(any(self.withdraw().values()))

    def test_management_authority_uses_immutable_actor_and_preserves_accepted_work(self):
        from ipms.apps.discovery.models import HyperVManagementJob

        jobs = []
        for status in ("queued", "delivered", "running", "requires_reconciliation"):
            jobs.append(HyperVManagementJob.objects.create(
                tenant=self.tenant, enrollment=self.enrollment, actor=self.user,
                requested_by="historical-name", operation="checkpoint_create",
                status=status, vm_source_id=str(uuid.uuid4()), vm_name="Synthetic VM",
                request_id=uuid.uuid4(),
                request_digest="a" * 64, input_digest="b" * 64,
                parameters={"policy": "configured"},
            ))
        counts = self.withdraw("password_reset")
        self.assertEqual(counts["management_jobs"], 4)
        for job, expected in zip(jobs, ("cancelled", "cancelled", "running", "requires_reconciliation")):
            job.refresh_from_db()
            self.assertEqual(job.status, expected)
            self.assertIsNotNone(job.authority_revoked_at)
            self.assertEqual(job.requested_by, "historical-name")
            self.assertEqual(job.actor_id, self.user.pk)
        self.assertEqual(self.withdraw("username_changed")["management_jobs"], 0)

    def test_delivered_and_running_jobs_remain_report_only_without_reoffer(self):
        from .lifecycle import offer_lifecycle_job, record_lifecycle_result
        from .hyperv_actions import offer_hyperv_action_job, record_hyperv_action_result

        lifecycle = self.lifecycle(status="delivered")
        action = self.action(status="running")
        self.withdraw("password_reset")
        for job, status in ((lifecycle, "delivered"), (action, "running")):
            job.refresh_from_db()
            self.assertEqual(job.status, status)
            self.assertEqual(job.result_code, "password_reset")
            self.assertIsNotNone(job.authority_revoked_at)
        self.assertIsNone(offer_lifecycle_job(self.enrollment))
        self.assertIsNone(offer_hyperv_action_job(self.enrollment))
        record_lifecycle_result(
            self.enrollment,
            job_id=str(lifecycle.id),
            result="running",
            result_code="accepted",
        )
        record_lifecycle_result(
            self.enrollment,
            job_id=str(lifecycle.id),
            result="succeeded",
            result_code="completed",
        )
        record_hyperv_action_result(
            self.enrollment,
            job_id=str(action.id),
            result="succeeded",
            result_code="completed",
        )
        for job in (lifecycle, action):
            job.refresh_from_db()
            self.assertEqual(job.status, "succeeded")
            self.assertIsNotNone(job.authority_revoked_at)

    def test_native_owner_and_legacy_name_close_and_clear_only_active_input_queues(
        self,
    ):
        legacy = self.console()
        native = self.console(
            owner=self.user, actor="historical-display-name", transport="vmconnect"
        )
        closed = self.console(status="closed")
        other = self.console(
            owner=self.other, actor=self.other.username, transport="vmconnect"
        )
        for session in (legacy, native, closed, other):
            HyperVConsoleInputEvent.objects.create(
                session=session,
                event_type="key",
                payload={"key_code": 65, "is_down": True},
            )
        counts = self.withdraw("password_changed")
        self.assertEqual(counts["console_sessions"], 2)
        self.assertEqual(counts["console_inputs"], 2)
        for session in (legacy, native):
            session.refresh_from_db()
            self.assertEqual(session.status, "closed")
            self.assertEqual(bytes(session.frame_png), b"")
            self.assertEqual(session.failure_code, "password_changed")
            self.assertFalse(session.input_events.exists())
        for session, status in ((closed, "closed"), (other, "active")):
            session.refresh_from_db()
            self.assertEqual(session.status, status)
            self.assertEqual(bytes(session.frame_png), b"synthetic-private-frame")
            self.assertTrue(session.input_events.exists())

    def test_unrelated_users_and_terminal_history_are_unchanged(self):
        own_completed = self.lifecycle(status="succeeded")
        other = self.lifecycle(actor=self.other.username)
        completed_action = self.action(status="failed")
        running_deployment = self.deployment(status="running")
        other_deployment = self.deployment(actor=self.other.username)
        foreign_tenant = Tenant.objects.create(
            slug="foreign-identity", display_name="Foreign identity"
        )
        foreign = DiscoveryJob.objects.create(
            tenant=foreign_tenant,
            connector_type="ilo_redfish",
            requested_by=self.other.username,
        )
        completed_discovery = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type="ilo_redfish",
            requested_by=self.user.username,
            status="succeeded",
        )
        records = (
            own_completed,
            other,
            completed_action,
            running_deployment,
            other_deployment,
            foreign,
            completed_discovery,
        )
        before = [
            (record, type(record).objects.filter(pk=record.pk).values().get())
            for record in records
        ]
        permissions = effective_tenant_permissions(self.user, self.tenant)
        self.withdraw()
        for record, snapshot in before:
            self.assertEqual(
                type(record).objects.filter(pk=record.pk).values().get(), snapshot
            )
        self.assertTrue(
            WindowsAgentDeploymentSecret.objects.filter(
                deployment=running_deployment
            ).exists()
        )
        self.assertTrue(
            WindowsAgentDeploymentSecret.objects.filter(
                deployment=other_deployment
            ).exists()
        )
        self.assertEqual(
            effective_tenant_permissions(self.user, self.tenant), permissions
        )

    def test_invalid_reason_cannot_change_any_operation(self):
        job = self.lifecycle()
        with self.assertRaises(ValidationError):
            self.withdraw("unbounded-user-input")
        job.refresh_from_db()
        self.assertEqual(job.status, "queued")

    def test_failed_identity_transaction_rolls_back_withdrawal_and_secret_cleanup(self):
        job = self.lifecycle()
        deployment = self.deployment()
        session = self.console()
        with self.assertRaises(RuntimeError):
            with transaction.atomic():
                self.withdraw()
                raise RuntimeError("Synthetic identity persistence failure")
        for record, status in (
            (job, "queued"),
            (deployment, "queued"),
            (session, "active"),
        ):
            record.refresh_from_db()
            self.assertEqual(record.status, status)
        self.assertIsNone(job.authority_revoked_at)
        self.assertTrue(
            WindowsAgentDeploymentSecret.objects.filter(deployment=deployment).exists()
        )
        self.assertEqual(bytes(session.frame_png), b"synthetic-private-frame")


class IdentityOperationTransactionTests(SimpleTestCase):
    def test_hook_rejects_calls_without_an_identity_transaction(self):
        with self.assertRaisesMessage(ValidationError, "identity_transaction_required"):
            operations.withdraw_identity_operations(
                SimpleNamespace(pk=1, get_username=lambda: "synthetic"),
                reason="username_changed",
            )


class IdentityNativeSessionTests(NativeFixture, TestCase):
    def test_password_reset_invalidates_cookie_independently_of_console_closure(self):
        session = self.native_session()
        authorize_browser(str(session.id), self.cookie, attach=True)
        with transaction.atomic():
            Tenant.objects.select_for_update(no_key=True).get(pk=self.tenant.id)
            user = (
                get_user_model()
                .objects.select_for_update(no_key=True)
                .get(pk=self.user.id)
            )
            operations.withdraw_identity_operations(user, reason="password_reset")
            user.set_password("synthetic-new-password")
            user.save(update_fields=("password",))
        session.refresh_from_db()
        self.assertEqual(session.status, "closed")
        fresh = self.native_session()
        with self.assertRaises(ValidationError):
            authorize_browser(str(fresh.id), self.cookie, attach=True)

    def test_username_change_preserves_immutable_login_but_closes_console(self):
        session = self.native_session()
        with transaction.atomic():
            Tenant.objects.select_for_update(no_key=True).get(pk=self.tenant.id)
            user = (
                get_user_model()
                .objects.select_for_update(no_key=True)
                .get(pk=self.user.id)
            )
            operations.withdraw_identity_operations(user, reason="username_changed")
            user.username = "native-renamed"
            user.save(update_fields=("username",))
        store = import_module(settings.SESSION_ENGINE).SessionStore(
            session_key=self.cookie
        )
        authenticated = get_user(SimpleNamespace(session=store))
        self.assertEqual(authenticated.pk, self.user.pk)
        self.assertEqual(authenticated.username, "native-renamed")
        session.refresh_from_db()
        self.assertEqual(session.status, "closed")
        self.assertEqual(session.requested_by, "native-admin")
