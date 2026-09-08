"""Public dialog lifecycle, automatic inspection, and exclusive settings ownership."""

from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest import skipUnless
import uuid

from django.contrib.auth import get_user_model
from django.db import connection, close_old_connections
from django.test import Client, TestCase, TransactionTestCase
from django.utils import timezone

from ipms.apps.discovery.models import HyperVManagementJob, HyperVSettingsLease
from ipms.apps.tenancy.models import TenantMembership
from .hyperv_management import settings_dialog
from .test_hyperv_management import ManagementFixture


class SettingsDialogTests(ManagementFixture, TestCase):
    def dialog(self, action="open", *, client=None, dialog_id=None, edit=True):
        return (client or self.client).post(
            self.endpoint("dialog/"),
            {
                "action": action,
                "dialog_id": str(dialog_id or self.dialog_id),
                "edit": edit,
            },
            content_type="application/json",
            **self.headers(),
        )

    def setUp(self):
        super().setUp()
        self.dialog_id = uuid.uuid4()

    def test_open_automatically_inspects_and_is_idempotent(self):
        first = self.dialog()
        self.assertEqual(first.status_code, 200, first.content)
        self.assertTrue(first.json()["edit_lock"]["owned"])
        self.assertEqual(first.json()["inspection"]["operation"], "inspect")
        self.assertNotIn(str(self.dialog_id), first.content.decode())
        history = self.client.get(self.endpoint(), **self.headers())
        self.assertNotIn(str(self.dialog_id), history.content.decode())
        second = self.dialog()
        self.assertEqual(
            first.json()["inspection"]["id"], second.json()["inspection"]["id"]
        )
        self.assertEqual(HyperVManagementJob.objects.count(), 1)

    def test_second_dialog_of_same_user_is_read_only_and_shares_inspection(self):
        first = self.dialog().json()
        second = self.dialog(dialog_id=uuid.uuid4())
        self.assertEqual(second.status_code, 200, second.content)
        lock = second.json()["edit_lock"]
        self.assertFalse(lock["owned"])
        self.assertEqual(lock["owner_username"], self.actor.username)
        self.assertNotIn("dialog_id", lock)
        self.assertEqual(first["inspection"]["id"], second.json()["inspection"]["id"])

    def test_same_token_in_different_login_session_does_not_own_lock(self):
        self.dialog()
        other = Client()
        other.force_login(self.actor)
        self.assertFalse(
            self.dialog("renew", client=other).json()["edit_lock"]["owned"]
        )
        self.dialog("release", client=other)
        self.assertTrue(self.dialog("renew").json()["edit_lock"]["owned"])

    def test_release_and_expiry_never_let_old_dialog_release_successor(self):
        self.dialog()
        self.dialog("release")
        successor = uuid.uuid4()
        self.assertTrue(self.dialog(dialog_id=successor).json()["edit_lock"]["owned"])
        self.dialog("release")
        self.assertTrue(
            self.dialog("renew", dialog_id=successor).json()["edit_lock"]["owned"]
        )
        HyperVSettingsLease.objects.update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertFalse(
            self.dialog("renew", dialog_id=successor).json()["edit_lock"]["owned"]
        )
        self.assertTrue(self.dialog().json()["edit_lock"]["owned"])

    def test_revoked_permission_releases_owner_and_viewers_do_not_lock(self):
        self.dialog()
        self.member.role = "reader"
        self.member.save(update_fields=("role",))
        response = self.dialog("renew")
        self.assertFalse(response.json()["edit_lock"]["owned"])
        self.assertIsNone(response.json()["edit_lock"]["owner_username"])
        response = self.dialog(dialog_id=uuid.uuid4(), edit=False)
        self.assertEqual(response.status_code, 200, response.content)
        self.assertIsNone(response.json()["edit_lock"]["owner_username"])

    def test_unrelated_tenant_cannot_observe_owner(self):
        self.dialog()
        outsider = get_user_model().objects.create_user("outsider")
        self.client.force_login(outsider)
        response = self.dialog("renew")
        self.assertIn(response.status_code, (403, 404))
        self.assertNotIn(self.actor.username, response.content.decode())

    def test_open_requires_csrf_and_conflicting_write_does_not_leave_a_lock(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.actor)
        self.assertEqual(self.dialog(client=csrf_client).status_code, 403)
        self.assertEqual(HyperVManagementJob.objects.count(), 0)
        self.inspect()
        write = self.create("checkpoint_create")
        response = self.dialog()
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["error"]["code"], "management_operation_conflict")
        self.assertFalse(HyperVSettingsLease.objects.exists())
        write.refresh_from_db()
        self.assertEqual(write.status, "queued")

    def test_settings_post_without_dialog_lease_is_rejected(self):
        response = self.client.post(
            self.endpoint("operations/"),
            {
                "request_id": str(uuid.uuid4()),
                "operation": "settings_update",
                "expected_revision": "a" * 64,
                "parameters": {
                    "section": "general",
                    "values": {"notes": "changed"},
                    "expected_state": "running",
                },
            },
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(HyperVManagementJob.objects.count(), 0)

    def test_only_owner_can_queue_settings_and_close_does_not_cancel_accepted_job(self):
        self.host.agent_version = "0.2.28"
        self.host.save(update_fields=("agent_version",))
        opened = self.dialog().json()
        inspection = HyperVManagementJob.objects.get(pk=opened["inspection"]["id"])
        self.claim(inspection)
        snapshot = self.snapshot()
        snapshot["schema_version"] = 2
        snapshot["capabilities"]["settings_update"] = True
        self.complete(inspection, snapshot=snapshot)
        payload = {
            "request_id": str(uuid.uuid4()),
            "operation": "settings_update",
            "settings_dialog_id": str(uuid.uuid4()),
            "expected_revision": "a" * 64,
            "parameters": {
                "section": "general",
                "expected_state": "running",
                "values": {"notes": "Authorized live edit"},
            },
        }
        response = self.client.post(
            self.endpoint("operations/"),
            payload,
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["error"]["code"], "management_settings_locked")
        payload["settings_dialog_id"] = str(self.dialog_id)
        response = self.client.post(
            self.endpoint("operations/"),
            payload,
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 202, response.content)
        job = HyperVManagementJob.objects.get(pk=response.json()["id"])
        self.dialog("release")
        self.assertTrue(self.claim(job)["authorized"])
        # Replaying an accepted operation observes its result without a new lease/job.
        replay = self.client.post(
            self.endpoint("operations/"),
            payload,
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(replay.status_code, 202, replay.content)
        self.assertEqual(replay.json()["id"], str(job.pk))
        self.assertEqual(HyperVManagementJob.objects.count(), 2)

    def test_other_user_sees_only_current_owner_and_cannot_release(self):
        self.dialog()
        colleague = get_user_model().objects.create_user("another-editor")
        TenantMembership.objects.create(
            tenant=self.tenant, user=colleague, role="tenant_admin"
        )
        other = Client()
        other.force_login(colleague)
        state = self.dialog(client=other, dialog_id=uuid.uuid4()).json()
        self.assertEqual(state["edit_lock"]["owner_username"], self.actor.username)
        self.assertFalse(state["edit_lock"]["owned"])
        self.dialog("release", client=other)
        self.assertTrue(self.dialog("renew").json()["edit_lock"]["owned"])


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks")
class SettingsDialogConcurrencyTests(ManagementFixture, TransactionTestCase):
    def test_concurrent_dialogs_have_one_owner_and_one_inspection(self):
        barrier = Barrier(2)

        def open_dialog(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                return settings_dialog(
                    virtual_machine=self.vm,
                    actor=self.actor,
                    session_key=f"disposable-session-{index}",
                    dialog_id=uuid.uuid4(),
                    action="open",
                    edit=True,
                )
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(open_dialog, range(2)))
        self.assertEqual(sum(item["edit_lock"]["owned"] for item in results), 1)
        self.assertEqual(len({item["inspection"]["id"] for item in results}), 1)
        self.assertEqual(HyperVManagementJob.objects.count(), 1)
