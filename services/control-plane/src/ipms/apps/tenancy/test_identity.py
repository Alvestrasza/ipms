"""Identity mutation boundary tests use disposable local account passwords only."""

import threading
import time
import uuid
from importlib import import_module
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import HASH_SESSION_KEY, get_user_model
from django.contrib.auth.hashers import make_password
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import close_old_connections, connection, migrations, transaction
from django.db.migrations.executor import MigrationExecutor
from django.db.migrations.exceptions import IrreversibleError
from django.test import Client, TestCase, TransactionTestCase, override_settings

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from .identity import create_local_user, normalize_username
from .models import (
    ExternalIdentity,
    PlatformAdministrator,
    Tenant,
    TenantMembership,
    UsernameReservation,
)


class OwnIdentityBaselineTests(TestCase):
    def test_local_account_without_tenant_can_rename_without_losing_session(self):
        user = get_user_model().objects.create_user(
            "identity-before", password="Disposable-actor-password-93!"
        )
        self.client.force_login(user)
        response = self.client.post(
            "/api/v1/auth/account/rename/",
            {
                "username": "identity-after",
                "current_password": "Disposable-actor-password-93!",
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json(),
            {"username": "identity-after", "reauthentication_required": False},
        )
        self.assertTrue(
            self.client.get("/api/v1/auth/session/").json()["authenticated"]
        )


class IdentityFixture:
    password = "Disposable-actor-password-93!"
    target_password = "Disposable-target-password-52!"
    new_password = "Disposable-new-password-24!"

    def setUp(self):
        super().setUp()
        self.tenant = Tenant.objects.create(
            slug="identity-main", display_name="Identity main"
        )
        self.actor = create_local_user(
            username="identity-admin", password=self.password
        )
        self.target = create_local_user(
            username="identity-target", password=self.target_password
        )
        self.admin_membership = TenantMembership.objects.create(
            user=self.actor, tenant=self.tenant, role="tenant_admin"
        )
        self.membership = TenantMembership.objects.create(
            user=self.target, tenant=self.tenant, role="reader"
        )
        self.client.force_login(self.actor)

    def mutate(self, action, *, own=False, client=None, membership=None, **data):
        endpoint = (
            f"/api/v1/auth/account/{action}/"
            if own
            else f"/api/v1/auth/users/{(membership or self.membership).pk}/{action}/"
        )
        return (client or self.client).post(
            endpoint,
            {"current_password": self.password, **data},
            content_type="application/json",
            HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk),
        )

    def assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status, response.content)
        self.assertEqual(response.json()["error"]["code"], code)
        self.assertNotIn(self.password, response.content.decode())
        self.assertNotIn(self.new_password, response.content.decode())


class IdentityApiTests(IdentityFixture, TestCase):
    @override_settings(
        PASSWORD_HASHERS=[
            "django.contrib.auth.hashers.PBKDF2PasswordHasher",
            "django.contrib.auth.hashers.MD5PasswordHasher",
        ]
    )
    def test_verification_of_legacy_actor_hash_does_not_invalidate_retained_session(self):
        legacy_hash = make_password(self.password, hasher="md5")
        self.actor.password = legacy_hash
        self.actor.save(update_fields=("password",))
        self.client.force_login(self.actor)
        for action, data in (
            ("rename", {"own": True, "username": "retained-session-admin"}),
            ("password", {"new_password": self.new_password}),
        ):
            response = self.mutate(action, **data)
            self.assertEqual(response.status_code, 200, response.content)
            self.assertFalse(response.json()["reauthentication_required"])
            self.actor.refresh_from_db()
            self.assertEqual(self.actor.password, legacy_hash)
            self.assertTrue(
                self.client.get("/api/v1/auth/session/").json()["authenticated"]
            )

    def test_account_capabilities_for_platform_ordinary_suspended_and_unassigned(self):
        platform = create_local_user(
            username="identity-platform", password=self.password
        )
        PlatformAdministrator.objects.create(user=platform)
        orphan = create_local_user(
            username="identity-unassigned", password=self.password
        )
        self.tenant.status = "suspended"
        self.tenant.save(update_fields=("status",))
        for user in (self.actor, platform, orphan):
            self.client.force_login(user)
            response = self.client.get("/api/v1/auth/account/")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.json(),
                {
                    "username": user.username,
                    "display_name": user.username,
                    "authentication_source": "local",
                    "can_rename": True,
                    "can_change_password": True,
                },
            )
            self.assertEqual(
                self.mutate(
                    "rename", own=True, username=user.username + "-new"
                ).status_code,
                200,
            )
        flagged = get_user_model().objects.create_user(
            "identity-flagged", password=self.password, is_staff=True
        )
        self.client.force_login(flagged)
        self.assert_error(self.client.get("/api/v1/auth/account/"), 403, "forbidden")

    def test_own_password_logs_out_all_sessions_and_requires_new_password(self):
        other = Client()
        other.force_login(self.actor)
        old_hash = self.actor.password
        response = self.mutate("password", own=True, new_password=self.new_password)
        self.assertEqual(response.json(), {"reauthentication_required": True})
        for client in (self.client, other):
            self.assertFalse(
                client.get("/api/v1/auth/session/").json()["authenticated"]
            )
        self.actor.refresh_from_db()
        self.assertNotEqual(self.actor.password, old_hash)
        self.assertTrue(self.actor.check_password(self.new_password))
        self.assertFalse(
            self.client.login(username=self.actor.username, password=self.password)
        )
        self.assertTrue(
            self.client.login(username=self.actor.username, password=self.new_password)
        )

    def test_other_user_reset_requires_actor_password_and_keeps_actor_session(self):
        target_clients = [Client(), Client()]
        for client in target_clients:
            client.force_login(self.target)
        wrong = self.mutate(
            "password",
            current_password=self.target_password,
            new_password=self.new_password,
        )
        self.assert_error(wrong, 403, "current_password_invalid")
        response = self.mutate("password", new_password=self.new_password)
        self.assertEqual(response.json(), {"reauthentication_required": False})
        self.assertTrue(
            self.client.get("/api/v1/auth/session/").json()["authenticated"]
        )
        for client in target_clients:
            self.assertFalse(
                client.get("/api/v1/auth/session/").json()["authenticated"]
            )
        self.target.refresh_from_db()
        self.assertTrue(self.target.check_password(self.new_password))

    def test_rename_target_retains_stable_id_and_reserves_old_name(self):
        old_id = self.target.pk
        response = self.mutate("rename", username="identity-renamed")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["user"]["username"], "identity-renamed")
        self.assertFalse(response.json()["reauthentication_required"])
        self.target.refresh_from_db()
        self.assertEqual(self.target.pk, old_id)
        self.assertTrue(self.target.check_password(self.target_password))
        self.assertEqual(
            UsernameReservation.objects.filter(user=self.target).count(), 2
        )
        self.assert_error(
            self.mutate("rename", username="IDENTITY-TARGET"),
            409,
            "username_unavailable",
        )
        self.assertEqual(
            self.mutate("rename", username="IDENTITY-RENAMED").status_code, 200
        )

    def test_tenant_payload_capabilities_and_self_reset_denied(self):
        response = self.client.get(
            "/api/v1/auth/users/", HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk)
        )
        by_name = {item["username"]: item for item in response.json()}
        self.assertTrue(by_name[self.actor.username]["can_rename"])
        self.assertFalse(by_name[self.actor.username]["can_reset_password"])
        self.assertTrue(by_name[self.target.username]["can_reset_password"])
        self.assert_error(
            self.mutate(
                "password",
                membership=self.admin_membership,
                new_password=self.new_password,
            ),
            409,
            "self_password_reset_denied",
        )
        self.assertEqual(
            self.mutate(
                "rename",
                membership=self.admin_membership,
                username="identity-admin-renamed",
            ).status_code,
            200,
        )

    def test_operator_and_cross_tenant_targets_cannot_be_managed(self):
        self.admin_membership.role = "operator"
        self.admin_membership.save(update_fields=("role",))
        self.assert_error(
            self.mutate("rename", username="denied-name"), 403, "forbidden"
        )
        self.admin_membership.role = "tenant_admin"
        self.admin_membership.save(update_fields=("role",))
        foreign = Tenant.objects.create(slug="identity-other", display_name="Other")
        foreign_member = TenantMembership.objects.create(
            user=self.target, tenant=foreign, role="reader", is_active=False
        )
        self.assert_error(
            self.mutate("rename", membership=foreign_member, username="denied-name"),
            404,
            "user_not_found",
        )
        for action, data in (
            ("rename", {"username": "denied-name"}),
            ("password", {"new_password": self.new_password}),
        ):
            self.assert_error(
                self.mutate(action, **data), 409, "shared_identity_protected"
            )
        items = self.client.get(
            "/api/v1/auth/users/", HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk)
        ).json()
        row = next(item for item in items if item["username"] == self.target.username)
        self.assertFalse(row["can_rename"])
        self.assertFalse(row["can_reset_password"])

    def test_inactive_and_external_or_hybrid_identities_are_not_reset(self):
        self.target.is_active = False
        self.target.save(update_fields=("is_active",))
        self.assert_error(
            self.mutate("password", new_password=self.new_password),
            409,
            "user_inactive",
        )
        self.target.is_active = True
        self.target.save(update_fields=("is_active",))
        external = ExternalIdentity.objects.create(
            user=self.target,
            issuer="https://identity.example.invalid",
            subject="disposable",
        )
        for usable in (True, False):
            if not usable:
                self.target.set_unusable_password()
                self.target.save(update_fields=("password",))
            self.assert_error(
                self.mutate("password", new_password=self.new_password),
                409,
                "external_identity_managed",
            )
            self.assert_error(
                self.mutate("rename", username="external-renamed"),
                409,
                "external_identity_managed",
            )
            self.client.force_login(self.target)
            account = self.client.get("/api/v1/auth/account/").json()
            self.assertEqual(
                account["authentication_source"], "hybrid" if usable else "oidc"
            )
            self.assertFalse(account["can_rename"])
            self.assert_error(
                self.mutate("rename", own=True, username="external-renamed"),
                409,
                "external_identity_managed",
            )
            self.client.force_login(self.actor)
        external.is_active = False
        external.save(update_fields=("is_active",))
        self.target.set_password(self.target_password)
        self.target.save(update_fields=("password",))
        self.assertEqual(self.mutate("rename", username="local-again").status_code, 200)

    def test_platform_identity_is_hidden_even_with_malformed_tenant_membership(self):
        platform = create_local_user(username="platform-hidden", password=self.password)
        PlatformAdministrator.objects.create(user=platform)
        member = TenantMembership(tenant=self.tenant, user=platform, role="reader")
        TenantMembership.objects.bulk_create([member])
        self.assert_error(
            self.mutate("rename", membership=member, username="denied-platform"),
            404,
            "user_not_found",
        )

    def test_reauthentication_denial_audited_without_secrets_or_mutation(self):
        for action, data in (
            ("rename", {"username": "never-created"}),
            ("password", {"new_password": self.new_password}),
        ):
            response = self.mutate(
                action, current_password="Wrong-fixture-secret!", **data
            )
            self.assert_error(response, 403, "current_password_invalid")
        events = AuditEvent.objects.filter(action__startswith="identity.account.")
        self.assertEqual(events.count(), 2)
        self.assertTrue(all(item.outcome == "denied" for item in events))
        self.assertTrue(
            all(item.details["actor_user_id"] == str(self.actor.pk) for item in events)
        )
        self.assertNotIn("Wrong-fixture-secret!", str(list(events.values())))
        self.assertNotIn(self.new_password, str(list(events.values())))
        self.target.refresh_from_db()
        self.assertEqual(self.target.username, "identity-target")
        self.assertTrue(self.target.check_password(self.target_password))
        self.assertFalse(
            UsernameReservation.objects.filter(pk="never-created").exists()
        )

    def test_current_session_hash_and_fresh_actor_password_are_checked_after_locks(
        self,
    ):
        from . import identity

        original = identity.locked_identities

        def reset_before_lock(*args, **kwargs):
            other = get_user_model().objects.get(pk=self.actor.pk)
            other.set_password(self.new_password)
            other.save(update_fields=("password",))
            return original(*args, **kwargs)

        with patch.object(identity, "locked_identities", side_effect=reset_before_lock):
            response = self.mutate("rename", username="must-not-rename")
        self.assert_error(response, 403, "current_password_invalid")
        self.target.refresh_from_db()
        self.assertEqual(self.target.username, "identity-target")

    def test_fresh_actor_authority_is_checked_after_tenant_lock(self):
        from . import identity

        original = identity.locked_identities

        def revoke_before_lock(*args, **kwargs):
            TenantMembership.objects.filter(pk=self.admin_membership.pk).update(
                role="reader"
            )
            return original(*args, **kwargs)

        with patch.object(
            identity, "locked_identities", side_effect=revoke_before_lock
        ):
            self.assert_error(
                self.mutate("rename", username="must-not-rename"), 403, "forbidden"
            )

    def test_password_policy_and_unexpected_fields_have_static_errors(self):
        for value in ("short", "123456789012", self.target_password):
            self.assert_error(
                self.mutate("password", new_password=value), 400, "weak_password"
            )
        for action, data in (
            ("rename", {"username": "valid-name", "is_staff": True}),
            (
                "password",
                {"new_password": self.new_password, "user_id": self.target.pk},
            ),
            ("password", {"new_password": "x" * 1025}),
            ("rename", {"username": "not a username"}),
            ("password", {"new_password": "a\x00" + "b" * 20}),
        ):
            self.assert_error(self.mutate(action, **data), 400, "invalid_request")

    def test_cookie_mutations_require_csrf_and_valid_token_succeeds(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.actor)
        for own in (False, True):
            for action, data in (
                ("rename", {"username": "csrf-renamed"}),
                ("password", {"new_password": self.new_password}),
            ):
                self.assert_error(
                    self.mutate(action, own=own, client=client, **data),
                    403,
                    "forbidden",
                )
        token = client.get("/api/v1/auth/session/").json()["csrf_token"]
        response = client.post(
            "/api/v1/auth/account/rename/",
            {"current_password": self.password, "username": "csrf-valid"},
            content_type="application/json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(response.status_code, 200)

    def test_rename_and_password_call_withdrawal_under_atomic_before_change(self):
        from . import operations

        original = operations.withdraw_identity_operations
        seen = []

        def inspect(user, *, reason):
            self.assertTrue(connection.in_atomic_block)
            seen.append((user.pk, user.username, reason))
            return original(user, reason=reason)

        with patch.object(
            operations, "withdraw_identity_operations", side_effect=inspect
        ):
            self.assertEqual(
                self.mutate("rename", username="renamed-target").status_code, 200
            )
            self.assertEqual(
                self.mutate("password", new_password=self.new_password).status_code, 200
            )
            self.assertEqual(
                self.mutate(
                    "password", own=True, new_password=self.new_password
                ).status_code,
                200,
            )
        self.assertEqual(
            seen,
            [
                (self.target.pk, "identity-target", "username_changed"),
                (self.target.pk, "renamed-target", "password_reset"),
                (self.actor.pk, "identity-admin", "password_changed"),
            ],
        )

    def test_retired_names_cannot_be_reused_by_create_initial_provision_or_bootstrap(
        self,
    ):
        self.assertEqual(
            self.mutate("rename", username="renamed-target").status_code, 200
        )
        response = self.client.post(
            "/api/v1/auth/users/",
            {
                "username": "IDENTITY-TARGET",
                "initial_password": self.new_password,
                "role": "reader",
            },
            content_type="application/json",
            HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk),
        )
        self.assert_error(response, 409, "username_unavailable")
        platform = create_local_user(
            username="platform-provisioner", password=self.password
        )
        PlatformAdministrator.objects.create(user=platform)
        tenant = Tenant.objects.create(slug="identity-new", display_name="New")
        self.client.force_login(platform)
        response = self.client.post(
            f"/api/v1/platform/tenants/{tenant.pk}/initial-administrator/",
            {"username": "identity-target", "initial_password": self.new_password},
            content_type="application/json",
        )
        self.assert_error(response, 409, "username_unavailable")
        with TemporaryDirectory() as directory:
            password_file = Path(directory) / "disposable-password"
            password_file.write_text(self.new_password, encoding="utf-8")
            with self.assertRaises(CommandError):
                call_command(
                    "bootstrap_instance",
                    tenant_slug="identity-bootstrap",
                    tenant_name="Bootstrap",
                    admin_username="identity-target",
                    admin_password_file=str(password_file),
                )
        self.assertFalse(Tenant.objects.filter(slug="identity-bootstrap").exists())

    def test_unicode_casefold_reservations_and_user_deletion_retain_tombstones(self):
        user = create_local_user(username="Straße", password=self.password)
        with self.assertRaises(PublicApiError):
            create_local_user(username="STRASSE", password=self.password)
        self.assertEqual(normalize_username("ＬＯＣＡＬ"), "local")
        user.delete()
        self.assertIsNone(UsernameReservation.objects.get(pk="strasse").user_id)
        with self.assertRaises(PublicApiError):
            create_local_user(username="Straße", password=self.password)


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks")
class IdentityConcurrencyTests(IdentityFixture, TransactionTestCase):
    def wait_for_database_lock(self, application_name, worker):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if worker.done():
                self.fail(
                    f"The identity request finished before the expected lock: {worker.result(timeout=1)!r}"
                )
            with connection.cursor() as cursor:
                # These tests hold the main transaction open. PostgreSQL caches
                # activity snapshots within it until explicitly invalidated.
                cursor.execute("SELECT pg_stat_clear_snapshot()")
                cursor.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock')",
                    [application_name],
                )
                if cursor.fetchone()[0]:
                    return
            time.sleep(0.02)
        self.fail("The competing identity request did not wait for its row lock")

    def threaded_rename(self, application_name):
        from rest_framework.test import APIRequestFactory, force_authenticate
        from .identity_views import TenantUserRenameView

        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('application_name', %s, false)",
                    [application_name],
                )
            request = APIRequestFactory().post(
                f"/api/v1/auth/users/{self.membership.pk}/rename/",
                {"username": "race-must-not-rename", "current_password": self.password},
                format="json",
                HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk),
            )
            request.session = {HASH_SESSION_KEY: self.actor.get_session_auth_hash()}
            request.correlation_id = uuid.uuid4()
            force_authenticate(request, user=self.actor)
            response = TenantUserRenameView.as_view()(request, pk=self.membership.pk)
            return response.status_code, response.data.get("error", {}).get("code")
        finally:
            connection.close()

    def test_concurrent_casefold_name_claims_have_one_winner(self):
        barrier = threading.Barrier(2)

        def create(username):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                try:
                    return create_local_user(
                        username=username, password=self.new_password
                    ).username
                except PublicApiError as exc:
                    return exc.public_code
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(create, "Concurrent-Claim")
            second = executor.submit(create, "concurrent-claim")
            values = [first.result(timeout=15), second.result(timeout=15)]
        self.assertEqual(values.count("username_unavailable"), 1)
        self.assertEqual(
            UsernameReservation.objects.filter(pk="concurrent-claim").count(), 1
        )
        self.assertEqual(
            get_user_model()
            .objects.filter(username__iexact="concurrent-claim")
            .count(),
            1,
        )

    def test_password_change_while_waiting_invalidates_stale_session_authority(self):
        application_name = "identity-session-race-" + uuid.uuid4().hex
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Tenant.objects.select_for_update(no_key=True).get(pk=self.tenant.pk)
                fresh = (
                    get_user_model()
                    .objects.select_for_update(no_key=True)
                    .get(pk=self.actor.pk)
                )
                worker = executor.submit(self.threaded_rename, application_name)
                self.wait_for_database_lock(application_name, worker)
                fresh.set_password(self.new_password)
                fresh.save(update_fields=("password",))
            self.assertEqual(
                worker.result(timeout=10), (403, "current_password_invalid")
            )
        self.target.refresh_from_db()
        self.assertEqual(self.target.username, "identity-target")

    def test_membership_committed_after_snapshot_cannot_escape_tenant_scope(self):
        other = Tenant.objects.create(slug="identity-race-other", display_name="Other")
        application_name = "identity-membership-race-" + uuid.uuid4().hex
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Tenant.objects.select_for_update(no_key=True).get(pk=other.pk)
                get_user_model().objects.select_for_update(no_key=True).get(
                    pk=self.target.pk
                )
                TenantMembership.objects.create(
                    tenant=other, user=self.target, role="reader", is_active=False
                )
                worker = executor.submit(self.threaded_rename, application_name)
                self.wait_for_database_lock(application_name, worker)
            self.assertEqual(worker.result(timeout=10), (403, "forbidden"))
        self.target.refresh_from_db()
        self.assertEqual(self.target.username, "identity-target")


class UsernameReservationMigrationTests(TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.restore_targets = MigrationExecutor(connection).loader.graph.leaf_nodes()
        self.old_target = [("tenancy", "0004_platformadministrator_and_more")]
        self.new_target = [("tenancy", "0005_username_reservation")]
        self.step = import_module(
            "ipms.apps.tenancy.migrations.0005_username_reservation"
        ).Migration.operations[-1]
        # Only disposable migration fixtures may remove the production ledger.
        with patch.object(self.step, "reverse_code", migrations.RunPython.noop):
            MigrationExecutor(connection).migrate(self.old_target)

    def tearDown(self):
        try:
            MigrationExecutor(connection).migrate(self.restore_targets)
        finally:
            super().tearDown()

    def historical_users(self):
        return (
            MigrationExecutor(connection)
            .loader.project_state(self.old_target)
            .apps.get_model("auth", "User")
        )

    def test_seed_existing_names_including_disabled_platform_and_unicode(self):
        users = self.historical_users()
        rows = [
            users.objects.create(username="Ｍｉｘｅｄ"),
            users.objects.create(username="DISABLED", is_active=False),
        ]
        MigrationExecutor(connection).migrate(self.new_target)
        self.assertEqual(
            dict(
                UsernameReservation.objects.values_list(
                    "normalized_username", "user_id"
                )
            ),
            {"mixed": rows[0].pk, "disabled": rows[1].pk},
        )
        with self.assertRaises(IrreversibleError):
            MigrationExecutor(connection).migrate(self.old_target)
        self.assertEqual(UsernameReservation.objects.count(), 2)

    def test_normalized_collisions_abort_instead_of_silently_claiming_an_identity(self):
        users = self.historical_users()
        users.objects.create(username="Straße")
        conflicting = users.objects.create(username="STRASSE")
        try:
            with self.assertRaisesRegex(RuntimeError, "Normalized username conflicts"):
                MigrationExecutor(connection).migrate(self.new_target)
        finally:
            users.objects.filter(pk=conflicting.pk).delete()
