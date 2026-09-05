import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import Client, TestCase, TransactionTestCase
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from .models import PlatformAdministrator, Tenant, TenantMembership
from .rbac import (
    Permission,
    effective_memberships,
    effective_tenant_permissions,
    is_platform_administrator,
)


class PlatformBoundaryBaselineTests(TestCase):
    def test_django_staff_has_no_implicit_tenant_access(self):
        user = get_user_model().objects.create_user("legacy-staff", is_staff=True)
        Tenant.objects.create(slug="private", display_name="Private")
        self.client.force_login(user)
        session = self.client.get("/api/v1/auth/session/").json()
        self.assertEqual(session["tenants"], [])


class PlatformFixture:
    endpoint = "/api/v1/platform/tenants/"
    password = "Only-this-fixture-strong-password-59!"

    def setUp(self):
        super().setUp()
        self.platform_user = get_user_model().objects.create_user(
            "platform-manager", password=self.password
        )
        PlatformAdministrator.objects.create(user=self.platform_user)
        self.tenant = Tenant.objects.create(
            slug="uninitialized", display_name="Uninitialized"
        )
        self.client.force_login(self.platform_user)

    def initial_endpoint(self, tenant=None):
        return f"{self.endpoint}{(tenant or self.tenant).id}/initial-administrator/"

    def initialize(self, username="customer-admin", **changes):
        return self.client.post(
            self.initial_endpoint(),
            {"username": username, "initial_password": self.password, **changes},
            content_type="application/json",
        )


class PlatformApiTests(PlatformFixture, TestCase):
    def test_platform_session_exposes_only_platform_permissions_even_with_stale_membership(
        self,
    ):
        TenantMembership.objects.bulk_create(
            [
                TenantMembership(
                    tenant=self.tenant, user=self.platform_user, role="tenant_admin"
                )
            ]
        )
        session = self.client.get("/api/v1/auth/session/").json()
        self.assertTrue(session["user"]["is_platform_admin"])
        self.assertEqual(session["platform_permissions"], ["tenants.manage"])
        self.assertEqual(session["tenants"], [])
        self.assertEqual(
            effective_tenant_permissions(self.platform_user, self.tenant), frozenset()
        )
        for endpoint in (
            "/api/v1/physical/",
            "/api/v1/agents/",
            "/api/v1/service-accounts/",
        ):
            response = self.client.get(
                endpoint, HTTP_X_IPMS_TENANT_ID=str(self.tenant.id)
            )
            self.assertEqual(response.status_code, 404, endpoint)
        self.assertFalse(
            effective_memberships().filter(user=self.platform_user).exists()
        )

    def test_create_list_update_metadata_without_customer_data(self):
        response = self.client.post(
            self.endpoint,
            {"slug": "Customer-A", "display_name": "Customer A"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201, response.content)
        created = response.json()
        self.assertEqual(
            set(created),
            {
                "id",
                "slug",
                "display_name",
                "status",
                "created_at",
                "updated_at",
                "needs_administrator",
            },
        )
        self.assertEqual(created["slug"], "customer-a")
        self.assertTrue(created["needs_administrator"])
        self.assertEqual(created["status"], "active")
        response = self.client.get(
            self.endpoint, HTTP_X_IPMS_TENANT_ID=str(uuid.uuid4())
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["results"]), 2)
        changed = self.client.patch(
            self.endpoint + created["id"] + "/",
            {"display_name": "Renamed"},
            content_type="application/json",
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(changed.json()["display_name"], "Renamed")
        self.assertEqual(
            self.client.delete(self.endpoint + created["id"] + "/").status_code, 405
        )
        self.assertEqual(
            AuditEvent.objects.filter(action__startswith="platform.tenant.").count(), 2
        )

    def test_tenant_slug_immutable_duplicate_and_arbitrary_fields_rejected(self):
        for data in (
            {"slug": "changed"},
            {"metadata": {"secret": "ignored?"}},
            {"external_reference": "foreign"},
            {"status": "decommissioned"},
            {},
        ):
            response = self.client.patch(
                self.endpoint + str(self.tenant.id) + "/",
                data,
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 400, data)
        duplicate = self.client.post(
            self.endpoint,
            {"slug": "UNINITIALIZED", "display_name": "Duplicate"},
            content_type="application/json",
        )
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(duplicate.json()["error"]["code"], "tenant_slug_unavailable")

    def test_tenant_admin_and_unmarked_django_flags_cannot_use_platform_api(self):
        admin = get_user_model().objects.create_user("ordinary-admin")
        TenantMembership.objects.create(
            user=admin, tenant=self.tenant, role="tenant_admin"
        )
        flagged = get_user_model().objects.create_user(
            "unmarked-superuser", is_staff=True, is_superuser=True
        )
        for user in (admin, flagged):
            self.client.force_login(user)
            for method, path, data in (
                ("get", self.endpoint, None),
                ("post", self.endpoint, {"slug": "other", "display_name": "Other"}),
                (
                    "patch",
                    self.endpoint + str(self.tenant.id) + "/",
                    {"display_name": "Denied"},
                ),
                (
                    "post",
                    self.initial_endpoint(),
                    {"username": "bad", "initial_password": self.password},
                ),
            ):
                response = getattr(self.client, method)(
                    path, data, content_type="application/json"
                )
                self.assertEqual(response.status_code, 403)
            self.assertFalse(is_platform_administrator(user))
        for suffix in ("admin/", "admin/login/", "admin/auth/user/"):
            self.assertEqual(self.client.get("/" + suffix).status_code, 404)

    def test_initial_admin_creates_independent_principal_once_without_login_or_secret_response(
        self,
    ):
        response = self.initialize(
            first_name="Customer",
            last_name="Administrator",
            email="customer@example.invalid",
        )
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(set(response.json()), {"tenant"})
        self.assertFalse(response.json()["tenant"]["needs_administrator"])
        user = get_user_model().objects.get(username="customer-admin")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertFalse(PlatformAdministrator.objects.filter(user=user).exists())
        self.assertTrue(user.check_password(self.password))
        membership = TenantMembership.objects.get(user=user)
        self.assertEqual(membership.tenant_id, self.tenant.id)
        self.assertEqual(membership.role, "tenant_admin")
        self.assertIsNone(membership.expires_at)
        self.assertEqual(
            self.client.get("/api/v1/auth/session/").json()["user"]["username"],
            self.platform_user.username,
        )
        self.assertNotIn(self.password, response.content.decode())
        self.assertNotIn(self.password, str(list(AuditEvent.objects.values())))
        second = self.initialize(username="replacement-admin")
        self.assertEqual(second.status_code, 409)
        self.assertEqual(
            second.json()["error"]["code"], "tenant_administrator_already_initialized"
        )
        self.assertFalse(
            get_user_model().objects.filter(username="replacement-admin").exists()
        )

    def test_disabled_deleted_or_expired_admin_never_reopens_provisioning(self):
        self.assertEqual(self.initialize().status_code, 201)
        user = get_user_model().objects.get(username="customer-admin")
        get_user_model().objects.filter(pk=user.pk).update(is_active=False)
        TenantMembership.objects.filter(user=user).update(
            is_active=False, expires_at=timezone.now() - timedelta(days=1)
        )
        self.assertEqual(self.initialize(username="takeover").status_code, 409)
        TenantMembership.objects.filter(user=user).delete()
        self.assertEqual(self.initialize(username="takeover").status_code, 409)
        self.tenant.refresh_from_db()
        self.assertIsNotNone(self.tenant.initial_administrator_created_at)

    def test_existing_username_is_never_attached_or_password_changed(self):
        existing = get_user_model().objects.create_user(
            "existing-user", password="original-private-password"
        )
        response = self.initialize(username="EXISTING-USER")
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "username_unavailable")
        existing.refresh_from_db()
        self.assertTrue(existing.check_password("original-private-password"))
        self.assertFalse(TenantMembership.objects.filter(user=existing).exists())
        self.tenant.refresh_from_db()
        self.assertIsNone(self.tenant.initial_administrator_created_at)

    def test_initial_admin_rejects_weak_password_privileges_and_expiry_fields(self):
        for changes in (
            {"initial_password": "short"},
            {"is_staff": True},
            {"is_superuser": True},
            {"role": "operator"},
            {"expires_at": None},
            {"initial_password": "a\x00" + "b" * 15},
        ):
            response = self.initialize(**changes)
            self.assertEqual(response.status_code, 400, changes)
        self.assertFalse(TenantMembership.objects.filter(tenant=self.tenant).exists())

    def test_platform_cookie_mutations_require_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.platform_user)
        for method, endpoint, data in (
            ("post", self.endpoint, {"slug": "customer-b", "display_name": "B"}),
            (
                "patch",
                self.endpoint + str(self.tenant.id) + "/",
                {"display_name": "Changed"},
            ),
            (
                "post",
                self.initial_endpoint(),
                {"username": "new-user", "initial_password": self.password},
            ),
        ):
            self.assertEqual(
                getattr(client, method)(
                    endpoint, data, content_type="application/json"
                ).status_code,
                403,
            )
        token = client.get("/api/v1/auth/session/").json()["csrf_token"]
        response = client.post(
            self.endpoint,
            {"slug": "valid-csrf", "display_name": "Valid CSRF"},
            content_type="application/json",
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(response.status_code, 201)

    def test_suspended_tenant_cannot_be_selected_and_can_be_reactivated(self):
        self.assertEqual(self.initialize().status_code, 201)
        endpoint = self.endpoint + str(self.tenant.id) + "/"
        self.assertEqual(
            self.client.patch(
                endpoint, {"status": "suspended"}, content_type="application/json"
            ).status_code,
            200,
        )
        user_client = Client()
        user_client.force_login(get_user_model().objects.get(username="customer-admin"))
        self.assertEqual(user_client.get("/api/v1/auth/session/").json()["tenants"], [])
        self.assertEqual(
            user_client.get(
                "/api/v1/service-accounts/", HTTP_X_IPMS_TENANT_ID=str(self.tenant.id)
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.patch(
                endpoint, {"status": "active"}, content_type="application/json"
            ).status_code,
            200,
        )
        self.assertEqual(
            len(user_client.get("/api/v1/auth/session/").json()["tenants"]), 1
        )

    def test_marker_and_django_flag_memberships_rejected_and_stale_rows_hidden(self):
        flagged = get_user_model().objects.create_user("flag-only", is_superuser=True)
        for user in (self.platform_user, flagged):
            with self.assertRaises(ValidationError):
                TenantMembership.objects.create(
                    tenant=self.tenant, user=user, role="tenant_admin"
                )
            TenantMembership.objects.bulk_create(
                [TenantMembership(tenant=self.tenant, user=user, role="tenant_admin")]
            )
            self.assertEqual(
                effective_tenant_permissions(user, self.tenant), frozenset()
            )
        ordinary = get_user_model().objects.create_user("independent")
        TenantMembership.objects.create(
            tenant=self.tenant, user=ordinary, role="reader"
        )
        with self.assertRaises(ValidationError):
            PlatformAdministrator.objects.create(user=ordinary)

    def test_initial_provisioning_checks_independent_history_even_if_timestamp_missing(
        self,
    ):
        user = get_user_model().objects.create_user("historic", is_active=False)
        TenantMembership.objects.bulk_create(
            [
                TenantMembership(
                    tenant=self.tenant, user=user, role="tenant_admin", is_active=False
                )
            ]
        )
        self.assertEqual(self.initialize().status_code, 409)
        self.assertFalse(
            self.client.get(self.endpoint).json()["results"][0]["needs_administrator"]
        )

    def test_bootstrap_does_not_promote_existing_tenant_principal(self):
        user = get_user_model().objects.create_user(
            "occupied-name", password="original-password"
        )
        TenantMembership.objects.create(tenant=self.tenant, user=user, role="reader")
        with TemporaryDirectory() as directory:
            password_file = Path(directory) / "bootstrap-password"
            password_file.write_text(self.password, encoding="utf-8")
            with self.assertRaises(CommandError):
                call_command(
                    "bootstrap_instance",
                    tenant_slug="unused",
                    tenant_name="Unused",
                    admin_username=user.username,
                    admin_password_file=str(password_file),
                )
        user.refresh_from_db()
        self.assertTrue(user.check_password("original-password"))
        self.assertFalse(user.is_staff)
        self.assertFalse(PlatformAdministrator.objects.filter(user=user).exists())
        self.assertFalse(Tenant.objects.filter(slug="unused").exists())

    def test_last_admin_guard_does_not_count_inactive_users_or_platform_memberships(
        self,
    ):
        self.assertEqual(self.initialize().status_code, 201)
        admin = get_user_model().objects.get(username="customer-admin")
        disabled = get_user_model().objects.create_user(
            "disabled-admin", is_active=False
        )
        TenantMembership.objects.create(
            tenant=self.tenant, user=disabled, role="tenant_admin"
        )
        TenantMembership.objects.bulk_create(
            [
                TenantMembership(
                    tenant=self.tenant, user=self.platform_user, role="tenant_admin"
                )
            ]
        )
        membership = TenantMembership.objects.get(tenant=self.tenant, user=admin)
        self.client.force_login(admin)
        response = self.client.patch(
            f"/api/v1/auth/users/{membership.id}/",
            {"is_active": False},
            content_type="application/json",
            HTTP_X_IPMS_TENANT_ID=str(self.tenant.id),
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "last_tenant_admin")


class PlatformMigrationTests(TransactionTestCase):
    def test_legacy_cutover_preserves_independent_history_and_rollback_never_regrants_access(
        self,
    ):
        executor = MigrationExecutor(connection)
        restore_targets = executor.loader.graph.leaf_nodes()
        old_target = [("tenancy", "0003_tenantmembership_expires_at_and_more")]
        new_target = [("tenancy", "0004_platformadministrator_and_more")]
        try:
            executor.migrate(old_target)
            old_apps = executor.loader.project_state(old_target).apps
            Users = old_apps.get_model("auth", "User")
            Tenants = old_apps.get_model("tenancy", "Tenant")
            Memberships = old_apps.get_model("tenancy", "TenantMembership")
            legacy = Users.objects.create(
                username="legacy-root",
                is_staff=True,
                is_superuser=True,
                password="unchanged-test-hash",
            )
            staff_only = Users.objects.create(
                username="legacy-staff", is_staff=True, is_superuser=False
            )
            independent = Users.objects.create(
                username="disabled-independent", is_active=False
            )
            requires_admin = Tenants.objects.create(
                slug="platform-only", display_name="Platform only"
            )
            initialized = Tenants.objects.create(
                slug="independent-history", display_name="Independent history"
            )
            Memberships.objects.create(
                tenant=requires_admin, user=legacy, role="tenant_admin"
            )
            Memberships.objects.create(tenant=initialized, user=legacy, role="reader")
            Memberships.objects.create(
                tenant=initialized,
                user=independent,
                role="tenant_admin",
                is_active=False,
                expires_at=timezone.now() - timedelta(days=1),
            )
            executor = MigrationExecutor(connection)
            executor.migrate(new_target)
            current_apps = executor.loader.project_state(new_target).apps
            Marker = current_apps.get_model("tenancy", "PlatformAdministrator")
            CurrentTenant = current_apps.get_model("tenancy", "Tenant")
            self.assertEqual(Marker.objects.count(), 2)
            self.assertTrue(Marker.objects.filter(user_id=legacy.pk).exists())
            self.assertTrue(Marker.objects.filter(user_id=staff_only.pk).exists())
            legacy.refresh_from_db()
            self.assertFalse(legacy.is_staff)
            self.assertFalse(legacy.is_superuser)
            self.assertEqual(legacy.password, "unchanged-test-hash")
            self.assertFalse(Memberships.objects.filter(user_id=legacy.pk).exists())
            self.assertIsNone(
                CurrentTenant.objects.get(
                    pk=requires_admin.pk
                ).initial_administrator_created_at
            )
            self.assertIsNotNone(
                CurrentTenant.objects.get(
                    pk=initialized.pk
                ).initial_administrator_created_at
            )
            executor = MigrationExecutor(connection)
            executor.migrate(old_target)
            legacy.refresh_from_db()
            self.assertFalse(legacy.is_staff)
            self.assertFalse(legacy.is_superuser)
            self.assertFalse(Memberships.objects.filter(user_id=legacy.pk).exists())
            self.assertTrue(Memberships.objects.filter(user_id=independent.pk).exists())
        finally:
            MigrationExecutor(connection).migrate(restore_targets)


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks")
class PlatformConcurrencyTests(PlatformFixture, TransactionTestCase):
    def wait_for_database_lock(self, application_name):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock')",
                    [application_name],
                )
                if cursor.fetchone()[0]:
                    return
            time.sleep(0.02)
        self.fail("The competing request did not wait on the tenant row lock")

    def threaded_request(
        self,
        view,
        user,
        method,
        path,
        document,
        pk,
        application_name="",
        tenant_header=False,
    ):
        from rest_framework.test import APIRequestFactory, force_authenticate

        close_old_connections()
        try:
            if application_name:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT set_config('application_name', %s, false)",
                        [application_name],
                    )
            headers = (
                {"HTTP_X_IPMS_TENANT_ID": str(self.tenant.id)} if tenant_header else {}
            )
            request = getattr(APIRequestFactory(), method)(
                path, document, format="json", **headers
            )
            request.correlation_id = uuid.uuid4()
            force_authenticate(request, user=user)
            return view.as_view()(request, pk=pk).status_code
        finally:
            connection.close()

    def test_only_one_initial_administrator_can_be_provisioned_concurrently(self):
        from . import platform_views

        gate, release = threading.Event(), threading.Event()
        original_audit = platform_views.audit_platform
        application_name = "ipms-initial-admin-race-" + uuid.uuid4().hex

        def paused_audit(*args, **kwargs):
            gate.set()
            if not release.wait(10):
                raise AssertionError("Initial administrator race gate timed out")
            return original_audit(*args, **kwargs)

        with (
            ThreadPoolExecutor(max_workers=2) as executor,
            patch.object(platform_views, "audit_platform", side_effect=paused_audit),
        ):
            first = executor.submit(
                self.threaded_request,
                platform_views.InitialTenantAdministratorView,
                self.platform_user,
                "post",
                self.initial_endpoint(),
                {"username": "initial-one", "initial_password": self.password},
                self.tenant.id,
            )
            try:
                self.assertTrue(gate.wait(10))
                second = executor.submit(
                    self.threaded_request,
                    platform_views.InitialTenantAdministratorView,
                    self.platform_user,
                    "post",
                    self.initial_endpoint(),
                    {"username": "initial-two", "initial_password": self.password},
                    self.tenant.id,
                    application_name,
                )
                self.wait_for_database_lock(application_name)
            finally:
                release.set()
            self.assertEqual(first.result(timeout=10), 201)
            self.assertEqual(second.result(timeout=10), 409)
        self.assertEqual(
            TenantMembership.objects.filter(
                tenant=self.tenant, role="tenant_admin"
            ).count(),
            1,
        )
        self.assertFalse(
            get_user_model().objects.filter(username="initial-two").exists()
        )

    def test_concurrent_cross_deactivation_rechecks_authority_and_preserves_last_admin(
        self,
    ):
        from . import views

        first_user = get_user_model().objects.create_user("first-admin")
        second_user = get_user_model().objects.create_user("second-admin")
        first_member = TenantMembership.objects.create(
            tenant=self.tenant, user=first_user, role="tenant_admin"
        )
        second_member = TenantMembership.objects.create(
            tenant=self.tenant, user=second_user, role="tenant_admin"
        )
        gate, release = threading.Event(), threading.Event()
        original_audit = views._audit_user_change
        application_name = "ipms-last-admin-race-" + uuid.uuid4().hex

        def paused_audit(*args, **kwargs):
            gate.set()
            if not release.wait(10):
                raise AssertionError("Last administrator race gate timed out")
            return original_audit(*args, **kwargs)

        with (
            ThreadPoolExecutor(max_workers=2) as executor,
            patch.object(views, "_audit_user_change", side_effect=paused_audit),
        ):
            first = executor.submit(
                self.threaded_request,
                views.TenantUserDetailView,
                first_user,
                "patch",
                f"/api/v1/auth/users/{second_member.id}/",
                {"is_active": False},
                second_member.id,
                "",
                True,
            )
            try:
                self.assertTrue(gate.wait(10))
                second = executor.submit(
                    self.threaded_request,
                    views.TenantUserDetailView,
                    second_user,
                    "patch",
                    f"/api/v1/auth/users/{first_member.id}/",
                    {"is_active": False},
                    first_member.id,
                    application_name,
                    True,
                )
                self.wait_for_database_lock(application_name)
            finally:
                release.set()
            self.assertEqual(first.result(timeout=10), 200)
            self.assertEqual(second.result(timeout=10), 403)
        self.assertEqual(
            effective_memberships()
            .filter(tenant=self.tenant, role="tenant_admin")
            .count(),
            1,
        )
        self.assertTrue(effective_memberships().filter(pk=first_member.pk).exists())
