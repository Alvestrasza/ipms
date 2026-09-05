import json
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.core.management import call_command
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent

from .models import ExternalIdentity, PlatformAdministrator, Tenant, TenantMembership
from .rbac import Permission, effective_tenant_permissions


class TenantModelTests(TestCase):
    def test_tenant_defaults_to_active(self) -> None:
        tenant = Tenant.objects.create(slug="example", display_name="Example")

        self.assertEqual(tenant.status, Tenant.Status.ACTIVE)
        self.assertEqual(tenant.metadata, {})

    def test_tenant_slug_is_unique(self) -> None:
        Tenant.objects.create(slug="example", display_name="First")

        with self.assertRaises(IntegrityError), transaction.atomic():
            Tenant.objects.create(slug="example", display_name="Second")

    def test_user_has_only_one_membership_per_tenant(self) -> None:
        user = get_user_model().objects.create_user(username="reader")
        tenant = Tenant.objects.create(slug="example", display_name="Example")
        TenantMembership.objects.create(
            tenant=tenant,
            user=user,
            role=TenantMembership.Role.READER,
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            TenantMembership.objects.create(
                tenant=tenant,
                user=user,
                role=TenantMembership.Role.OPERATOR,
            )

    def test_external_identity_is_unique_by_issuer_and_subject(self) -> None:
        users = get_user_model()
        first = users.objects.create_user(username="first")
        second = users.objects.create_user(username="second")
        ExternalIdentity.objects.create(
            user=first,
            issuer="https://identity.example.invalid/realms/ipms",
            subject="stable-subject",
        )

        with self.assertRaises(IntegrityError), transaction.atomic():
            ExternalIdentity.objects.create(
                user=second,
                issuer="https://identity.example.invalid/realms/ipms",
                subject="stable-subject",
            )

    def test_operator_permissions_do_not_include_user_administration(self) -> None:
        user = get_user_model().objects.create_user(username="operator")
        tenant = Tenant.objects.create(slug="operator-scope", display_name="Operator")
        TenantMembership.objects.create(
            tenant=tenant,
            user=user,
            role=TenantMembership.Role.OPERATOR,
        )

        permissions = effective_tenant_permissions(user, tenant)
        self.assertIn(Permission.AGENTS_MANAGE, permissions)
        self.assertIn(Permission.CONNECTORS_MANAGE, permissions)
        self.assertIn(Permission.VIRTUAL_MACHINES_OPERATE, permissions)
        self.assertIn(Permission.VIRTUAL_MACHINES_CONSOLE_CONTROL, permissions)
        self.assertNotIn(Permission.USERS_VIEW, permissions)
        self.assertNotIn(Permission.USERS_MANAGE, permissions)


class AuthenticationApiTests(TestCase):
    def setUp(self) -> None:
        self.client = Client(enforce_csrf_checks=True)
        self.user = get_user_model().objects.create_user(
            username="tenant-admin",
            password="test-only-password",
            first_name="Tenant",
            last_name="Administrator",
        )
        self.tenant = Tenant.objects.create(
            slug="example",
            display_name="Example Tenant",
        )
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.user,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        self.session_url = reverse("core:tenancy:session")
        self.login_url = reverse("core:tenancy:login")
        self.logout_url = reverse("core:tenancy:logout")

    def csrf_token(self) -> str:
        response = self.client.get(self.session_url)
        return response.json()["csrf_token"]

    def test_anonymous_session_returns_only_csrf_bootstrap(self) -> None:
        response = self.client.get(self.session_url)

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["authenticated"])
        self.assertIn("csrf_token", response.json())
        self.assertNotIn("user", response.json())

    def test_login_returns_minimal_user_and_authorized_tenants(self) -> None:
        response = self.client.post(
            self.login_url,
            data=json.dumps(
                {"username": "tenant-admin", "password": "test-only-password"}
            ),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.csrf_token(),
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["authenticated"])
        self.assertEqual(body["user"]["username"], "tenant-admin")
        self.assertEqual(body["tenants"][0]["id"], str(self.tenant.id))
        self.assertEqual(body["tenants"][0]["role"], "tenant_admin")
        self.assertIn(
            Permission.USERS_MANAGE,
            body["tenants"][0]["permissions"],
        )
        self.assertNotIn("password", str(body).lower())
        event = AuditEvent.objects.get(action="auth.login")
        self.assertEqual(event.outcome, AuditEvent.Outcome.SUCCEEDED)

    def test_invalid_credentials_use_generic_error_and_are_audited(self) -> None:
        response = self.client.post(
            self.login_url,
            data=json.dumps({"username": "unknown", "password": "incorrect"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=self.csrf_token(),
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"]["message"], "Sign-in failed.")
        event = AuditEvent.objects.get(action="auth.login")
        self.assertEqual(event.outcome, AuditEvent.Outcome.DENIED)

    def test_login_rejects_missing_csrf_token(self) -> None:
        response = self.client.post(
            self.login_url,
            data=json.dumps(
                {"username": "tenant-admin", "password": "test-only-password"}
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"]["code"], "csrf_failed")
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_expired_membership_is_not_returned_or_selectable(self) -> None:
        membership = TenantMembership.objects.get(user=self.user, tenant=self.tenant)
        membership.expires_at = timezone.now() - timedelta(minutes=1)
        membership.save(update_fields=("expires_at", "updated_at"))
        self.client.force_login(self.user)

        session = self.client.get(self.session_url)
        self.assertEqual(session.json()["tenants"], [])
        denied = self.client.get(
            reverse("core:physical-list"),
            HTTP_X_IPMS_TENANT_ID=str(self.tenant.id),
        )
        self.assertEqual(denied.status_code, 404)

    def test_logout_invalidates_authenticated_session(self) -> None:
        self.client.force_login(self.user)
        token = self.csrf_token()

        response = self.client.post(
            self.logout_url,
            data="{}",
            content_type="application/json",
            HTTP_X_CSRFTOKEN=token,
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["authenticated"])
        self.assertEqual(
            AuditEvent.objects.get(action="auth.logout").outcome,
            AuditEvent.Outcome.SUCCEEDED,
        )


class InstanceBootstrapCommandTests(TestCase):
    def test_command_creates_idempotent_platform_admin_without_membership(self) -> None:
        with TemporaryDirectory() as directory:
            password_file = Path(directory) / "password"
            password_file.write_text(
                "A-strong-test-only-bootstrap-password-482!",
                encoding="utf-8",
            )
            arguments = [
                "bootstrap_instance",
                "--tenant-slug",
                "development",
                "--tenant-name",
                "Development",
                "--admin-username",
                "alice",
                "--admin-password-file",
                str(password_file),
            ]

            call_command(*arguments)
            call_command(*arguments)

        user = get_user_model().objects.get(username="alice")
        tenant = Tenant.objects.get(slug="development")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(PlatformAdministrator.objects.filter(user=user).exists())
        self.assertTrue(
            user.check_password("A-strong-test-only-bootstrap-password-482!")
        )
        self.assertFalse(TenantMembership.objects.filter(user=user).exists())
        self.assertIsNone(tenant.initial_administrator_created_at)


class TenantUserAdministrationApiTests(TestCase):
    def setUp(self) -> None:
        users = get_user_model()
        self.admin = users.objects.create_user(
            username="tenant-admin",
            password="test-only-password",
        )
        self.reader = users.objects.create_user(
            username="reader",
            password="test-only-password",
        )
        self.tenant = Tenant.objects.create(
            slug="user-management",
            display_name="User Management",
        )
        self.other_tenant = Tenant.objects.create(
            slug="other-user-management",
            display_name="Other User Management",
        )
        self.admin_membership = TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.admin,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.reader,
            role=TenantMembership.Role.READER,
        )

    def headers(self, tenant=None):
        return {"HTTP_X_IPMS_TENANT_ID": str((tenant or self.tenant).id)}

    def test_tenant_admin_creates_local_user_without_password_disclosure(self) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("core:tenancy:user-list"),
            {
                "username": "operator-one",
                "first_name": "Operations",
                "last_name": "User",
                "email": "operator@example.invalid",
                "role": TenantMembership.Role.OPERATOR,
                "initial_password": "A-strong-test-only-password-729!",
            },
            content_type="application/json",
            **self.headers(),
        )

        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["role"], TenantMembership.Role.OPERATOR)
        self.assertEqual(body["authentication_source"], "local")
        self.assertNotIn("password", str(body).lower())
        created = get_user_model().objects.get(username="operator-one")
        self.assertTrue(created.check_password("A-strong-test-only-password-729!"))
        event = AuditEvent.objects.get(action="identity.user.create")
        self.assertEqual(event.tenant, self.tenant)

    def test_reader_cannot_list_users(self) -> None:
        self.client.force_login(self.reader)
        response = self.client.get(
            reverse("core:tenancy:user-list"),
            **self.headers(),
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_updates_role_and_deactivates_membership(self) -> None:
        self.client.force_login(self.admin)
        membership = TenantMembership.objects.get(user=self.reader, tenant=self.tenant)
        response = self.client.patch(
            reverse("core:tenancy:user-detail", args=(membership.id,)),
            {"role": TenantMembership.Role.AUDITOR, "is_active": False},
            content_type="application/json",
            **self.headers(),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["role"], TenantMembership.Role.AUDITOR)
        self.assertFalse(response.json()["is_active"])
        membership.refresh_from_db()
        self.assertFalse(membership.is_active)
        self.assertTrue(
            AuditEvent.objects.filter(action="identity.membership.update").exists()
        )

    def test_tenant_admin_cannot_remove_last_admin_or_cross_tenant_user(self) -> None:
        self.client.force_login(self.admin)
        denied = self.client.patch(
            reverse("core:tenancy:user-detail", args=(self.admin_membership.id,)),
            {"role": TenantMembership.Role.READER},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(denied.status_code, 409)

        hidden = self.client.patch(
            reverse("core:tenancy:user-detail", args=(self.admin_membership.id,)),
            {"role": TenantMembership.Role.READER},
            content_type="application/json",
            **self.headers(self.other_tenant),
        )
        self.assertIn(hidden.status_code, (403, 404))

    def test_malformed_platform_membership_is_hidden_and_inaccessible(self) -> None:
        platform = get_user_model().objects.create_user(
            username="platform-admin",
            password="test-only-password",
            is_staff=True,
        )
        membership = TenantMembership(
            tenant=self.tenant,
            user=platform,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        TenantMembership.objects.bulk_create([membership])
        self.client.force_login(self.admin)

        response = self.client.patch(
            reverse("core:tenancy:user-detail", args=(membership.id,)),
            {"is_active": False},
            content_type="application/json",
            **self.headers(),
        )
        self.assertEqual(response.status_code, 404)
        listed = self.client.get(
            reverse("core:tenancy:user-list"), **self.headers()
        ).json()
        self.assertNotIn("platform-admin", str(listed))
