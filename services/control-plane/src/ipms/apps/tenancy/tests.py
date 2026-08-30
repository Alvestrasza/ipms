import json

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import Client, TestCase
from django.urls import reverse

from ipms.apps.audit.models import AuditEvent

from .models import Tenant, TenantMembership


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
