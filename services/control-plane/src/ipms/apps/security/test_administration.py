# File Name: test_administration.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant visibility settings, authorization, strict input and retained evidence.
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership

SETTINGS = "/api/v1/security/baseline-settings/"
CATALOG = "/api/v1/security/baselines/"
SERVER = "microsoft-windows-server-2025"


class BaselineAdministrationTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="baseline-settings", display_name="Settings")
        self.other = Tenant.objects.create(slug="other-settings", display_name="Other")
        self.user = get_user_model().objects.create_user(username="baseline-admin", password="test")
        self.membership = TenantMembership.objects.create(tenant=self.tenant, user=self.user, role="tenant_admin")
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))

    def change(self, data, baseline=SERVER):
        return self.client.patch(SETTINGS + baseline + "/", data, format="json")

    def test_admin_lists_all_baselines_with_visible_defaults(self):
        response = self.client.get(SETTINGS)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        self.assertEqual(len(response.data["results"]), 8)
        self.assertTrue(all(not row["hidden"] and row["updated_at"] is None for row in response.data["results"]))

    def test_hide_and_show_are_tenant_scoped_and_audited(self):
        response = self.change({"hidden": True})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["hidden"])
        self.assertEqual(response["Cache-Control"], "no-store")
        catalog = self.client.get(CATALOG).data
        self.assertEqual(catalog["hidden_count"], 1)
        self.assertNotIn(SERVER, [row["id"] for row in catalog["results"]])
        self.assertEqual(self.client.get(CATALOG + SERVER + "/systems/").status_code, 404)
        self.assertEqual(len(self.client.get(SETTINGS).data["results"]), 8)
        event = AuditEvent.objects.get(action="security.baseline_visibility_changed")
        self.assertEqual(event.tenant_id, self.tenant.id)
        self.assertEqual(event.object_id, SERVER)
        self.assertEqual(event.details, {"hidden": True})
        self.assertEqual(self.change({"hidden": True}).status_code, 200)
        self.assertEqual(AuditEvent.objects.filter(action=event.action).count(), 1)
        self.assertEqual(self.change({"hidden": False}).status_code, 200)
        self.assertIn(SERVER, [row["id"] for row in self.client.get(CATALOG).data["results"]])
        self.assertEqual(AuditEvent.objects.filter(action=event.action).count(), 2)

    def test_other_tenant_and_non_admin_roles_cannot_manage(self):
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        self.assertEqual(self.change({"hidden": True}).status_code, 404)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        for role in ("reader", "operator", "approver", "auditor"):
            self.membership.role = role
            self.membership.save()
            self.assertEqual(self.client.get(SETTINGS).status_code, 403)
            self.assertEqual(self.change({"hidden": True}).status_code, 403)
        self.membership.role = "tenant_admin"
        self.membership.expires_at = timezone.now()
        self.membership.save()
        self.assertEqual(self.change({"hidden": True}).status_code, 404)

    def test_platform_and_suspended_tenant_are_denied(self):
        self.tenant.status = "suspended"
        self.tenant.save()
        self.assertEqual(self.change({"hidden": True}).status_code, 404)
        self.tenant.status = "active"
        self.tenant.save()
        platform = get_user_model().objects.create_user(username="settings-platform")
        PlatformAdministrator.objects.create(user=platform)
        self.client.force_authenticate(platform)
        self.assertEqual(self.client.get(SETTINGS).status_code, 404)
        self.assertEqual(self.change({"hidden": True}).status_code, 404)

    def test_input_is_strict_boolean_known_id_and_bounded_json(self):
        for data in ({}, {"hidden": 1}, {"hidden": "false"}, {"hidden": None}, {"hidden": True, "tenant_id": str(self.other.id)}, []):
            self.assertEqual(self.change(data).status_code, 400, data)
        self.assertEqual(self.change({"hidden": True}, baseline="missing").status_code, 404)
        duplicate = self.client.patch(SETTINGS + SERVER + "/", '{"hidden":true,"hidden":false}', content_type="application/json")
        self.assertEqual(duplicate.status_code, 400)
        self.assertEqual(self.client.patch(SETTINGS + SERVER + "/", " " * 5000, content_type="application/json").status_code, 413)

    def test_all_hidden_catalog_can_be_restored_and_counts_are_target_scoped(self):
        rows = self.client.get(SETTINGS)
        self.assertEqual(rows.status_code, 200)
        for row in rows.data["results"]:
            self.assertEqual(self.change({"hidden": True}, baseline=row["id"]).status_code, 200)
        for target, count in (("all", 8), ("server", 4), ("client", 4)):
            data = self.client.get(CATALOG + "?target=" + target).data
            self.assertEqual(data["results"], [])
            self.assertEqual(data["hidden_count"], count)
        self.assertEqual(len(self.client.get(SETTINGS).data["results"]), 8)
        self.assertEqual(self.change({"hidden": False}).status_code, 200)
        self.assertEqual(len(self.client.get(CATALOG).data["results"]), 1)

    def test_visibility_does_not_cross_tenants(self):
        self.assertEqual(self.change({"hidden": True}).status_code, 200)
        TenantMembership.objects.create(tenant=self.other, user=self.user, role="tenant_admin")
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        self.assertEqual(self.client.get(CATALOG).data["hidden_count"], 0)
        self.assertEqual(len(self.client.get(CATALOG).data["results"]), 8)

    def test_session_mutation_requires_csrf(self):
        csrf_client = APIClient(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        response = csrf_client.patch(SETTINGS + SERVER + "/", {"hidden": True}, format="json", HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        self.assertEqual(response.status_code, 403)
