# File Name: tests.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Public baseline API, assessment semantics and tenant isolation acceptance.
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership

BASE = "/api/v1/security/baselines/"
SERVER = "microsoft-windows-server-2025"


class SecurityBaselineTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="security", display_name="Security")
        self.other = Tenant.objects.create(slug="other", display_name="Other")
        self.user = get_user_model().objects.create_user(username="reader", password="test")
        self.membership = TenantMembership.objects.create(
            tenant=self.tenant, user=self.user, role="reader"
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))

    def system(self, *, tenant=None, role="server", build="26100", name="host", os=None):
        tenant = tenant or self.tenant
        enrollment = AgentEnrollment.objects.create(
            tenant=tenant, device_uri=f"urn:ipms:agent:{uuid.uuid4()}",
            display_name=name, platform="windows", status="active",
        )
        return WindowsServer.objects.create(
            tenant=tenant, source_id=enrollment.device_uri, inventory_source="agent",
            hostname=name, fqdn=f"{name}.example.invalid", os_build=build,
            operating_system=os or ("Windows 11 Enterprise" if role == "client" else "Microsoft Windows Server 2025"),
            operating_system_role=role, discovered_at=timezone.now(),
        )

    def assessment(self, system, **changes):
        from .models import BaselineAssessment
        from .content import MANIFESTS
        manifest = MANIFESTS[(SERVER, system.operating_system_role)]
        fields = dict(
            system=system,
            enrollment=AgentEnrollment.objects.get(device_uri=system.source_id),
            baseline_id=SERVER, baseline_revision="2602", catalog_revision="2026-09-14", profile=system.operating_system_role,
            content_sha256=manifest["manifest_sha256"],
            os_build=system.os_build, operating_system=system.operating_system,
            scope_verified=True, total_controls=10, passed_controls=10,
            observed_at=timezone.now() - timedelta(minutes=1),
        )
        fields.update(changes)
        # Scale the synthetic ten-control outcome cases to the actual pinned
        # profile census. Count inconsistencies remain inconsistencies.
        extra = len(manifest["controls"]) - fields["total_controls"]
        fields["total_controls"] += extra
        for key in ("passed_controls", "not_applicable_controls", "failed_controls", "unknown_controls"):
            if fields.get(key, 0):
                fields[key] += extra
                break
        return BaselineAssessment.objects.create(**fields)

    def catalog(self, query=""):
        response = self.client.get(BASE + query)
        self.assertEqual(response.status_code, 200, getattr(response, "data", None))
        self.assertEqual(response["Cache-Control"], "no-store")
        return response.data

    def row(self, key=SERVER):
        return next(row for row in self.catalog()["results"] if row["id"] == key)

    def test_catalog_has_authoritative_providers_without_fake_scores(self):
        data = self.catalog()
        self.assertEqual(len(data["results"]), 20)
        self.assertEqual({row["target"] for row in data["results"]}, {"client", "server"})
        self.assertEqual(data["capabilities"], {"assessment": True, "deployment": True, "collections": True})
        self.assertEqual(
            {row["provider"] for row in data["results"]},
            {"microsoft", "cis", "disa", "bsi", "acsc", "ncsc-uk"},
        )
        for row in data["results"]:
            self.assertTrue(row["source_url"].startswith("https://"))
            self.assertIsNone(row["summary"]["compliance_percent"])
            self.assertIsNone(row["summary"]["coverage_percent"])
        microsoft = [row for row in data["results"] if row["provider"] == "microsoft"]
        references = [row for row in data["results"] if row["provider"] != "microsoft"]
        self.assertEqual(len(microsoft), 8)
        self.assertTrue(all(row["assessment_state"] == "native-read-only" and row["deployment_state"] == "bundled" for row in microsoft))
        self.assertTrue(all(row["assessment_state"] == "catalog-only" and row["deployment_state"] != "bundled" for row in references))

    def test_inventory_without_measurements_is_unknown(self):
        self.system()
        summary = self.row()["summary"]
        self.assertEqual(summary["applicable"], 1)
        self.assertEqual(summary["unknown"], 1)
        self.assertEqual(summary["coverage_percent"], 0.0)
        self.assertIsNone(summary["compliance_percent"])

    def test_percent_uses_all_applicable_systems_and_coverage_is_separate(self):
        self.assessment(self.system(name="pass"))
        self.assessment(self.system(name="fail"), passed_controls=8, failed_controls=2)
        self.system(name="unknown")
        self.assessment(self.system(name="stale"), observed_at=timezone.now() - timedelta(hours=25))
        self.system(role="client", name="client")
        self.system(tenant=self.other, name="other")
        summary = self.row()["summary"]
        self.assertEqual(summary["applicable"], 4)
        self.assertEqual(summary["compliance_percent"], 25.0)
        self.assertEqual(summary["coverage_percent"], 50.0)
        self.assertEqual(summary["assessed"], 2)
        self.assertEqual((summary["compliant"], summary["non_compliant"], summary["unknown"], summary["stale"]), (1, 1, 1, 1))

    def test_all_measured_failures_are_zero_and_all_passes_are_one_hundred(self):
        system = self.system()
        self.assessment(system, passed_controls=0, failed_controls=10)
        self.assertEqual(self.row()["summary"]["compliance_percent"], 0.0)
        self.assessment(system, observed_at=timezone.now())
        self.assertEqual(self.row()["summary"]["compliance_percent"], 100.0)

    def test_same_build_client_and_server_are_not_conflated(self):
        self.system(role="client")
        self.system(role="domain-controller", name="dc")
        self.assertEqual(self.row()["summary"]["applicable"], 1)
        self.assertEqual(self.row("microsoft-windows-11-24h2")["summary"]["applicable"], 1)

    def test_unsupported_and_missing_identity_are_visible(self):
        self.system(role="client", build="28000", name="unsupported")
        self.system(role="unknown", build="", name="missing")
        self.system(build="26100", name="inconsistent", os="Microsoft Windows Server 2022")
        inventory = self.catalog()["inventory"]
        self.assertEqual(inventory["total"], 3)
        self.assertEqual(inventory["unclassified"], 1)
        self.assertEqual(inventory["unmatched"], 3)
        self.assertEqual(self.row()["summary"]["applicable"], 0)

    def test_catalog_filter_and_unknown_queries(self):
        self.assertEqual(len(self.catalog("?target=server")["results"]), 10)
        self.assertEqual(len(self.catalog("?target=client")["results"]), 10)
        for query in ("?target=linux", "?target=server&target=client", "?collection=other"):
            self.assertEqual(self.client.get(BASE + query).status_code, 400)

    def test_home_and_unknown_client_editions_are_not_applicable(self):
        self.system(role="client", name="home", os="Microsoft Windows 11 Home")
        self.system(role="client", name="unknown", os="Microsoft Windows 11")
        self.system(role="client", name="professional", os="Microsoft Windows 11 Pro")
        self.assertEqual(self.row("microsoft-windows-11-24h2")["summary"]["applicable"], 1)
        self.assertEqual(self.catalog()["inventory"]["unmatched"], 2)

    def test_partial_and_failed_collection_cannot_pass(self):
        for index, change in enumerate((
            {"scope_verified": False},
            {"passed_controls": 9, "unknown_controls": 1},
            {"passed_controls": 0, "not_applicable_controls": 10},
            {"error_code": "collection_failed"},
        )):
            self.assessment(self.system(name=f"partial-{index}"), **change)
        summary = self.row()["summary"]
        self.assertIsNone(summary["compliance_percent"])
        self.assertEqual(summary["unknown"], 3)
        self.assertEqual(summary["error"], 1)

    def test_latest_incomplete_result_replaces_older_pass(self):
        system = self.system()
        self.assessment(system, observed_at=timezone.now() - timedelta(hours=1))
        self.assessment(system, scope_verified=False)
        self.assertIsNone(self.row()["summary"]["compliance_percent"])

    def test_known_failure_disproves_compliance_without_claiming_full_coverage(self):
        self.assessment(self.system(), passed_controls=8, failed_controls=1, unknown_controls=1, scope_verified=False)
        summary = self.row()["summary"]
        self.assertEqual((summary["non_compliant"], summary["assessed"], summary["unknown"]), (1, 0, 0))
        self.assertEqual(summary["compliance_percent"], 0)
        self.assertEqual(summary["coverage_percent"], 0)

    def test_revision_profile_build_and_identity_changes_invalidate_evidence(self):
        for index, change in enumerate((
            {"baseline_revision": "old"}, {"profile": "domain-controller"},
            {"os_build": "26099"}, {"operating_system": "Old OS"},
        )):
            self.assessment(self.system(name=f"changed-{index}"), **change)
        self.assertEqual(self.row()["summary"]["unknown"], 4)

    def test_revoked_agent_cannot_supply_a_pass(self):
        system = self.system()
        assessment = self.assessment(system)
        assessment.enrollment.status = "revoked"
        assessment.enrollment.save()
        self.assertEqual(self.row()["summary"]["unknown"], 1)

    def test_legacy_empty_content_hash_and_incomplete_census_never_pass(self):
        from .models import BaselineAssessment
        first = self.assessment(self.system(name="legacy"), content_sha256="")
        second = self.assessment(self.system(name="small"))
        BaselineAssessment.objects.filter(pk=second.id).update(total_controls=1, passed_controls=1)
        self.assertEqual(self.row()["summary"]["unknown"], 2)
        self.assertIsNone(self.row()["summary"]["compliance_percent"])

    def test_heartbeat_does_not_refresh_expired_assessment(self):
        system = self.system()
        self.assessment(system, observed_at=timezone.now() - timedelta(days=2))
        AgentEnrollment.objects.update(last_heartbeat_at=timezone.now())
        self.assertEqual(self.row()["summary"]["stale"], 1)

    def test_future_dated_evidence_is_rejected(self):
        with self.assertRaises(ValidationError):
            self.assessment(self.system(), observed_at=timezone.now() + timedelta(hours=1))

    def test_invalid_counts_and_cross_tenant_enrollment_are_rejected(self):
        system = self.system()
        with self.assertRaises(ValidationError):
            self.assessment(system, passed_controls=11)
        other = self.system(tenant=self.other, name="other")
        with self.assertRaises(ValidationError):
            self.assessment(system, enrollment=AgentEnrollment.objects.get(device_uri=other.source_id))

    def test_detail_paginates_only_applicable_tenant_inventory(self):
        for index in range(26):
            self.system(name=f"server-{index:02}")
        self.system(tenant=self.other, name="hidden")
        self.system(role="client", name="client")
        first = self.client.get(BASE + SERVER + "/systems/")
        second = self.client.get(BASE + SERVER + "/systems/?page=2")
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(first.data["count"], 26)
        self.assertEqual(len(first.data["results"]), 25)
        self.assertEqual(len(second.data["results"]), 1)
        self.assertEqual(first.data["results"][0]["reason"], "not_assessed")
        self.assertNotIn("enrollment", first.data["results"][0])
        self.assertEqual(self.client.get(BASE + SERVER + "/systems/?page=0").status_code, 400)
        self.assertEqual(self.client.get(BASE + "absent/systems/").status_code, 404)

    def test_anonymous_cross_tenant_suspended_expired_and_platform_are_denied(self):
        self.client.force_authenticate(None)
        self.assertIn(self.client.get(BASE).status_code, (401, 403))
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        self.assertEqual(self.client.get(BASE).status_code, 404)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        self.membership.expires_at = timezone.now() - timedelta(seconds=1)
        self.membership.save()
        self.assertEqual(self.client.get(BASE).status_code, 404)
        self.membership.expires_at = None
        self.membership.save()
        self.tenant.status = "suspended"
        self.tenant.save()
        self.assertEqual(self.client.get(BASE).status_code, 404)
        platform = get_user_model().objects.create_user(username="platform")
        PlatformAdministrator.objects.create(user=platform)
        self.client.force_authenticate(platform)
        self.assertEqual(self.client.get(BASE).status_code, 404)

    def test_no_browser_or_agent_write_endpoint(self):
        for method in ("post", "put", "patch", "delete"):
            self.assertEqual(getattr(self.client, method)(BASE, {}, format="json").status_code, 405)
        self.assertEqual(self.client.post(BASE + SERVER + "/systems/", {}, format="json").status_code, 405)
