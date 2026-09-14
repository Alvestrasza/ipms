# File Name: test_job_logs.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant job history access, stable query/export behavior and read-only guarantees.
import csv
import io
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.agent_pki.models import AgentEnrollment, AgentLifecycleJob, WindowsAgentDeployment
from ipms.apps.discovery.models import HyperVManagementJob, HyperVVirtualMachineActionJob, WindowsServer
from ipms.apps.security.models import BaselinePreference, BaselineScanJob, DomainSecuritySettings, GpoImportJob
from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership


class JobLogTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="job-logs", display_name="Job logs")
        self.other = Tenant.objects.create(slug="other-job-logs", display_name="Other")
        self.user = get_user_model().objects.create_user(username="log-admin", password="test")
        self.membership = TenantMembership.objects.create(tenant=self.tenant, user=self.user, role="tenant_admin")
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        self.agent = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=f"urn:ipms:agent:{uuid.uuid4()}", display_name="log-host",
        )
        self.host = WindowsServer.objects.create(
            tenant=self.tenant, source_id=self.agent.device_uri, hostname="log-host",
            fqdn="log-host.example.invalid", domain_name="example.invalid", discovered_at=timezone.now(),
        )
        self.lifecycle = AgentLifecycleJob.objects.create(
            tenant=self.tenant, enrollment=self.agent, action="update", requested_by="log-admin",
            target_version="0.2.32", status="succeeded", result_code="updated",
        )
        self.scan = BaselineScanJob.objects.create(
            tenant=self.tenant, enrollment=self.agent, system=self.host, requested_by=self.user,
            baseline_id="microsoft-windows-server-2025", status="completed",
            expires_at=timezone.now() + timedelta(minutes=10),
        )

    def test_logs_combine_jobs_and_baseline_view_limits_sources(self):
        response = self.client.get("/api/v1/logs/agents/")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.data["count"], 2)
        self.assertEqual({row["kind"] for row in response.data["results"]}, {"agent_lifecycle", "baseline_scan"})
        self.assertEqual({row["id"] for row in response.data["results"]}, {str(self.lifecycle.id), str(self.scan.id)})
        self.assertEqual(response["Cache-Control"], "no-store")
        baseline = self.client.get("/api/v1/logs/baselines/")
        self.assertEqual(baseline.status_code, 200)
        self.assertEqual([row["id"] for row in baseline.data["results"]], [str(self.scan.id)])

    def extra_sources(self):
        self.domain = DomainSecuritySettings.objects.create(tenant=self.tenant, domain_name="example.invalid")
        self.gpo = GpoImportJob.objects.create(
            id=uuid.uuid4(), tenant=self.tenant, enrollment=self.agent, system=self.host, domain=self.domain,
            requested_by=self.user, domain_guid=str(uuid.uuid4()), pilot_display_name="0-C-ALL-Test_V1.0.0-Pilot",
            pilot_name_key="synthetic-pilot", status="awaiting_approval",
            assignment={"baseline_id": self.scan.baseline_id, "backup_id": "fixture-backup", "target_tier": "0",
                        "approval_test_marker": "exact-protected-approval-document"},
            expires_at=timezone.now() + timedelta(minutes=20), result_evidence={"private_marker": "never-export-this"},
        )
        WindowsAgentDeployment.objects.create(
            tenant=self.tenant, enrollment=self.agent, display_name="deployment-host",
            target_address="deployment.example.invalid", requested_by="log-admin", status="succeeded",
            certificate_fingerprint_sha256="never-export-certificate-fingerprint",
        )
        HyperVVirtualMachineActionJob.objects.create(
            tenant=self.tenant, enrollment=self.agent, vm_name="power-vm", vm_source_id=str(uuid.uuid4()),
            action="start", requested_by="log-admin", status="succeeded",
        )
        HyperVManagementJob.objects.create(
            tenant=self.tenant, enrollment=self.agent, actor=self.user, request_id=uuid.uuid4(),
            vm_name="management-vm", vm_source_id=str(uuid.uuid4()), operation="inspect", requested_by="log-admin",
            status="succeeded", parameters={"private_marker": "never-export-parameters"},
        )

    def test_all_six_sources_project_only_named_metadata_and_json_baseline(self):
        self.extra_sources()
        response = self.client.get("/api/v1/logs/agents/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["count"], 6)
        expected = {"id", "kind", "action", "status", "system", "target", "enrollment_id", "baseline_id",
                    "domain", "requested_at", "started_at", "completed_at", "result_code", "requested_by"}
        for row in response.data["results"]:
            self.assertEqual(set(row), expected)
            self.assertEqual(row["enrollment_id"], str(self.agent.id))
        filtered = self.client.get("/api/v1/logs/baselines/", {"baseline": self.scan.baseline_id, "domain": "EXAMPLE.INVALID"})
        self.assertEqual(filtered.data["count"], 2)
        for endpoint in ("/api/v1/logs/agents/", "/api/v1/logs/agents/export/"):
            body = self.client.get(endpoint).content.decode("utf-8-sig")
            for forbidden in ("never-export", "approval_document", "approval_test_marker", "request_sha256"):
                self.assertNotIn(forbidden, body)

    def test_roles_preserve_source_permissions_and_detail_is_separate(self):
        self.extra_sources()
        for role, allowed in (
            ("reader", {"baseline_scan", "hyperv_management"}),
            ("auditor", {"baseline_scan", "hyperv_management"}),
            ("operator", {"baseline_scan", "hyperv_management", "agent_lifecycle", "agent_deployment", "hyperv_power"}),
        ):
            with self.subTest(role=role):
                self.membership.role = role
                self.membership.save()
                response = self.client.get("/api/v1/logs/agents/")
                self.assertEqual({row["kind"] for row in response.data["results"]}, allowed)
                self.assertEqual(set(response.data["available_kinds"]), allowed)
                self.assertEqual(self.client.get(f"/api/v1/logs/gpo-imports/{self.gpo.id}/").status_code, 403)
                self.assertNotIn(str(self.gpo.id), self.client.get("/api/v1/logs/agents/export/").content.decode())
        self.membership.role = "tenant_admin"
        self.membership.save()
        detail = self.client.get(f"/api/v1/logs/gpo-imports/{self.gpo.id}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["approval_document"], self.gpo.assignment)
        self.assertEqual(detail.data["domain_id"], str(self.domain.id))
        self.assertEqual(detail["Cache-Control"], "no-store")

    def test_tenant_membership_platform_and_relation_boundaries(self):
        self.extra_sources()
        TenantMembership.objects.create(tenant=self.other, user=self.user, role="tenant_admin")
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        self.assertEqual(self.client.get("/api/v1/logs/agents/").data["count"], 0)
        self.assertEqual(self.client.get(f"/api/v1/logs/gpo-imports/{self.gpo.id}/").status_code, 404)
        corrupt = AgentLifecycleJob.objects.create(tenant=self.other, enrollment=self.agent, action="update", status="failed")
        self.assertEqual(self.client.get("/api/v1/logs/agents/").data["count"], 0)
        corrupt.delete()
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        self.membership.is_active = False
        self.membership.save()
        self.assertEqual(self.client.get("/api/v1/logs/agents/").status_code, 404)
        self.membership.is_active = True
        self.membership.save()
        platform_user = get_user_model().objects.create_user(username="log-platform", password="test")
        PlatformAdministrator.objects.create(user=platform_user)
        self.client.force_authenticate(platform_user)
        self.assertEqual(self.client.get("/api/v1/logs/agents/").status_code, 404)

    def test_hidden_baseline_history_survives_and_reads_do_not_expire_or_modify_jobs(self):
        self.extra_sources()
        BaselinePreference.objects.create(tenant=self.tenant, baseline_id=self.scan.baseline_id, hidden=True)
        BaselineScanJob.objects.filter(pk=self.scan.pk).update(status="queued", expires_at=timezone.now() - timedelta(minutes=1))
        GpoImportJob.objects.filter(pk=self.gpo.pk).update(expires_at=timezone.now() - timedelta(minutes=1))
        with CaptureQueriesContext(connection) as queries:
            listing = self.client.get("/api/v1/logs/baselines/")
            export = self.client.get("/api/v1/logs/baselines/export/")
            detail = self.client.get(f"/api/v1/logs/gpo-imports/{self.gpo.id}/")
        self.assertEqual(listing.data["count"], 2)
        self.assertEqual(export.status_code, 200)
        self.assertIsNone(detail.data["approval_document"])
        writes = [item["sql"] for item in queries if item["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))]
        self.assertEqual(writes, [])
        self.scan.refresh_from_db()
        self.gpo.refresh_from_db()
        self.assertEqual(self.scan.status, "queued")
        self.assertEqual(self.gpo.status, "awaiting_approval")
        self.assertEqual(self.client.post("/api/v1/logs/agents/", {}).status_code, 405)

    def test_stable_pagination_sort_and_full_filtered_export(self):
        instant = timezone.now().replace(microsecond=0)
        AgentLifecycleJob.objects.filter(pk=self.lifecycle.pk).update(created_at=instant)
        jobs = [AgentLifecycleJob(tenant=self.tenant, enrollment=self.agent, action="update", status="failed",
                                 requested_by="page-marker", result_code="synthetic_failure") for _ in range(30)]
        AgentLifecycleJob.objects.bulk_create(jobs)
        AgentLifecycleJob.objects.filter(requested_by="page-marker").update(created_at=instant)
        options = {"kind": "agent_lifecycle", "q": "page-marker", "sort": "requested_at", "direction": "asc"}
        first = self.client.get("/api/v1/logs/agents/", options).data
        second = self.client.get("/api/v1/logs/agents/", {**options, "page": "2"}).data
        self.assertEqual((first["count"], len(first["results"]), len(second["results"])), (30, 25, 5))
        ids = [row["id"] for row in first["results"] + second["results"]]
        self.assertEqual(ids, sorted(str(job.id) for job in jobs))
        exported = self.client.get("/api/v1/logs/agents/export/", {**options, "page": "2"})
        self.assertEqual(exported.status_code, 200)
        self.assertTrue(exported.content.startswith(b"\xef\xbb\xbf"))
        rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
        self.assertEqual([row["id"] for row in rows], ids)
        self.assertEqual(self.client.get("/api/v1/logs/agents/", {**options, "page": "3"}).data["results"], [])

    def test_union_sort_dates_nulls_filters_and_date_end_are_consistent(self):
        self.extra_sources()
        early = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        BaselineScanJob.objects.filter(pk=self.scan.pk).update(requested_at=early + timedelta(hours=23), completed_at=early)
        GpoImportJob.objects.filter(pk=self.gpo.pk).update(requested_at=early + timedelta(days=1))
        filtered = self.client.get("/api/v1/logs/baselines/", {"from": early.date().isoformat(), "to": early.date().isoformat(), "agent": str(self.agent.id)})
        self.assertEqual([row["id"] for row in filtered.data["results"]], [str(self.scan.id)])
        for sort in ("requested_at", "completed_at", "system", "kind", "status"):
            for direction in ("asc", "desc"):
                options = {"sort": sort, "direction": direction}
                listed = self.client.get("/api/v1/logs/agents/", options)
                self.assertEqual(listed.status_code, 200, listed.content)
                exported = self.client.get("/api/v1/logs/agents/export/", options)
                rows = list(csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig"))))
                self.assertEqual([row["id"] for row in rows], [row["id"] for row in listed.data["results"]])
                if sort == "completed_at":
                    self.assertEqual(listed.data["results"][0]["id"], str(self.scan.id))

    def test_equal_timestamp_union_pages_have_no_duplicates_or_missing_history(self):
        instant = timezone.now().replace(microsecond=0)
        AgentLifecycleJob.objects.bulk_create([
            AgentLifecycleJob(tenant=self.tenant, enrollment=self.agent, action="update", status="failed")
            for _ in range(15)
        ])
        BaselineScanJob.objects.bulk_create([
            BaselineScanJob(tenant=self.tenant, enrollment=self.agent, system=self.host, requested_by=self.user,
                            baseline_id=self.scan.baseline_id, status="failed", expires_at=instant)
            for _ in range(15)
        ])
        AgentLifecycleJob.objects.filter(tenant=self.tenant).update(created_at=instant)
        BaselineScanJob.objects.filter(tenant=self.tenant).update(requested_at=instant)
        # Removing the Agent from active management must not erase retained jobs.
        AgentEnrollment.objects.filter(pk=self.agent.pk).update(status="removed")
        expected = sorted(("agent_lifecycle", str(pk)) for pk in AgentLifecycleJob.objects.values_list("pk", flat=True))
        expected += sorted(("baseline_scan", str(pk)) for pk in BaselineScanJob.objects.values_list("pk", flat=True))
        pages = [self.client.get("/api/v1/logs/agents/", {"page": page}).data for page in (1, 2)]
        self.assertEqual([item["count"] for item in pages], [32, 32])
        actual = [(row["kind"], row["id"]) for item in pages for row in item["results"]]
        self.assertEqual(actual, expected)
        exported = self.client.get("/api/v1/logs/agents/export/")
        rows = csv.DictReader(io.StringIO(exported.content.decode("utf-8-sig")))
        self.assertEqual([(row["kind"], row["id"]) for row in rows], expected)

    def test_filter_validation_is_bounded_and_unknown_filters_are_rejected(self):
        cases = ["sort=assignment", "direction=sideways", "page=0", "page=10000000", "page_size=10000",
                 "kind=unknown", "status=unknown", "agent=invalid", "q=" + "a" * 201,
                 "q=one&q=two", "unexpected=1", "from=2026-02-30", "from=2026-01-01T12:00:00",
                 "from=2026-09-15&to=2026-09-14", "to=9999-12-31", "q=%00"]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(self.client.get("/api/v1/logs/agents/?" + value).status_code, 400)
        self.assertEqual(self.client.get("/api/v1/logs/baselines/?kind=agent_lifecycle").data["count"], 0)

    def test_export_formula_safety_and_explicit_size_limit(self):
        for value in ("=1+1", " +1+1", "\t@SUM(1)", "\r-2+3", "\u00a0=2+2", "\u200b\ufeff=2+2"):
            AgentEnrollment.objects.filter(pk=self.agent.pk).update(display_name=value)
            response = self.client.get("/api/v1/logs/agents/export/?kind=agent_lifecycle")
            row = next(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
            self.assertEqual(row["system"], "'" + value)
        with patch("ipms.apps.core.job_logs.EXPORT_LIMIT", 1):
            response = self.client.get("/api/v1/logs/agents/export/")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error"]["code"], "log_export_limit_exceeded")
