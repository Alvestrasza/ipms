# File Name: test_scans.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Native scan authority, complete-manifest evaluation, attempt isolation and strict transport tests.
import asyncio
import copy
import json
import uuid
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.agent_pki import gateway
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.agent_pki.test_console_transport import ConsoleWriter, request as wire_request
from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import WindowsServer
from .content import CATALOG_SHA256, MANIFESTS
from .evaluator import evaluate
from .models import BaselineAssessment, BaselinePreference, BaselineScanJob
from .scans import security_exchange
from . import tests as baseline_tests
from .tests import BASE, SERVER

SCANS = BASE + SERVER + "/scans/"


class SecurityScanTests(TestCase):
    system = baseline_tests.SecurityBaselineTests.system
    assessment = baseline_tests.SecurityBaselineTests.assessment
    catalog = baseline_tests.SecurityBaselineTests.catalog
    row = baseline_tests.SecurityBaselineTests.row

    def setUp(self):
        baseline_tests.SecurityBaselineTests.setUp(self)
        self.membership.role = "operator"
        self.membership.save()
        self.host = self.system()
        self.host.agent_version = "0.2.31"
        self.host.save()
        self.agent = AgentEnrollment.objects.get(device_uri=self.host.source_id)
        self.agent.last_heartbeat_at = timezone.now()
        self.agent.certificate_fingerprint_sha256 = "a" * 64
        self.agent.certificate_not_before = timezone.now() - timedelta(days=1)
        self.agent.certificate_not_after = timezone.now() + timedelta(days=1)
        self.agent.save()
        self.manifest = MANIFESTS[(SERVER, "server")]

    def envelope(self, action="poll", **fields):
        return {"type": "security_scan", "schema_version": "1", "device_uri": self.agent.device_uri,
                "correlation_id": "synthetic-security", "action": action, **fields}

    def queue(self):
        response = self.client.post(SCANS, {}, format="json")
        self.assertEqual(response.status_code, 202, response.data)
        return response.data

    def poll(self, **changes):
        data = self.envelope(agent_version="0.2.31", catalog_sha256=CATALOG_SHA256)
        data.update(changes)
        return security_exchange(self.agent, data)["security_scan"]

    def begin(self):
        self.queue()
        return self.poll()

    def pages(self, assignment):
        observations = [{"control_id": control["id"], "read_status": "unsupported", "value": None}
                        if control["kind"] == "unsupported" or control["comparison"] == "unsupported" else
                        {"control_id": control["id"], "read_status": "ok", "value": control["expected"]}
                        if control["expected"] is not None else
                        {"control_id": control["id"], "read_status": "missing", "value": None}
                        for control in self.manifest["controls"]]
        count = (len(observations) + 31) // 32
        return [self.envelope("result", job_id=assignment["job_id"], attempt_id=assignment["attempt_id"],
                             manifest_sha256=assignment["manifest_sha256"], page_index=index, page_count=count,
                             system={"os_build": "26100", "product_type": 3, "operating_system": self.host.operating_system,
                                     "join_state": "domain"}, controls=observations[index * 32:(index + 1) * 32])
                for index in range(count)]

    def test_queue_requires_operator_authority_and_preserves_tenant_boundary(self):
        for role in ("reader", "auditor", "approver"):
            self.membership.role = role
            self.membership.save()
            self.assertEqual(self.client.post(SCANS, {}, format="json").status_code, 403)
        self.membership.role = "operator"
        self.membership.save()
        other = self.system(tenant=self.other)
        for ids in ([str(other.id)], [str(uuid.uuid4())]):
            self.assertEqual(self.client.post(SCANS, {"system_ids": ids}, format="json").status_code, 404)
        self.assertFalse(BaselineScanJob.objects.exists())

    def test_queue_is_explicit_and_idempotent_and_old_agents_are_unavailable(self):
        old = self.system(name="old")
        self.assertEqual(self.client.get(SCANS).data["count"], 0)
        result = self.queue()
        self.assertEqual((result["queued"], result["existing"], result["unavailable"]), (1, 0, 1))
        result = self.queue()
        self.assertEqual((result["queued"], result["existing"], result["unavailable"]), (0, 1, 1))
        self.assertEqual(BaselineScanJob.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="security.scan_requested").count(), 1)
        self.assertFalse(BaselineAssessment.objects.exists())

    def test_queue_capacity_counts_only_new_eligible_jobs_and_expires_before_post(self):
        with patch("ipms.apps.security.scans.MAX_ACTIVE_JOBS", 1):
            self.assertEqual(self.queue()["queued"], 1)
            self.assertEqual(self.queue()["existing"], 1)
            BaselineScanJob.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
            self.assertEqual(self.queue()["queued"], 1)
        self.assertEqual(BaselineScanJob.objects.filter(status="expired").count(), 1)

    def test_csrf_unknown_fields_empty_selection_duplicates_and_body_bounds(self):
        for data in ({"command": "no"}, {"scope_verified": True}, {"system_ids": []},
                     {"system_ids": [str(self.host.id)] * 2}, {"system_ids": ["invalid"]}):
            self.assertEqual(self.client.post(SCANS, data, format="json").status_code, 400)
        self.assertEqual(self.client.post(SCANS, '{"system_ids":[],"system_ids":[]}', content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post(SCANS, " " * 16385, content_type="application/json").status_code, 413)
        browser = APIClient(enforce_csrf_checks=True)
        browser.force_login(self.user)
        self.assertEqual(browser.post(SCANS, {}, format="json", HTTP_X_IPMS_TENANT_ID=str(self.tenant.id)).status_code, 403)

    def test_poll_binds_manifest_and_replaces_old_pass_with_unknown_attempt(self):
        self.assessment(self.host)
        self.queue()
        self.assertIsNone(self.poll(catalog_sha256="0" * 64))
        self.assertIsNone(self.poll(agent_version="0.2.30"))
        assignment = self.poll()
        self.assertEqual(assignment["total_controls"], len(self.manifest["controls"]))
        self.assertEqual(assignment["manifest_sha256"], self.manifest["manifest_sha256"])
        self.assertIsNone(self.row()["summary"]["compliance_percent"])
        self.assertEqual(self.row()["summary"]["unknown"], 1)

    def test_full_manifest_pages_are_evaluated_server_side_and_scope_omissions_stay_unknown(self):
        assignment = self.begin()
        pages = self.pages(assignment)
        for index, page in enumerate(pages):
            receipt = security_exchange(self.agent, page)
            self.assertEqual(receipt["complete"], index == len(pages) - 1)
        job = BaselineScanJob.objects.get(pk=assignment["job_id"])
        record = job.assessment
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.pages, {})
        self.assertEqual(len(record.findings), len(self.manifest["controls"]))
        self.assertGreater(record.passed_controls, 0)
        self.assertGreater(record.unknown_controls, 0)
        self.assertFalse(record.scope_verified)
        self.assertTrue(all(row["status"] == "unknown" for row in record.findings if row["scope"] != "machine"))
        self.assertIsNone(self.row()["summary"]["compliance_percent"])
        self.assertTrue(security_exchange(self.agent, pages[-1])["complete"])
        self.assertEqual(AuditEvent.objects.filter(action="security.scan_completed").count(), 1)
        findings = self.client.get(BASE + SERVER + f"/systems/{self.host.id}/findings/").data
        self.assertEqual((findings["count"], len(findings["results"])), (len(record.findings), 50))

    def test_partial_pages_never_complete_and_duplicate_changed_page_is_rejected(self):
        page = self.pages(self.begin())[0]
        self.assertFalse(security_exchange(self.agent, page)["complete"])
        self.assertFalse(security_exchange(self.agent, page)["complete"])
        changed = copy.deepcopy(page)
        changed["controls"][0].update(read_status="error", value=None)
        with self.assertRaises(ValidationError):
            security_exchange(self.agent, changed)
        record = BaselineScanJob.objects.get().assessment
        self.assertEqual(record.passed_controls, 0)
        self.assertEqual(record.unknown_controls, record.total_controls)

    def test_restart_gets_new_attempt_and_cannot_mix_with_old_pages(self):
        first = self.begin()
        old = self.pages(first)[0]
        security_exchange(self.agent, old)
        second = self.poll()
        self.assertNotEqual(first["attempt_id"], second["attempt_id"])
        job = BaselineScanJob.objects.get()
        self.assertEqual((job.pages, job.page_hashes, job.attempt_count), ({}, {}, 2))
        with self.assertRaises(ValidationError):
            security_exchange(self.agent, old)
        self.assertIsNotNone(self.poll())
        self.assertIsNone(self.poll())
        job.refresh_from_db()
        self.assertEqual(job.error_code, "attempt_limit")

    def test_rejects_wrong_agent_job_attempt_manifest_extra_controls_and_measurement_types(self):
        original = self.pages(self.begin())[0]
        bad = [
            {"job_id": str(uuid.uuid4())}, {"attempt_id": str(uuid.uuid4())},
            {"manifest_sha256": "0" * 64}, {"scope_verified": True}, {"page_count": True},
            {"system": {**original["system"], "product_type": 1}},
            {"controls": [{"control_id": "unexpected", "read_status": "ok", "value": 1}]},
            {"controls": [original["controls"][0]] * 2},
            {"controls": [{**original["controls"][0], "value": True}]},
            {"controls": [{**original["controls"][0], "value": float("nan")}]},
            {"controls": [{**original["controls"][0], "value": "x" * 4097}]},
            {"controls": [{**original["controls"][0], "read_status": "unsupported", "value": 0}]},
        ]
        for changes in bad:
            with self.subTest(fields=list(changes)), self.assertRaises(ValidationError):
                security_exchange(self.agent, {**original, **changes})
        self.assertEqual(BaselineScanJob.objects.get().pages, {})

    def test_missing_final_control_or_duplicate_across_pages_cannot_complete(self):
        pages = self.pages(self.begin())
        security_exchange(self.agent, pages[0])
        duplicate = copy.deepcopy(pages[1])
        duplicate["controls"][0] = pages[0]["controls"][0]
        with self.assertRaises(ValidationError):
            security_exchange(self.agent, duplicate)
        for page in pages[1:-1]:
            security_exchange(self.agent, page)
        incomplete = copy.deepcopy(pages[-1])
        incomplete["controls"].pop()
        with self.assertRaises(ValidationError):
            security_exchange(self.agent, incomplete)
        self.assertEqual(BaselineScanJob.objects.get().status, "running")

    def test_failed_scan_and_expiration_supersede_old_pass(self):
        self.assessment(self.host)
        assignment = self.begin()
        failed = self.envelope("failed", **{key: assignment[key] for key in ("job_id", "attempt_id", "manifest_sha256")}, error_code="collection_failed")
        self.assertTrue(security_exchange(self.agent, failed)["complete"])
        self.assertEqual(self.row()["summary"]["error"], 1)
        self.assertTrue(security_exchange(self.agent, failed)["complete"])
        self.begin()
        BaselineScanJob.objects.filter(status="running").update(lease_expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.get(SCANS).data["active"], 0)
        self.assertEqual(BaselineScanJob.objects.first().status, "expired")

    def test_role_revocation_and_system_scope_changes_prevent_evidence_commit(self):
        page = self.pages(self.begin())[0]
        self.membership.role = "reader"
        self.membership.save()
        self.assertTrue(security_exchange(self.agent, page)["complete"])
        self.assertEqual(BaselineScanJob.objects.get().error_code, "scope_changed")
        self.membership.role = "operator"
        self.membership.save()
        page = self.pages(self.begin())[0]
        WindowsServer.objects.filter(pk=self.host.id).update(operating_system_role="domain-controller")
        self.assertTrue(security_exchange(self.agent, page)["complete"])
        self.assertEqual(BaselineScanJob.objects.first().error_code, "scope_changed")

    def test_stale_mtls_identity_and_suspended_tenant_cannot_poll(self):
        self.queue()
        for changes in ({"status": "revoked"}, {"certificate_fingerprint_sha256": "b" * 64},
                        {"certificate_not_after": timezone.now() - timedelta(seconds=1)}):
            with transaction_fixture(self.agent, changes), self.assertRaises(ValidationError):
                self.poll()
        self.tenant.status = "suspended"
        self.tenant.save()
        with self.assertRaises(ValidationError):
            self.poll()

    def test_hiding_keeps_evidence_and_pending_scan_but_blocks_display_and_new_requests(self):
        self.assessment(self.host)
        self.queue()
        BaselinePreference.objects.create(tenant=self.tenant, baseline_id=SERVER, hidden=True)
        self.assertEqual(self.client.post(SCANS, {}, format="json").status_code, 404)
        self.assertEqual(self.client.get(SCANS).status_code, 404)
        self.assertEqual(self.client.get(BASE + SERVER + f"/systems/{self.host.id}/findings/").status_code, 404)
        self.assertIsNotNone(self.poll())
        self.assertEqual(BaselineAssessment.objects.count(), 2)


class transaction_fixture:
    def __init__(self, agent, changes):
        self.agent, self.changes = agent, changes
        self.previous = {key: getattr(agent, key) for key in changes}

    def __enter__(self):
        AgentEnrollment.objects.filter(pk=self.agent.pk).update(**self.changes)

    def __exit__(self, *_):
        AgentEnrollment.objects.filter(pk=self.agent.pk).update(**self.previous)


class SecurityEvaluationTests(SimpleTestCase):
    def test_unknowns_type_confusion_and_domain_values_never_pass(self):
        template = {"id": "rule", "kind": "registry", "scope": "machine", "value_type": "dword",
                    "expected": 1, "comparison": "equals", "label": "Synthetic setting"}
        cases = [({}, {"read_status": "ok", "value": 1}, "passed"),
                 ({}, {"read_status": "ok", "value": 0}, "failed"),
                 ({}, {"read_status": "ok", "value": True}, "unknown"),
                 ({}, {"read_status": "missing", "value": None}, "unknown"),
                 ({"scope": "user"}, {"read_status": "ok", "value": 1}, "unknown"),
                 ({"kind": "system_access"}, {"read_status": "ok", "value": 1}, "unknown"),
                 ({"comparison": "absent", "expected": None}, {"read_status": "missing", "value": None}, "passed")]
        for change, observed, status in cases:
            result = evaluate({"controls": [{**template, **change}]}, {"rule": observed}, {"join_state": "domain"})
            self.assertEqual(result["findings"][0]["status"], status)
            self.assertEqual(result["scope_verified"], status != "unknown")


class SecurityTransportTests(SimpleTestCase):
    async def test_scan_route_authenticates_without_offering_other_jobs(self):
        reader = asyncio.StreamReader()
        reader.feed_data(wire_request(path="/v1/security-scan", type="security_scan", schema_version="1", action="poll"))
        reader.feed_eof()
        writer = ConsoleWriter()
        calls = []

        async def database(function, *args, **kwargs):
            calls.append(function.__name__)
            if function.__name__ == "validate_peer_certificate":
                self.assertFalse(kwargs["allow_suspended_report"])
                return SimpleNamespace(device_uri="test-device")
            self.assertEqual(function.__name__, "security_exchange")
            return {"status": "accepted", "security_scan": None}

        with patch.object(gateway, "_database_call_async", database):
            await gateway.handle_connection(reader, writer)
        self.assertIn(b"HTTP/1.1 200", bytes(writer.output))
        self.assertEqual(calls, ["validate_peer_certificate", "security_exchange"])
