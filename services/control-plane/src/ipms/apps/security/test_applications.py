# File Name: test_applications.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Real inventory and import receipts for baseline-family application accounting.
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import uuid
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.agent_pki.services import confirm_inventory
from ipms.apps.agent_pki.test_group_policy_inventory import DOMAIN_GUID, group_policy_report, utc_text, windows_inventory
from .catalog import BASELINES, BY_ID
from .gpo_content import COMPONENTS, PROFILE_COMPONENTS
from .gpo_jobs import digest, security_gpo_exchange
from .models import BaselinePreference, DomainSecuritySettings, GpoImportJob
from . import tests as baseline_tests

SERVER = baseline_tests.SERVER


def staged_component(*, tenant, domain, executor, baseline_id, backup_id, profile=None,
                     domain_guid=DOMAIN_GUID, guid=None):
    """Synthetic historical import, sealed through the real native receipt receiver.

    Test databases only. This helper neither contacts AD nor grants execution.
    The fixture's backdated completion lets a later inventory prove processing.
    """
    now = timezone.now()
    profile = profile or next(role for role in BY_ID[baseline_id].profiles
                              if backup_id in PROFILE_COMPONENTS[(baseline_id, role)])
    component = COMPONENTS[(baseline_id, backup_id)]
    enrollment = AgentEnrollment.objects.get(tenant=tenant, device_uri=executor.source_id)
    job_id, guid = uuid.uuid4(), guid or str(uuid.uuid4())
    name = f"1-C-ALL-Test-Pilot-{job_id}_V1.0.0"
    expires = now + timedelta(hours=1)
    assignment = {
        "schema": 1, "job_id": str(job_id), "operation": "create_unlinked_pilot",
        "domain_dns_name": domain.domain_name, "domain_guid": domain_guid,
        "forest_dns_name": domain.domain_name, "executor_dc_fqdn": executor.fqdn,
        "scope_id": str(domain.id), "scope_revision": domain.revision, "target_tier": 1,
        "baseline_id": baseline_id, "profile": profile, "backup_id": backup_id,
        "artifact_sha256": component["artifact_sha256"], "pilot_display_name": name,
        "expires_at": utc_text(expires.replace(microsecond=0)),
    }
    assignment["input_digest"] = digest(assignment)
    job = GpoImportJob.objects.create(
        id=job_id, tenant=tenant, domain=domain, enrollment=enrollment, system=executor,
        domain_guid=domain_guid, request_sha256="1" * 64,
        input_digest=assignment["input_digest"], assignment=assignment,
        pilot_display_name=name, pilot_name_key=name.casefold(), status="running",
        requested_at=now - timedelta(minutes=20), claimed_at=now - timedelta(minutes=15),
        expires_at=expires,
    )
    security_gpo_exchange(enrollment, {
        "type": "security_gpo", "schema_version": "1", "device_uri": enrollment.device_uri,
        "correlation_id": "synthetic-application-binding", "action": "result",
        "job_id": str(job.id), "input_digest": job.input_digest,
        "status": "staged", "result_code": "gpo_staged_unlinked", "gpo_guid": guid,
        "evidence": {"computer_enabled": False, "user_enabled": False, "unlinked": True,
                     "domain_dns_name": domain.domain_name, "domain_guid": domain_guid,
                     "dc_fqdn": executor.fqdn},
    })
    GpoImportJob.objects.filter(pk=job.id).update(completed_at=now - timedelta(minutes=10))
    job.refresh_from_db()
    return job


class GroupPolicyApplicationTests(TestCase):
    system = baseline_tests.SecurityBaselineTests.system
    assessment = baseline_tests.SecurityBaselineTests.assessment
    catalog = baseline_tests.SecurityBaselineTests.catalog

    def setUp(self):
        baseline_tests.SecurityBaselineTests.setUp(self)
        self.executor = self.system(role="domain-controller", name="executor", build="", os="Unknown Windows")
        self.domain = DomainSecuritySettings.objects.create(
            tenant=self.tenant, domain_name="example.invalid",
            tier_ous={"0": [], "1": [], "2": []},
            gpo_name_template="{tier}-{scope}-{target}-{purpose}_V{version}", baseline_order=[],
        )

    def group(self, target="server", query=""):
        return next(item for item in self.catalog(query)["application_groups"] if item["target"] == target)

    def receive(self, system, *, report=None):
        enrollment = AgentEnrollment.objects.get(device_uri=system.source_id)
        confirm_inventory(enrollment, agent_version="0.2.33", inventory=windows_inventory(
            report=report, hostname=system.hostname, fqdn=system.fqdn, os_name=system.operating_system,
            os_build=system.os_build, operating_system_role=system.operating_system_role,
        ))
        system.refresh_from_db()

    def bind_profile(self, baseline_id=SERVER, profile="server", **changes):
        return [staged_component(
            tenant=self.tenant, domain=self.domain, executor=self.executor,
            baseline_id=baseline_id, backup_id=backup_id, **changes,
        ) for backup_id in PROFILE_COMPONENTS[(baseline_id, profile)]
            if COMPONENTS[(baseline_id, backup_id)]["scope"] == "machine"]

    def observe(self, jobs, **changes):
        now = timezone.now()
        return group_policy_report(now=now, gpos=[{
            "guid": job.gpo_guid, "version": 65538, "status": "applied",
            "processed_at": utc_text(now - timedelta(minutes=1)),
        } for job in jobs], **changes)

    def test_family_groups_cover_all_inventory_and_do_not_inherit_compliance(self):
        system = self.system()
        self.assessment(system, passed_controls=0, failed_controls=10)
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        data = self.catalog()
        row = next(item for item in data["results"] if item["id"] == SERVER)
        self.assertEqual(row["summary"]["compliance_percent"], 0)
        self.assertEqual(self.group()["summary"], {
            "applicable": 2, "applied": 1, "not_applied": 0, "partial": 0,
            "unknown": 1, "application_percent": 50.0,
        })
        self.assertEqual(self.group()["baseline_ids"], [item.id for item in BASELINES if item.target == "server"])
        self.assertEqual(self.group()["id"], "microsoft:windows:server")
        # An unrelated catalog filter must not remove the global application tiles.
        self.assertEqual(self.group(query="?target=client"), self.group())
        self.assertIsNone(self.group("client")["summary"]["application_percent"])

    def test_imports_alone_unknown_gpos_or_compliance_do_not_prove_application(self):
        system = self.system()
        self.assessment(system)
        self.bind_profile()
        self.assertEqual(self.group()["summary"]["unknown"], 2)
        self.assertIsNone(self.group()["summary"]["application_percent"])
        self.receive(system, report=group_policy_report())
        self.assertEqual(self.group()["summary"]["not_applied"], 1)
        # The same fresh GPO observation without an IPMS component association is unknown.
        GpoImportJob.objects.all().delete()
        self.assertEqual(self.group()["summary"]["unknown"], 2)
        self.assertIsNone(self.group()["summary"]["application_percent"])

    def test_complete_mapping_and_fresh_complete_absence_are_zero(self):
        system = self.system()
        self.bind_profile()
        self.receive(system, report=group_policy_report(gpos=[]))
        summary = self.group()["summary"]
        self.assertEqual((summary["applied"], summary["not_applied"], summary["unknown"]), (0, 1, 1))
        self.assertEqual(summary["application_percent"], 0)

    def test_partial_components_never_count_as_a_full_baseline(self):
        system = self.system()
        jobs = self.bind_profile()
        self.assertGreater(len(jobs), 1)
        self.receive(system, report=self.observe(jobs[:1]))
        summary = self.group()["summary"]
        self.assertEqual((summary["applied"], summary["partial"], summary["unknown"]), (0, 1, 1))
        self.assertEqual(summary["application_percent"], 0)
        GpoImportJob.objects.exclude(pk=jobs[0].id).delete()
        self.assertEqual(self.group()["summary"]["partial"], 1)

    def test_failed_or_unknown_gpos_and_incomplete_negative_mapping_remain_unknown(self):
        system = self.system()
        jobs = self.bind_profile()
        for status in ("failed", "unknown"):
            report = self.observe(jobs)
            for gpo in report["gpos"]:
                gpo["status"] = status
            self.receive(system, report=report)
            self.assertEqual(self.group()["summary"]["unknown"], 2)
        GpoImportJob.objects.exclude(pk=jobs[0].id).delete()
        self.receive(system, report=group_policy_report(gpos=[]))
        self.assertEqual(self.group()["summary"]["unknown"], 2)

    def test_fresh_excluded_components_are_conclusive_negative_evidence(self):
        system = self.system()
        jobs = self.bind_profile()
        report = self.observe(jobs)
        for gpo in report["gpos"]:
            gpo.update(status="excluded", processed_at=None)
        self.receive(system, report=report)
        self.assertEqual(self.group()["summary"]["not_applied"], 1)

    def test_expired_observation_or_processing_and_new_unavailable_snapshots_replace_success(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        self.assertEqual(self.group()["summary"]["applied"], 1)
        old = timezone.now() - timedelta(hours=25)
        # Keep the imports older than the expired processing record so this
        # tests the processing age, independently of the post-import check.
        GpoImportJob.objects.update(
            requested_at=old - timedelta(hours=2), claimed_at=old - timedelta(hours=1),
            completed_at=old - timedelta(minutes=30),
        )
        expired_observation = self.observe(jobs, observed_at=utc_text(old))
        for gpo in expired_observation["gpos"]:
            gpo["processed_at"] = utc_text(old - timedelta(minutes=1))
        expired_processing = self.observe(jobs)
        for gpo in expired_processing["gpos"]:
            gpo["processed_at"] = utc_text(old)
        self.receive(system, report=None)
        for index, report in enumerate((expired_observation, expired_processing,
                       group_policy_report(now=old, gpos=[]),
                       group_policy_report(status="unavailable", gpos=[]),
                       group_policy_report(status="incomplete", gpos=[]), None)):
            # Each first receipt has no earlier barrier. These checks therefore
            # prove freshness itself, independently of replay protection.
            candidate = self.system(name=f"expired-{index}")
            self.receive(candidate, report=report)
            if report is not None:
                self.assertEqual(candidate.detail_snapshot["group_policy"], report)
            summary = self.group()["summary"]
            self.assertEqual(summary["unknown"], summary["applicable"])
            self.assertIsNone(summary["application_percent"])

    def test_processing_expires_at_the_24_hour_boundary(self):
        system = self.system()
        jobs = self.bind_profile()
        now = timezone.now()
        GpoImportJob.objects.update(
            requested_at=now - timedelta(hours=28), claimed_at=now - timedelta(hours=27),
            completed_at=now - timedelta(hours=26),
        )
        report = self.observe(jobs)
        for row in report["gpos"]:
            row["processed_at"] = utc_text(now - timedelta(hours=24) + timedelta(seconds=1))
        self.receive(system, report=report)
        with patch("ipms.apps.security.services.timezone.now", return_value=now):
            self.assertEqual(self.group()["summary"]["applied"], 1)
        for row in report["gpos"]:
            row["processed_at"] = utc_text(now - timedelta(hours=24))
        boundary = self.system(name="boundary")
        self.receive(boundary, report=report)
        with patch("ipms.apps.security.services.timezone.now", return_value=now):
            self.assertEqual(self.group()["summary"]["applied"], 1)
            self.assertEqual(self.group()["summary"]["unknown"], 2)

    def test_current_enrollment_domain_and_system_identity_are_required(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        enrollment = AgentEnrollment.objects.get(device_uri=system.source_id)
        for model, changes in ((enrollment, {"status": "removed"}), (enrollment, {"platform": "linux"}),
                               (enrollment, {"tenant": self.other}),
                               (system, {"domain_name": "other.example.invalid"}),
                               (system, {"inventory_source": "connector"}),
                               (system, {"operating_system_role": "domain-controller"}),
                               (system, {"os_build": "26100.1"}),
                               (system, {"operating_system": "Microsoft Windows Server 2025 Datacenter"})):
            with self.subTest(changes=changes):
                original = {key: getattr(model, key) for key in changes}
                for key, value in changes.items():
                    setattr(model, key, value)
                model.save()
                self.assertEqual(self.group()["summary"]["applied"], 0)
                for key, value in original.items():
                    setattr(model, key, value)
                model.save()

    def test_late_or_equal_timestamp_positive_cannot_resurrect_a_failed_snapshot(self):
        system = self.system()
        jobs = self.bind_profile()
        now = timezone.now()
        failure = group_policy_report(now=now - timedelta(minutes=1), status="unavailable", gpos=[])
        self.receive(system, report=failure)
        older = self.observe(jobs, observed_at=utc_text(now - timedelta(minutes=2)))
        for row in older["gpos"]:
            row["processed_at"] = utc_text(now - timedelta(minutes=3))
        self.receive(system, report=older)
        self.assertEqual(self.group()["summary"]["unknown"], 2)
        same_time = self.observe(jobs, observed_at=failure["observed_at"])
        for row in same_time["gpos"]:
            row["processed_at"] = utc_text(now - timedelta(minutes=2))
        self.receive(system, report=same_time)
        self.assertEqual(self.group()["summary"]["unknown"], 2)
        self.receive(system, report=self.observe(jobs))
        self.assertEqual(self.group()["summary"]["applied"], 1)

    def test_cleared_or_changed_identity_cannot_restore_application_until_after_the_barrier(self):
        system = self.system()
        jobs = self.bind_profile()
        now = timezone.now().replace(microsecond=0)
        original = self.observe(jobs, observed_at=utc_text(now - timedelta(seconds=1)))
        with patch("ipms.apps.agent_pki.services.timezone.now", return_value=now):
            self.receive(system, report=original)
            self.assertEqual(self.group()["summary"]["applied"], 1)
        with patch("ipms.apps.agent_pki.services.timezone.now", return_value=now + timedelta(minutes=1)):
            self.receive(system, report=None)
            self.receive(system, report=original)
            self.assertEqual(self.group()["summary"]["unknown"], 2)
        with patch("ipms.apps.agent_pki.services.timezone.now", return_value=now + timedelta(minutes=2)):
            system.os_build = "26100.1"
            self.receive(system, report=original)
            system.os_build = "26100"
            self.receive(system, report=original)
            self.assertEqual(self.group()["summary"]["unknown"], 2)
        with patch("ipms.apps.agent_pki.services.timezone.now", return_value=now + timedelta(minutes=7, seconds=1)):
            self.receive(system, report=self.observe(jobs))
            self.assertEqual(self.group()["summary"]["applied"], 1)

    def test_malformed_watermark_cannot_count_even_before_the_next_inventory_receipt(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        self.assertEqual(self.group()["summary"]["applied"], 1)
        system.detail_snapshot["group_policy_watermark"]["blocked_through"] = "malformed"
        system.save()
        self.assertEqual(self.group()["summary"]["unknown"], 2)

    def test_cross_domain_guid_and_tenant_bindings_are_not_reused(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs, domain_guid=str(uuid.uuid4())))
        self.assertEqual(self.group()["summary"]["unknown"], 2)
        self.receive(system, report=self.observe(jobs))
        GpoImportJob.objects.update(tenant=self.other)
        self.assertEqual(self.group()["summary"]["unknown"], 2)

    def test_missing_tampered_or_transferred_snapshot_context_is_unknown(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        snapshot = deepcopy(system.detail_snapshot)
        other = self.system(name="unrelated")
        other.detail_snapshot = snapshot
        other.save()
        self.assertEqual(self.group()["summary"]["applied"], 1)
        for context in (None, {}, {**snapshot["group_policy_context"], "enrollment_id": str(uuid.uuid4())},
                        {**snapshot["group_policy_context"], "received_at": utc_text(timezone.now() + timedelta(minutes=6))}):
            system.detail_snapshot = {**snapshot, "group_policy_context": context}
            system.save()
            self.assertEqual(self.group()["summary"]["applied"], 0)

    def test_failed_tampered_obsolete_and_newer_conflicting_imports_cannot_count(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        for changes in ({"status": "failed"}, {"result_digest": "f" * 64},
                        {"input_digest": "f" * 64}, {"claimed_at": None},
                        {"completed_at": None}, {"result_evidence": {}},
                        {"assignment": {**jobs[0].assignment, "artifact_sha256": "f" * 64}}):
            with self.subTest(changes=changes):
                saved = {key: getattr(jobs[0], key) for key in changes}
                GpoImportJob.objects.filter(pk=jobs[0].id).update(**changes)
                self.assertEqual(self.group()["summary"]["applied"], 0)
                GpoImportJob.objects.filter(pk=jobs[0].id).update(**saved)
        conflicting = staged_component(
            tenant=self.tenant, domain=self.domain, executor=self.executor,
            baseline_id=SERVER, backup_id=jobs[0].assignment["backup_id"], guid=jobs[0].gpo_guid,
        )
        GpoImportJob.objects.filter(pk=conflicting.id).update(status="reconciliation_required", completed_at=None)
        self.assertEqual(self.group()["summary"]["applied"], 0)

    def test_processing_before_import_receipt_cannot_confirm_a_reused_guid(self):
        system = self.system()
        jobs = self.bind_profile()
        report = self.observe(jobs)
        for gpo in report["gpos"]:
            gpo["processed_at"] = utc_text(timezone.now() - timedelta(minutes=30))
        self.receive(system, report=report)
        self.assertEqual(self.group()["summary"]["unknown"], 2)

    def test_current_component_manifest_is_required_even_when_receipt_is_valid(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        component = COMPONENTS[(SERVER, jobs[0].assignment["backup_id"])]
        with patch.dict(component, artifact_sha256="0" * 64):
            self.assertEqual(self.group()["summary"]["applied"], 0)

    def test_later_gpo_versions_keep_the_known_identity_without_claiming_content_compliance(self):
        system = self.system()
        jobs = self.bind_profile()
        report = self.observe(jobs)
        for row in report["gpos"]:
            row["version"] = 458798
        self.receive(system, report=report)
        self.assertEqual(self.group()["summary"]["applied"], 1)
        summary = next(row for row in self.catalog()["results"] if row["id"] == SERVER)["summary"]
        self.assertIsNone(summary["compliance_percent"])

    def test_inventory_growth_does_not_add_per_system_or_per_component_queries(self):
        from .services import BaselineOverview
        jobs = self.bind_profile()
        for index in range(25):
            self.receive(self.system(name=f"host-{index}"), report=self.observe(jobs))
        with self.assertNumQueries(5):
            data = BaselineOverview(self.tenant).catalog()
        summary = next(group for group in data["application_groups"] if group["target"] == "server")["summary"]
        self.assertEqual((summary["applied"], summary["applicable"]), (25, 26))

    def test_versions_deduplicate_and_hidden_versions_do_not_shrink_population(self):
        system = self.system()
        jobs = self.bind_profile()
        self.receive(system, report=self.observe(jobs))
        older = self.system(name="older", os="Microsoft Windows Server 2022", build="20348")
        older_jobs = self.bind_profile("microsoft-windows-server-2022")
        self.receive(older, report=self.observe(older_jobs))
        summary = self.group()["summary"]
        self.assertEqual((summary["applicable"], summary["applied"], summary["application_percent"]), (3, 2, 66.7))
        BaselinePreference.objects.create(tenant=self.tenant, baseline_id=SERVER, hidden=True)
        summary = self.group()["summary"]
        self.assertEqual((summary["applicable"], summary["applied"], summary["unknown"]), (3, 1, 2))
        for baseline in BASELINES:
            if baseline.target == "server":
                BaselinePreference.objects.update_or_create(tenant=self.tenant, baseline_id=baseline.id, defaults={"hidden": True})
        self.assertEqual([item["target"] for item in self.catalog()["application_groups"]], ["client"])

    def test_shared_component_bindings_satisfy_actual_dc_profile_and_user_scope_is_excluded(self):
        system = self.system(role="domain-controller", name="dc")
        jobs = self.bind_profile(profile="domain-controller")
        self.assertTrue(any(job.assignment["profile"] == "server" for job in jobs))
        self.assertTrue(any(COMPONENTS[(SERVER, key)]["scope"] != "machine"
                            for key in PROFILE_COMPONENTS[(SERVER, "domain-controller")]))
        self.receive(system, report=self.observe(jobs))
        self.assertEqual(self.group()["summary"]["applied"], 1)

    def test_future_provider_families_are_not_merged_with_microsoft(self):
        extra = replace(BY_ID[SERVER], id="custom-server-2025", provider="a-corp")
        with patch("ipms.apps.security.services.BASELINES", (*BASELINES, extra)):
            groups = self.catalog()["application_groups"]
        self.assertEqual([item["id"] for item in groups], [
            "microsoft:windows:server", "microsoft:windows:client", "a-corp:windows:server",
        ])
