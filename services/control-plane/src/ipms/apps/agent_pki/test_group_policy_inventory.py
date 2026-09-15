# File Name: test_group_policy_inventory.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Authenticated inventory projection and bounded computer GPO evidence validation.
from copy import deepcopy
from datetime import timedelta
import uuid
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from .models import AgentEnrollment
from .services import confirm_inventory


DOMAIN_GUID = "736e543d-d66e-440b-b2f1-cce495631fba"
GPO_GUID = "52cbb71f-0d83-4b18-a77b-1225d0830e97"


def utc_text(value):
    return value.isoformat().replace("+00:00", "Z")


def group_policy_report(*, now=None, gpos=None, **changes):
    now = now or timezone.now()
    return {
        "schema_version": "1", "source": "windows-rsop-computer", "scope": "computer",
        "status": "collected", "observed_at": utc_text(now),
        "domain_dns": "example.invalid", "domain_guid": DOMAIN_GUID,
        "gpos": gpos if gpos is not None else [{
            "guid": GPO_GUID, "version": 65538, "status": "applied",
            "processed_at": utc_text(now - timedelta(minutes=1)),
        }],
        **changes,
    }


def windows_inventory(*, report=None, **changes):
    return {
        "schema_version": "1", "pack": "windows-server-core", "agent_gateway_port": 9419,
        "hostname": "application-test", "fqdn": "application-test.example.invalid",
        "domain_name": "example.invalid", "operating_system_role": "server",
        "os_name": "Microsoft Windows Server 2025 Standard", "os_build": "26100",
        "logical_processors": 4, "memory_total_bytes": 8 * 1024**3,
        **({"group_policy": report} if report is not None else {}), **changes,
    }


class GroupPolicyInventoryTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="gpo-inventory", display_name="GPO inventory")
        self.agent = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=f"urn:ipms:agent:{uuid.uuid4()}",
            display_name="Application test", platform="windows", status="active",
        )

    def receive(self, document, *, at=None):
        with patch("ipms.apps.agent_pki.services.timezone.now", return_value=at or timezone.now()):
            confirm_inventory(self.agent, agent_version="0.2.33", inventory=document)
        return WindowsServer.objects.get(tenant=self.tenant, source_id=self.agent.device_uri)

    def test_report_is_projected_with_server_bound_inventory_context(self):
        report = group_policy_report()
        system = self.receive(windows_inventory(report=report))
        self.assertEqual(system.detail_snapshot["group_policy"], report)
        context = system.detail_snapshot["group_policy_context"]
        self.assertEqual(context["enrollment_id"], str(self.agent.id))
        self.assertEqual(context["domain_name"], system.domain_name)
        self.assertEqual(context["operating_system_role"], system.operating_system_role)
        self.assertEqual(context["os_build"], system.os_build)
        self.assertEqual(context["operating_system"], system.operating_system)
        self.assertTrue(context["received_at"].endswith("Z"))

    def test_older_agent_and_later_failed_collection_replace_prior_positive(self):
        now = timezone.now().replace(microsecond=0)
        self.receive(windows_inventory(report=group_policy_report(now=now - timedelta(minutes=2))), at=now)
        system = self.receive(windows_inventory(), at=now + timedelta(minutes=1))
        self.assertNotIn("group_policy", system.detail_snapshot)
        self.assertNotIn("group_policy_context", system.detail_snapshot)
        self.receive(windows_inventory(report=group_policy_report(now=now + timedelta(minutes=7))), at=now + timedelta(minutes=7))
        unavailable = group_policy_report(now=now + timedelta(minutes=8), status="unavailable", gpos=[])
        system = self.receive(windows_inventory(report=unavailable), at=now + timedelta(minutes=8))
        self.assertEqual(system.detail_snapshot["group_policy"], unavailable)

    def test_malformed_reports_are_rejected_before_any_inventory_or_presence_write(self):
        report = group_policy_report()
        bad = [None, [], {**report, "schema_version": 1}, {**report, "extra": True},
               {**report, "source": "registry"}, {**report, "scope": "user"},
               {**report, "status": "successful"}, {**report, "domain_guid": DOMAIN_GUID.upper()},
               {**report, "domain_guid": str(uuid.UUID(int=0))},
               {**report, "domain_dns": "other.example.invalid"},
               {**report, "domain_dns": "EXAMPLE.INVALID"}, {**report, "domain_dns": None},
               {**report, "observed_at": "2026-09-15T00:00:00+00:00"},
               {**report, "observed_at": utc_text(timezone.now() + timedelta(minutes=6))},
               {**report, "status": "incomplete"},
               {**report, "status": "not-domain-joined", "gpos": []},
               {**report, "gpos": report["gpos"] * 2},
               {**report, "gpos": report["gpos"] * 257}]
        for changes in ({"guid": "{52CBB71F-0D83-4B18-A77B-1225D0830E97}"},
                        {"version": True}, {"version": -1}, {"version": 2**32},
                        {"status": "compliant"}, {"processed_at": None},
                        {"processed_at": utc_text(timezone.now() + timedelta(minutes=1))},
                        {"path": "untrusted"}):
            bad.append({**report, "gpos": [{**report["gpos"][0], **changes}]})
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValidationError):
                    self.receive(windows_inventory(group_policy=value))
                self.assertFalse(WindowsServer.objects.exists())
                self.agent.refresh_from_db()
                self.assertIsNone(self.agent.last_seen_at)
                self.assertIsNone(self.agent.first_inventory_at)

    def test_collected_empty_and_non_collected_reports_do_not_invent_applied_gpos(self):
        now = timezone.now().replace(microsecond=0)
        for index, changes in enumerate(({"gpos": []}, {"status": "incomplete", "gpos": []},
                        {"status": "unavailable", "gpos": [], "domain_dns": None, "domain_guid": None},
                        {"status": "not-domain-joined", "gpos": [], "domain_dns": None, "domain_guid": None})):
            with self.subTest(changes=changes):
                report = group_policy_report(now=now - timedelta(seconds=10 - index), **changes)
                system = self.receive(windows_inventory(report=report), at=now)
                self.assertEqual(system.detail_snapshot["group_policy"], report)

    def test_expired_but_well_formed_evidence_keeps_its_original_clock(self):
        report = group_policy_report(now=timezone.now() - timedelta(days=2))
        system = self.receive(windows_inventory(report=report))
        self.assertEqual(system.detail_snapshot["group_policy"]["observed_at"], report["observed_at"])

    def test_bad_new_snapshot_cannot_partially_replace_a_previous_snapshot(self):
        original = self.receive(windows_inventory(report=group_policy_report()))
        snapshot = deepcopy(original.detail_snapshot)
        with self.assertRaises(ValidationError):
            self.receive(windows_inventory(hostname="must-not-change", group_policy={"status": "collected"}))
        original.refresh_from_db()
        self.assertEqual(original.hostname, "application-test")
        self.assertEqual(original.detail_snapshot, snapshot)

    def test_queued_older_positive_cannot_replace_newer_failed_observation(self):
        now = timezone.now()
        failure = group_policy_report(now=now - timedelta(minutes=1), status="unavailable", gpos=[])
        previous = self.receive(windows_inventory(report=failure)).detail_snapshot
        positive = group_policy_report(now=now - timedelta(minutes=2))
        system = self.receive(windows_inventory(report=positive))
        self.assertEqual(system.detail_snapshot["group_policy"], failure)
        self.assertEqual(system.detail_snapshot["group_policy_context"], previous["group_policy_context"])

    def test_equal_timestamp_conflicts_remain_unknown_until_a_newer_observation(self):
        now = timezone.now().replace(microsecond=0)
        positive = group_policy_report(now=now - timedelta(minutes=2))
        failure = group_policy_report(now=now - timedelta(minutes=2), status="incomplete", gpos=[])
        self.receive(windows_inventory(report=positive), at=now)
        system = self.receive(windows_inventory(report=failure), at=now + timedelta(seconds=10))
        self.assertNotIn("group_policy_context", system.detail_snapshot)
        self.assertEqual(system.detail_snapshot["group_policy_watermark"]["blocked_through"], positive["observed_at"])
        system = self.receive(windows_inventory(report=positive), at=now + timedelta(seconds=20))
        self.assertNotIn("group_policy_context", system.detail_snapshot)
        newer = group_policy_report(now=now - timedelta(minutes=1))
        system = self.receive(windows_inventory(report=newer), at=now + timedelta(seconds=30))
        self.assertEqual(system.detail_snapshot["group_policy"], newer)

    def test_previous_observation_is_not_retained_across_inventory_identity_changes(self):
        now = timezone.now()
        failure = group_policy_report(now=now - timedelta(minutes=1), status="unavailable", gpos=[])
        self.receive(windows_inventory(report=failure))
        positive = group_policy_report(now=now - timedelta(minutes=2))
        system = self.receive(windows_inventory(report=positive, os_build="26100.1"))
        self.assertNotIn("group_policy", system.detail_snapshot)
        self.assertNotIn("group_policy_context", system.detail_snapshot)
        self.assertIn("group_policy_watermark", system.detail_snapshot)

    def test_omission_keeps_a_watermark_against_seen_and_unseen_queued_positives(self):
        now = timezone.now().replace(microsecond=0)
        positive = group_policy_report(now=now - timedelta(minutes=2))
        self.receive(windows_inventory(report=positive), at=now)
        cleared = self.receive(windows_inventory(), at=now + timedelta(minutes=1))
        watermark = cleared.detail_snapshot["group_policy_watermark"]
        self.assertEqual(watermark["highest_observed"], positive["observed_at"])
        self.assertEqual(watermark["blocked_through"], utc_text(now + timedelta(minutes=6)))
        for queued in (positive, group_policy_report(now=now + timedelta(minutes=5, seconds=30))):
            system = self.receive(windows_inventory(report=queued), at=now + timedelta(minutes=2))
            self.assertNotIn("group_policy", system.detail_snapshot)
            self.assertNotIn("group_policy_context", system.detail_snapshot)
        recovered = group_policy_report(now=now + timedelta(minutes=6, seconds=1))
        system = self.receive(windows_inventory(report=recovered), at=now + timedelta(minutes=6, seconds=1))
        self.assertEqual(system.detail_snapshot["group_policy"], recovered)

    def test_watermark_and_omission_barrier_do_not_move_back_with_the_receipt_clock(self):
        now = timezone.now().replace(microsecond=0)
        future = group_policy_report(now=now + timedelta(minutes=4))
        self.receive(windows_inventory(report=future), at=now)
        cleared = self.receive(windows_inventory(), at=now + timedelta(minutes=1))
        before = cleared.detail_snapshot["group_policy_watermark"]
        system = self.receive(windows_inventory(), at=now - timedelta(minutes=1))
        after = system.detail_snapshot["group_policy_watermark"]
        self.assertEqual(after["highest_observed"], before["highest_observed"])
        self.assertEqual(after["blocked_through"], before["blocked_through"])
        self.assertEqual(after["recorded_at"], before["recorded_at"])

    def test_failed_observation_then_omission_cannot_be_replaced_by_an_old_positive(self):
        now = timezone.now().replace(microsecond=0)
        failure = group_policy_report(now=now - timedelta(minutes=1), status="unavailable", gpos=[])
        self.receive(windows_inventory(report=failure), at=now)
        self.receive(windows_inventory(), at=now + timedelta(minutes=1))
        old = group_policy_report(now=now - timedelta(minutes=2))
        system = self.receive(windows_inventory(report=old), at=now + timedelta(minutes=2))
        self.assertNotIn("group_policy", system.detail_snapshot)
        self.assertEqual(system.detail_snapshot["group_policy_watermark"]["highest_observed"], failure["observed_at"])

    def test_malformed_watermark_creates_one_recoverable_fail_closed_barrier(self):
        now = timezone.now().replace(microsecond=0)
        report = group_policy_report(now=now - timedelta(minutes=1))
        system = self.receive(windows_inventory(report=report), at=now)
        original = deepcopy(system.detail_snapshot)
        valid = original["group_policy_watermark"]
        for index, malformed in enumerate((None, {}, {"schema_version": "wrong", "blocked_through": "invalid"},
                {**valid, "recorded_at": "9999-12-31T23:59:59Z"},
                {**valid, "highest_observed": utc_text(now + timedelta(minutes=6))},
                {**valid, "identity_sha256": "0" * 64}, {**valid, "enrollment_id": str(uuid.uuid4())})):
            with self.subTest(malformed=malformed):
                receipt = now + timedelta(minutes=index * 10)
                system.detail_snapshot = deepcopy(original)
                system.detail_snapshot["group_policy_watermark"] = malformed
                system.save()
                first = self.receive(windows_inventory(report=report), at=receipt + timedelta(minutes=1))
                self.assertNotIn("group_policy", first.detail_snapshot)
                watermark = first.detail_snapshot["group_policy_watermark"]
                self.assertEqual(watermark["blocked_through"], utc_text(receipt + timedelta(minutes=6)))
                second = self.receive(windows_inventory(report=report), at=receipt + timedelta(minutes=2))
                self.assertEqual(second.detail_snapshot["group_policy_watermark"]["blocked_through"], watermark["blocked_through"])
                fresh = group_policy_report(now=receipt + timedelta(minutes=6, seconds=1))
                system = self.receive(windows_inventory(report=fresh), at=receipt + timedelta(minutes=6, seconds=1))
                self.assertEqual(system.detail_snapshot["group_policy"], fresh)

    def assert_identity_replay_blocked(self, inventory_changes, report_changes=None):
        now = timezone.now().replace(microsecond=0)
        initial = group_policy_report(now=now - timedelta(minutes=2))
        self.receive(windows_inventory(report=initial), at=now)
        older = group_policy_report(now=now - timedelta(minutes=3), **(report_changes or {}))
        changed = self.receive(windows_inventory(report=older, **inventory_changes), at=now + timedelta(minutes=1))
        self.assertNotIn("group_policy", changed.detail_snapshot)
        self.assertNotIn("group_policy_context", changed.detail_snapshot)
        self.assertEqual(changed.detail_snapshot["group_policy_watermark"]["highest_observed"], initial["observed_at"])
        restored_identity = self.receive(windows_inventory(report=initial), at=now + timedelta(minutes=2))
        self.assertNotIn("group_policy", restored_identity.detail_snapshot)
        watermark = restored_identity.detail_snapshot["group_policy_watermark"]
        self.assertEqual(watermark["highest_observed"], initial["observed_at"])
        self.assertEqual(watermark["blocked_through"], utc_text(now + timedelta(minutes=7)))
        fresh = group_policy_report(now=now + timedelta(minutes=7, seconds=1))
        recovered = self.receive(windows_inventory(report=fresh), at=now + timedelta(minutes=7, seconds=1))
        self.assertEqual(recovered.detail_snapshot["group_policy"], fresh)

    def test_os_identity_cycle_does_not_restore_an_old_positive(self):
        self.assert_identity_replay_blocked({"os_build": "26100.1"})

    def test_role_identity_cycle_does_not_restore_an_old_positive(self):
        self.assert_identity_replay_blocked({"operating_system_role": "domain-controller"})

    def test_domain_identity_cycle_does_not_restore_an_old_positive(self):
        self.assert_identity_replay_blocked({"domain_name": "other.example.invalid"}, {"domain_dns": "other.example.invalid"})

    def test_domain_guid_cycle_without_dns_change_does_not_restore_an_old_positive(self):
        self.assert_identity_replay_blocked({}, {"domain_guid": str(uuid.uuid4())})

    def test_conflict_then_omission_retains_the_replay_barrier(self):
        now = timezone.now().replace(microsecond=0)
        positive = group_policy_report(now=now - timedelta(minutes=1))
        conflict = group_policy_report(now=now - timedelta(minutes=1), status="incomplete", gpos=[])
        self.receive(windows_inventory(report=positive), at=now)
        self.receive(windows_inventory(report=conflict), at=now + timedelta(seconds=1))
        self.receive(windows_inventory(), at=now + timedelta(minutes=1))
        replayed = self.receive(windows_inventory(report=positive), at=now + timedelta(minutes=2))
        self.assertNotIn("group_policy", replayed.detail_snapshot)
        self.assertEqual(replayed.detail_snapshot["group_policy_watermark"]["highest_observed"], positive["observed_at"])
        self.assertEqual(replayed.detail_snapshot["group_policy_watermark"]["blocked_through"], utc_text(now + timedelta(minutes=6)))

    def test_identical_retry_preserves_an_existing_report_without_advancing_its_observation(self):
        now = timezone.now().replace(microsecond=0)
        report = group_policy_report(now=now - timedelta(minutes=1))
        original = self.receive(windows_inventory(report=report), at=now).detail_snapshot
        retried = self.receive(windows_inventory(report=report), at=now + timedelta(minutes=1)).detail_snapshot
        self.assertEqual(retried["group_policy"], original["group_policy"])
        self.assertEqual(retried["group_policy_context"], original["group_policy_context"])
        self.assertEqual(retried["group_policy_watermark"]["highest_observed"], report["observed_at"])
