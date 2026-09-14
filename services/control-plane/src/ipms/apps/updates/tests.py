# File Name: tests.py
# Version: v0.2.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Public API acceptance of WSUS reception and inventory comparison.
import copy
import json
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.discovery.models import WindowsServer
from ipms.apps.discovery.models import SoftwareInventorySnapshot
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import Tenant, TenantMembership
from .models import UpdateSource, WsusSnapshot


class WsusReceptionTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="primary", display_name="Primary")
        self.other = Tenant.objects.create(slug="other", display_name="Other")
        self.user = get_user_model().objects.create_user(username="owner", password="test")
        self.member = TenantMembership.objects.create(
            tenant=self.tenant, user=self.user, role=TenantMembership.Role.TENANT_ADMIN
        )
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        response = self.client.post("/api/v1/update-sources/", {
            "name": "Pilot WSUS", "scope": "Windows Server security pilot"
        }, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.source_id = response.data["id"]
        self.token = response.data["token"]
        self.base = f"/api/v1/update-sources/{self.source_id}/"
        self.sender = APIClient()
        self.sender.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")
        self.server = self.make_server("host.example.test", "urn:ipms:agent:one")
        self.document = {
            "schema_version": 1, "snapshot_id": str(uuid.uuid4()),
            "observed_at": timezone.now().isoformat(), "complete": True,
            "scope": "Windows Server security pilot",
            "updates": [{"update_id": str(uuid.uuid4()), "revision": 1,
                         "title": "Security update", "kb_articles": ["1234567"],
                         "products": ["Windows Server"], "classification": "Security Updates",
                         "severity": "Critical"}],
            "computers": [{"computer_id": str(uuid.uuid4()), "fqdn": "HOST.EXAMPLE.TEST.",
                           "reported_at": timezone.now().isoformat(), "updates": []}],
        }
        self.document["computers"][0]["reported_at"] = self.document["observed_at"]
        self.document["computers"][0]["updates"] = [{
            "update_id": self.document["updates"][0]["update_id"], "revision": 1,
            "state": "not_installed",
        }]

    def make_server(self, fqdn, source_id, tenant=None):
        return WindowsServer.objects.create(
            tenant=tenant or self.tenant, source_id=source_id, inventory_source="agent",
            hostname=fqdn.split(".")[0], fqdn=fqdn, discovered_at=timezone.now(),
        )

    def upload(self, document=None):
        return self.sender.post(self.base + "snapshots/", document or self.document, format="json")

    def comparison(self):
        response = self.client.get(self.base + "comparison/")
        self.assertEqual(response.status_code, 200, response.data)
        return response.data

    def test_receives_matches_and_exposes_per_update_evidence(self):
        self.assertEqual(self.upload().status_code, 201)
        row = self.comparison()["results"][0]
        self.assertEqual(row["match_status"], "matched")
        self.assertEqual(row["wsus_status"], "missing")
        self.assertEqual(row["counts"]["not_installed"], 1)
        self.assertIsNone(row["agent"])
        detail = self.client.get(self.base + f"servers/{self.server.id}/updates/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.data["results"][0]["state"], "not_installed")
        self.server.refresh_from_db()
        self.assertEqual(self.server.fqdn, "host.example.test")

    def test_duplicate_is_idempotent_but_modified_replay_conflicts(self):
        self.assertEqual(self.upload().status_code, 201)
        self.assertEqual(self.upload().status_code, 200)
        self.document["updates"][0]["title"] = "Changed"
        self.assertEqual(self.upload().status_code, 409)
        self.assertEqual(WsusSnapshot.objects.count(), 1)

    def test_rejects_partial_unknown_fields_and_orphan_states_atomically(self):
        for change in ("partial", "extra", "orphan", "duplicate", "scope"):
            with self.subTest(change=change):
                doc = copy.deepcopy(self.document)
                if change == "partial": doc["complete"] = False
                if change == "extra": doc["command"] = "anything"
                if change == "orphan": doc["computers"][0]["updates"][0]["update_id"] = str(uuid.uuid4())
                if change == "duplicate": doc["updates"].append(doc["updates"][0])
                if change == "scope": doc["scope"] = "Changed scope"
                self.assertEqual(self.upload(doc).status_code, 400)
        self.assertFalse(WsusSnapshot.objects.exists())

    def test_unknown_missing_cells_and_empty_catalog_never_mean_current(self):
        self.document["computers"][0]["updates"] = []
        self.assertEqual(self.upload().status_code, 201)
        self.assertEqual(self.comparison()["results"][0]["wsus_status"], "unknown")

    def test_stale_report_is_not_refreshed_by_new_import(self):
        self.document["computers"][0]["reported_at"] = (timezone.now() - timedelta(days=3)).isoformat()
        self.document["computers"][0]["updates"][0]["state"] = "installed"
        self.assertEqual(self.upload().status_code, 201)
        self.assertEqual(self.comparison()["results"][0]["wsus_status"], "stale")

    def test_ambiguous_fqdn_and_cross_tenant_inventory_are_not_merged(self):
        self.make_server("HOST.example.test", "duplicate")
        self.make_server("elsewhere.example.test", "other", self.other)
        self.assertEqual(self.upload().status_code, 201)
        rows = self.comparison()["results"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["match_status"] == "ambiguous" for r in rows))
        self.assertTrue(all(r["wsus_status"] == "unknown" for r in rows))

    def test_cross_tenant_source_and_server_access_hidden(self):
        self.assertEqual(self.upload().status_code, 201)
        other_server = self.make_server("host.example.test", "other", self.other)
        self.assertEqual(self.client.get(self.base + f"servers/{other_server.id}/updates/").status_code, 404)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        self.assertEqual(self.client.get(self.base + "comparison/").status_code, 404)

    def test_token_cannot_read_or_manage_and_session_cannot_push(self):
        self.assertEqual(self.sender.get("/api/v1/update-sources/").status_code, 403)
        session_client = APIClient()
        session_client.login(username="owner", password="test")
        self.assertEqual(session_client.post(self.base + "snapshots/", self.document, format="json").status_code, 401)
        self.assertEqual(self.sender.post("/api/v1/update-sources/", {"name":"bad"}, format="json").status_code, 403)

    def test_rotation_disable_and_tenant_suspension_revoke_push(self):
        response = self.client.post(self.base + "rotate-token/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.upload().status_code, 401)
        self.sender.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['token']}")
        self.assertEqual(self.client.patch(self.base, {"enabled":False}, format="json").status_code, 200)
        self.assertEqual(self.upload().status_code, 401)
        self.client.patch(self.base, {"enabled":True}, format="json")
        self.tenant.status = "suspended"
        self.tenant.save()
        self.assertEqual(self.upload().status_code, 401)

    def test_reader_can_compare_but_cannot_configure(self):
        self.member.role = "reader"
        self.member.save()
        self.assertEqual(self.client.get(self.base + "comparison/").status_code, 200)
        self.assertEqual(self.client.patch(self.base, {"enabled":False}, format="json").status_code, 403)

    def test_admin_can_save_and_reload_wsus_server_settings(self):
        response = self.client.post("/api/v1/update-sources/", {
            "name": "Configured WSUS", "scope": "Security pilot",
            "wsus_host": "WSUS.EXAMPLE.TEST.", "wsus_port": 8531, "wsus_use_ssl": True,
        }, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        saved = next(source for source in self.client.get("/api/v1/update-sources/").data
                     if source["id"] == response.data["id"])
        self.assertEqual(saved["wsus_host"], "wsus.example.test")
        self.assertEqual(saved["wsus_port"], 8531)
        self.assertIs(saved["wsus_use_ssl"], True)
        self.assertNotIn("token", saved)
        legacy = next(source for source in self.client.get("/api/v1/update-sources/").data
                      if source["id"] == self.source_id)
        self.assertEqual(legacy["wsus_host"], "")
        self.assertEqual(legacy["wsus_port"], 8531)
        self.assertIs(legacy["wsus_use_ssl"], True)

    def test_wsus_server_settings_validate_host_and_complete_endpoint(self):
        valid = {"wsus_host": "wsus.example.test", "wsus_port": 8531, "wsus_use_ssl": True}
        for host in ("", "https://wsus.example.test", "wsus.example.test:8531", "user@host",
                     "host/path", "host?query", "host name", "bad_host", "[::1]", "fe80::1%eth0"):
            with self.subTest(host=host):
                response = self.client.patch(self.base, {**valid, "wsus_host": host}, format="json")
                self.assertEqual(response.status_code, 400, response.data)
        for change in ({}, {"wsus_port": 8530}, {"wsus_host": "wsus"},
                       {**valid, "wsus_port": 0}, {**valid, "wsus_port": 65536},
                       {**valid, "wsus_port": True}, {**valid, "wsus_use_ssl": "false"}):
            with self.subTest(change=change):
                self.assertEqual(self.client.patch(self.base, change, format="json").status_code, 400)
        for host in ("wsus", "192.0.2.10", "2001:db8::10"):
            with self.subTest(host=host):
                response = self.client.patch(self.base, {**valid, "wsus_host": host,
                                                       "wsus_port": 8530, "wsus_use_ssl": False}, format="json")
                self.assertEqual(response.status_code, 200, response.data)
                self.assertEqual(response.data["wsus_host"], host)
                self.assertFalse(response.data["wsus_use_ssl"])

    def test_changed_wsus_server_requires_new_report_and_retains_history(self):
        self.assertEqual(self.upload().status_code, 201)
        response = self.client.patch(self.base, {
            "wsus_host": "wsus.example.test", "wsus_port": 8531, "wsus_use_ssl": True,
        }, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIsNone(response.data["last_received_at"])
        self.assertIsNone(self.comparison()["snapshot"])
        self.assertEqual(WsusSnapshot.objects.count(), 1)
        self.assertEqual(self.upload().status_code, 200)  # Receipt replay never republishes old data.
        self.assertIsNone(self.comparison()["snapshot"])
        self.document["snapshot_id"] = str(uuid.uuid4())
        self.assertEqual(self.upload().status_code, 409)  # Collection predates changed settings.
        self.document["observed_at"] = timezone.now().isoformat()
        self.assertEqual(self.upload().status_code, 201)
        self.assertIsNotNone(self.comparison()["snapshot"])
        # Saving the same normalized endpoint does not discard its report.
        self.client.patch(self.base, {"wsus_host": "WSUS.EXAMPLE.TEST.", "wsus_port": 8531,
                                     "wsus_use_ssl": True}, format="json")
        self.assertIsNotNone(self.comparison()["snapshot"])
        self.assertNotIn("wsus.example.test", str(list(AuditEvent.objects.values_list("details", flat=True))))

    def test_wsus_server_configuration_enforces_reader_and_tenant_boundaries(self):
        settings = {"wsus_host": "wsus.example.test", "wsus_port": 8531, "wsus_use_ssl": True}
        self.member.role = "reader"
        self.member.save()
        self.assertEqual(self.client.patch(self.base, settings, format="json").status_code, 403)
        self.assertEqual(self.sender.patch(self.base, settings, format="json").status_code, 403)
        self.member.role = TenantMembership.Role.TENANT_ADMIN
        self.member.save()
        other_source = UpdateSource.objects.create(tenant=self.other, name="Other", scope="Other")
        self.assertEqual(self.client.patch(f"/api/v1/update-sources/{other_source.id}/", settings,
                                           format="json").status_code, 404)

    def test_endpoint_reset_preserves_monotonic_catalog_observations(self):
        now = timezone.now()
        self.document["observed_at"] = (now + timedelta(minutes=1)).isoformat()
        self.assertEqual(self.upload().status_code, 201)
        response = self.client.patch(self.base, {"wsus_host": "192.0.2.1", "wsus_port": 65535,
                                                 "wsus_use_ssl": True}, format="json")
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["wsus_port"], 65535)
        self.document["snapshot_id"] = str(uuid.uuid4())
        self.document["observed_at"] = (now + timedelta(seconds=30)).isoformat()
        self.assertEqual(self.upload().status_code, 409)
        self.assertIsNone(self.comparison()["snapshot"])
        self.document["observed_at"] = (now + timedelta(minutes=2)).isoformat()
        self.assertEqual(self.upload().status_code, 201)

    def test_token_is_not_returned_by_reads_or_stored_as_plaintext(self):
        data = self.client.get("/api/v1/update-sources/").data
        self.assertNotIn(self.token, str(data))
        source = UpdateSource.objects.get(id=self.source_id)
        self.assertNotEqual(source.token_hash, self.token)
        self.assertNotIn(self.token, str(source.__dict__))

    def test_old_snapshot_cannot_replace_current(self):
        self.assertEqual(self.upload().status_code, 201)
        self.document["snapshot_id"] = str(uuid.uuid4())
        older = (timezone.now() - timedelta(hours=1)).isoformat()
        self.document["observed_at"] = older
        self.document["computers"][0]["reported_at"] = older
        self.assertEqual(self.upload().status_code, 409)

    def test_future_dates_and_invalid_pagination_are_rejected(self):
        self.document["observed_at"] = (timezone.now() + timedelta(days=1)).isoformat()
        self.assertEqual(self.upload().status_code, 400)
        self.assertEqual(self.client.get(self.base + "comparison/?page=-1").status_code, 400)

    def test_domain_controller_is_included_but_windows_client_is_not(self):
        self.server.operating_system_role = "domain-controller"
        self.server.save()
        workstation = self.make_server("client.example.test", "client")
        workstation.operating_system_role = "client"
        workstation.save()
        self.assertEqual(self.upload().status_code, 201)
        rows = self.comparison()["results"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["server_id"], str(self.server.id))
        self.assertEqual(rows[0]["match_status"], "matched")

    def test_pruning_keeps_immutable_snapshot_receipt(self):
        original = copy.deepcopy(self.document)
        start = timezone.now() - timedelta(hours=1)
        original["observed_at"] = start.isoformat()
        original["computers"][0]["reported_at"] = start.isoformat()
        self.assertEqual(self.upload(original).status_code, 201)
        for index in range(1, 4):
            doc = copy.deepcopy(original)
            doc["snapshot_id"] = str(uuid.uuid4())
            doc["observed_at"] = (start + timedelta(minutes=index)).isoformat()
            self.assertEqual(self.upload(doc).status_code, 201)
        receipt = WsusSnapshot.objects.get(snapshot_id=original["snapshot_id"])
        self.assertEqual(receipt.updates, [])
        self.assertEqual(receipt.update_count, 1)
        self.assertEqual(receipt.computers.count(), 0)
        self.assertEqual(self.upload(original).status_code, 200)
        original["observed_at"] = timezone.now().isoformat()
        self.assertEqual(self.upload(original).status_code, 409)

    def test_payload_limit_duplicate_keys_and_missing_offset(self):
        response = self.sender.generic("POST", self.base + "snapshots/", b" " * 1_048_577,
                                       content_type="application/json")
        self.assertEqual(response.status_code, 413)
        raw = json.dumps(self.document).replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
        self.assertEqual(self.sender.generic("POST", self.base + "snapshots/", raw,
                                            content_type="application/json").status_code, 400)
        self.document["observed_at"] = "2026-09-13T10:00:00"
        self.assertEqual(self.upload().status_code, 400)

    def test_all_reported_states_and_absent_report_timestamp(self):
        expected = {"installed":"current", "not_applicable":"current", "unknown":"unknown",
                    "not_installed":"missing", "downloaded":"missing", "failed":"failed",
                    "installed_pending_reboot":"reboot-required"}
        for index, (state, status) in enumerate(expected.items()):
            doc = copy.deepcopy(self.document)
            doc["snapshot_id"] = str(uuid.uuid4())
            doc["observed_at"] = (timezone.now() + timedelta(seconds=index)).isoformat()
            doc["computers"][0]["updates"][0]["state"] = state
            self.assertEqual(self.upload(doc).status_code, 201)
            self.assertEqual(self.comparison()["results"][0]["wsus_status"], status)
        doc["snapshot_id"] = str(uuid.uuid4())
        doc["observed_at"] = (timezone.now() + timedelta(minutes=1)).isoformat()
        doc["computers"][0]["reported_at"] = None
        self.assertEqual(self.upload(doc).status_code, 201)
        self.assertEqual(self.comparison()["results"][0]["wsus_status"], "stale")

    def test_same_short_name_does_not_match_different_domain(self):
        self.document["computers"][0]["fqdn"] = "host.other.test"
        self.assertEqual(self.upload().status_code, 201)
        result = self.comparison()
        self.assertEqual(result["results"][0]["match_status"], "unmatched")
        self.assertEqual(result["unmatched_computers"], 1)

    def test_empty_catalog_does_not_prove_current_and_ambiguous_wsus_identity(self):
        doc = copy.deepcopy(self.document)
        doc["updates"] = []
        doc["computers"][0]["updates"] = []
        self.assertEqual(self.upload(doc).status_code, 201)
        self.assertEqual(self.comparison()["results"][0]["wsus_status"], "unknown")
        doc = copy.deepcopy(self.document)
        doc["snapshot_id"] = str(uuid.uuid4())
        doc["observed_at"] = timezone.now().isoformat()
        duplicate = copy.deepcopy(doc["computers"][0])
        duplicate["computer_id"] = str(uuid.uuid4())
        doc["computers"].append(duplicate)
        self.assertEqual(self.upload(doc).status_code, 201)
        self.assertEqual(self.comparison()["results"][0]["match_status"], "ambiguous")

    def test_agent_evidence_is_separate_latest_completed_and_revocation_aware(self):
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=self.server.source_id,
            display_name="server", platform="windows", status="active",
        )
        for index in range(2):
            SoftwareInventorySnapshot.objects.create(
                id=uuid.uuid4(), tenant=self.tenant, enrollment=enrollment,
                platform="windows", status="completed", page_count=1,
                updates_available=99 - index, update_scan_status="unknown",
                completed_at=timezone.now() + timedelta(seconds=index),
            )
        self.document["computers"][0]["updates"][0]["state"] = "installed"
        self.assertEqual(self.upload().status_code, 201)
        row = self.comparison()["results"][0]
        self.assertEqual(row["wsus_status"], "current")
        self.assertEqual(row["agent"]["scan_status"], "unknown")
        self.assertEqual(row["agent"]["updates_available"], 98)
        enrollment.status = "revoked"
        enrollment.save()
        self.assertIsNone(self.comparison()["results"][0]["agent"])

    def test_audit_and_source_path_do_not_leak_or_extend_token_authority(self):
        self.assertEqual(self.upload().status_code, 201)
        event = AuditEvent.objects.get(action="updates.wsus.snapshot_received")
        self.assertEqual(event.tenant_id, self.tenant.id)
        self.assertNotIn(self.token, str(event.details))
        self.assertEqual(event.details["computer_count"], 1)
        second = self.client.post("/api/v1/update-sources/", {"name":"Second", "scope":"Other"}, format="json")
        self.assertEqual(second.status_code, 201)
        response = self.sender.post(f"/api/v1/update-sources/{second.data['id']}/snapshots/",
                                    self.document, format="json")
        self.assertEqual(response.status_code, 401)

    def test_configuration_session_requires_csrf(self):
        browser = APIClient(enforce_csrf_checks=True)
        browser.login(username="owner", password="test")
        browser.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        response = browser.post("/api/v1/update-sources/", {"name":"Rejected", "scope":"Scope"}, format="json")
        self.assertEqual(response.status_code, 403)

    def test_atomic_import_failure_preserves_previous_snapshot(self):
        from unittest.mock import patch
        self.assertEqual(self.upload().status_code, 201)
        before = UpdateSource.objects.get(id=self.source_id).current_snapshot_id
        self.document["snapshot_id"] = str(uuid.uuid4())
        self.document["observed_at"] = timezone.now().isoformat()
        with patch("ipms.apps.updates.services.WsusComputerReport.objects.bulk_create", side_effect=RuntimeError("test interruption")):
            with self.assertRaises(RuntimeError):
                self.upload()
        self.assertEqual(UpdateSource.objects.get(id=self.source_id).current_snapshot_id, before)
        self.assertEqual(WsusSnapshot.objects.count(), 1)

    def agent_document(self):
        return {"schema_version":"2", "platform":"windows", "snapshot_id":str(uuid.uuid4()),
                "page_index":0, "page_count":1, "reboot_required":None,
                "update_scan_status":"unknown", "last_update_scan_at":None,
                "last_update_install_at":None, "packages":[],
                "windows_update_evidence":{"source":"wua-local-cache", "status":"collected",
                    "observed_at":timezone.now().isoformat(),
                    "updates":[{"update_id":self.document["updates"][0]["update_id"], "revision":1}]}}

    def test_catalog_only_compares_authenticated_agent_installed_evidence(self):
        from ipms.apps.agent_pki.services import confirm_software_inventory
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=self.server.source_id,
            display_name="server", platform="windows", status="active",
        )
        self.document["computers"] = []
        unknown_update = copy.deepcopy(self.document["updates"][0])
        unknown_update["update_id"] = str(uuid.uuid4())
        self.document["updates"].append(unknown_update)
        doc = self.agent_document()
        confirm_software_inventory(enrollment, document=doc, agent_version="0.2.30")
        self.assertEqual(self.upload().status_code, 201)
        row = self.comparison()["results"][0]
        self.assertEqual(row["match_status"], "unmatched")
        self.assertEqual(row["wsus_status"], "unknown")
        self.assertEqual(row["agent_evidence"]["installed_matches"], 1)
        self.assertEqual(row["agent_evidence"]["unknown"], 1)
        self.assertFalse(row["agent_evidence"]["stale"])
        details = self.client.get(self.base + f"servers/{self.server.id}/updates/").data["results"]
        self.assertEqual([d["agent_state"] for d in details], ["installed", "unknown"])
        self.assertTrue(all(d["state"] == "unknown" for d in details))

    def test_agent_evidence_contract_rejects_partial_cross_page_and_over_limit(self):
        from django.core.exceptions import ValidationError
        from ipms.apps.agent_pki.services import confirm_software_inventory
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=self.server.source_id,
            display_name="server", platform="windows", status="active",
        )
        doc = self.agent_document()
        doc["page_count"] = 2
        confirm_software_inventory(enrollment, document=doc, agent_version="0.2.30")
        self.assertIsNone(self.comparison()["results"][0]["agent"])
        doc["page_index"] = 1
        doc["windows_update_evidence"]["updates"][0]["revision"] = 2
        with self.assertRaises(ValidationError):
            confirm_software_inventory(enrollment, document=doc, agent_version="0.2.30")
        for case in ("truncated", "duplicate", "over-limit", "wrong-source", "missing-time"):
            with self.subTest(case=case):
                invalid = self.agent_document()
                evidence = invalid["windows_update_evidence"]
                if case == "truncated": evidence["status"] = "limit-exceeded"
                if case == "duplicate": evidence["updates"].append(evidence["updates"][0])
                if case == "over-limit": evidence["updates"] = evidence["updates"] * 129
                if case == "wrong-source": evidence["source"] = "vendor-url"
                if case == "missing-time": evidence["observed_at"] = None
                with self.assertRaises(ValidationError):
                    confirm_software_inventory(enrollment, document=invalid, agent_version="0.2.30")

    def test_agent_revision_difference_and_stale_evidence_are_explicit(self):
        from ipms.apps.agent_pki.services import confirm_software_inventory
        enrollment = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=self.server.source_id,
            display_name="server", platform="windows", status="active",
        )
        self.document["computers"] = []
        doc = self.agent_document()
        doc["windows_update_evidence"]["updates"][0]["revision"] = 2
        doc["windows_update_evidence"]["observed_at"] = (timezone.now() - timedelta(days=3)).isoformat()
        confirm_software_inventory(enrollment, document=doc, agent_version="0.2.30")
        self.assertEqual(self.upload().status_code, 201)
        row = self.comparison()["results"][0]
        self.assertEqual(row["agent_evidence"]["revision_mismatches"], 1)
        self.assertTrue(row["agent_evidence"]["stale"])
        self.assertEqual(row["agent_evidence"]["installed_matches"], 0)
