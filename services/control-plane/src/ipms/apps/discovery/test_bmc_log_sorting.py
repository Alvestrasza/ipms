# File Name: test_bmc_log_sorting.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant-scoped BMC log ordering and bounded, spreadsheet-safe CSV.
import csv
import io
import uuid
from datetime import datetime, timedelta, timezone

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from ipms.apps.tenancy.models import Tenant, TenantMembership

from .models import BmcCommunicationLog, BmcEventLogEntry, ConnectorEndpoint
from .views import _csv_safe


class BmcCsvSafetyTests(SimpleTestCase):
    def test_formulas_after_whitespace_and_control_characters_are_neutralized(self):
        for prefix in ("", " ", "\t", "\r\n", "\x00\x1b", "\x7f\x85", "\u200b\ufeff", " \t\x00\n"):
            for operator in "=+-@":
                value = f"{prefix}{operator}SUM(1,2)"
                with self.subTest(prefix=repr(prefix), operator=operator):
                    self.assertEqual(_csv_safe(value), "'" + value)

    def test_plain_values_and_existing_text_quotes_are_preserved(self):
        for value in ("", " plain", "\tordinary", "text=1", "'=1", "123", "\x00"):
            with self.subTest(value=repr(value)):
                self.assertEqual(_csv_safe(value), value)
        self.assertEqual(_csv_safe(None), "")
        self.assertEqual(_csv_safe(42), "42")


class BmcLogSortingTests(TestCase):
    timestamp = datetime(2026, 9, 14, 12, tzinfo=timezone.utc)

    @classmethod
    def setUpTestData(cls):
        cls.tenant = Tenant.objects.create(slug="bmc-log-sort", display_name="Log tenant")
        cls.other = Tenant.objects.create(slug="other-log-sort", display_name="Other tenant")
        cls.user = get_user_model().objects.create_user(username="log-reader")
        TenantMembership.objects.create(
            tenant=cls.tenant, user=cls.user, role=TenantMembership.Role.READER,
        )
        cls.connector = ConnectorEndpoint.objects.create(
            tenant=cls.tenant,
            connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
            display_name="Synthetic BMC",
            base_url="https://bmc.example.invalid",
            tls_certificate_sha256="a" * 64,
        )
        cls.other_connector = ConnectorEndpoint.objects.create(
            tenant=cls.other,
            connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
            display_name="Other synthetic BMC",
            base_url="https://other-bmc.example.invalid",
            tls_certificate_sha256="b" * 64,
        )

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))

    def record(self, kind, index, **changes):
        values = {
            "id": uuid.UUID(int=index),
            "tenant": self.tenant,
            "bmc_name": f"BMC {index:05d}",
            "severity": "info",
        }
        if kind == "communication":
            values.update(
                bmc_family="hpe-ilo4", event_type="poll", correlation_id=values["id"],
            )
            model = BmcCommunicationLog
        else:
            values.update(
                log_type=BmcEventLogEntry.LogType.ILO_EVENT_LOG,
                source_record_id=str(values["id"]),
                message="Synthetic event",
                source_created_at=self.timestamp,
                last_discovered_at=self.timestamp,
            )
            model = BmcEventLogEntry
        values.update(changes)
        return model(**values)

    def create(self, kind, index, **changes):
        occurred_at = changes.pop("occurred_at", self.timestamp)
        row = self.record(kind, index, **changes)
        row.save()
        if kind == "communication":
            BmcCommunicationLog.objects.filter(pk=row.pk).update(occurred_at=occurred_at)
        return row

    def url(self, kind, export=False):
        name = "bmc-log" if kind == "communication" else "bmc-event-log"
        return reverse(f"core:{name}-{'export' if export else 'list'}")

    def exported_rows(self, response):
        self.assertEqual(response.status_code, 200, response.content[:300])
        self.assertTrue(response.content.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(response["Cache-Control"], "private, no-store")
        return list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))

    def assert_order(self, kind, parameters, expected):
        listed = self.client.get(self.url(kind), parameters)
        self.assertEqual(listed.status_code, 200, listed.content[:300])
        expected_ids = [str(uuid.UUID(int=index)) for index in expected]
        self.assertEqual([row["id"] for row in listed.json()], expected_ids)
        exported = self.exported_rows(self.client.get(self.url(kind, True), parameters))
        marker = "correlation_id" if kind == "communication" else "source_record_id"
        self.assertEqual([row[marker] for row in exported], expected_ids)

    def test_communication_sorting_and_stable_ties_match_csv(self):
        self.create("communication", 1, bmc_name="Bravo", severity="warning")
        self.create("communication", 2, bmc_name="Alpha", occurred_at=self.timestamp - timedelta(days=2))
        self.create("communication", 3, bmc_name="Charlie", severity="error", occurred_at=self.timestamp - timedelta(days=1))
        self.create("communication", 4, bmc_name="Bravo", severity="debug")
        self.assert_order("communication", {}, [1, 4, 3, 2])
        for sort, ascending, descending in (
            ("occurred_at", [2, 3, 1, 4], [1, 4, 3, 2]),
            ("severity", [4, 2, 1, 3], [3, 1, 2, 4]),
            ("bmc", [2, 1, 4, 3], [3, 1, 4, 2]),
        ):
            for direction, expected in (("asc", ascending), ("desc", descending)):
                with self.subTest(sort=sort, direction=direction):
                    self.assert_order("communication", {"sort": sort, "direction": direction}, expected)

    def test_event_sorting_keeps_missing_times_last_in_both_directions(self):
        self.create("event", 1, bmc_name="Bravo", severity="warning")
        self.create("event", 2, bmc_name="Alpha", source_created_at=self.timestamp - timedelta(days=2))
        self.create("event", 3, bmc_name="Charlie", severity="critical", source_created_at=self.timestamp - timedelta(days=1))
        self.create("event", 4, bmc_name="Bravo", severity="unknown", source_created_at=None)
        self.create("event", 5, bmc_name="Delta")
        self.assert_order("event", {}, [1, 5, 3, 2, 4])
        for sort, ascending, descending in (
            ("source_created_at", [2, 3, 1, 5, 4], [1, 5, 3, 2, 4]),
            ("severity", [4, 2, 5, 1, 3], [3, 1, 2, 5, 4]),
            ("bmc", [2, 1, 4, 3, 5], [5, 3, 1, 4, 2]),
        ):
            for direction, expected in (("asc", ascending), ("desc", descending)):
                with self.subTest(sort=sort, direction=direction):
                    self.assert_order("event", {"sort": sort, "direction": direction}, expected)

    def test_sort_and_direction_are_allowlisted_for_lists_and_exports(self):
        for kind in ("communication", "event"):
            for export in (False, True):
                for parameters in (
                    {"sort": "id"}, {"sort": "connector__tenant"}, {"sort": ""},
                    {"sort": "bmc;SELECT"}, {"direction": "up"},
                    {"direction": "DESC"}, {"direction": ""},
                ):
                    with self.subTest(kind=kind, export=export, parameters=parameters):
                        response = self.client.get(self.url(kind, export), parameters)
                        self.assertEqual(response.status_code, 400)
                        self.assertEqual(response.json()["error"]["code"], "invalid_request")

    def test_filters_preserve_repeated_severities_and_tenant_isolation(self):
        other_client = APIClient()
        other_client.force_authenticate(self.user)
        other_client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        for kind in ("communication", "event"):
            self.create(kind, 1, bmc_name="Keep Bravo", severity="warning", connector=self.connector)
            self.create(kind, 2, bmc_name="Keep Alpha", severity="info", connector=self.connector)
            self.create(kind, 3, bmc_name="Different", connector=self.connector)
            self.create(kind, 4, bmc_name="Keep but disconnected")
            self.create(kind, 5, tenant=self.other, bmc_name="Keep other", connector=self.other_connector)
            parameters = {
                "severity": ["warning", "info,warning"],
                "connector": str(self.connector.id),
                "q": "Keep",
                "from": "2026-09-14T00:00:00Z",
                "to": "2026-09-14T23:59:59Z",
                "sort": "bmc", "direction": "asc",
            }
            if kind == "event":
                parameters["log_type"] = ["ilo_event_log", "integrated_management_log"]
            with self.subTest(kind=kind):
                self.assert_order(kind, parameters, [2, 1])
                self.assert_order(kind, {"q": "Keep", "sort": "bmc", "direction": "asc"}, [2, 1, 4])
                self.assert_order(kind, {"connector": str(self.other_connector.id)}, [])
                for export in (False, True):
                    forbidden = other_client.get(self.url(kind, export), parameters)
                    self.assertEqual(forbidden.status_code, 404)

    def test_csv_neutralizes_formula_cells_but_preserves_list_values(self):
        name = " \t\x00=SUM(1,2)"
        message = "\r\n@SUM(1,2)"
        for kind in ("communication", "event"):
            changes = {"message": message} if kind == "event" else {"resource_path": message}
            self.create(kind, 1, bmc_name=name, **changes)
            with self.subTest(kind=kind):
                response = self.client.get(self.url(kind))
                self.assertEqual(response.json()[0]["bmc_name"], name)
                rows = self.exported_rows(self.client.get(self.url(kind, True)))
                self.assertEqual(rows[0]["bmc"], "'" + name)
                field = "message" if kind == "event" else "resource_path"
                self.assertEqual(rows[0][field], "'" + message)

    def test_communication_export_limit_is_explicit_and_applies_after_filters(self):
        self.check_export_limit("communication", BmcCommunicationLog)

    def test_event_export_limit_is_explicit_and_applies_after_filters(self):
        self.check_export_limit("event", BmcEventLogEntry)

    def check_export_limit(self, kind, model):
        model.objects.bulk_create([self.record(kind, index) for index in range(1, 10001)])
        self.create(kind, 20000, tenant=self.other)
        parameters = {"sort": "bmc", "direction": "asc"}
        rows = self.exported_rows(self.client.get(self.url(kind, True), parameters))
        self.assertEqual(len(rows), 10000)
        self.assertEqual(rows[0]["bmc"], "BMC 00001")
        self.assertEqual(rows[-1]["bmc"], "BMC 10000")
        self.create(kind, 10001, bmc_name="Only extra")
        oversized = self.client.get(self.url(kind, True), parameters)
        self.assertEqual(oversized.status_code, 400)
        self.assertEqual(oversized.json()["error"]["code"], "log_export_limit_exceeded")
        self.assert_order(kind, {**parameters, "q": "Only extra"}, [10001])
        listed = self.client.get(self.url(kind), parameters)
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(len(listed.json()), 500)
        self.assertEqual(listed.json()[-1]["bmc_name"], "BMC 00500")

    def test_log_endpoints_reject_write_methods(self):
        for kind in ("communication", "event"):
            for export in (False, True):
                with self.subTest(kind=kind, export=export):
                    response = self.client.post(self.url(kind, export), {}, format="json")
                    self.assertEqual(response.status_code, 405)
        self.assertFalse(BmcCommunicationLog.objects.exists())
        self.assertFalse(BmcEventLogEntry.objects.exists())
