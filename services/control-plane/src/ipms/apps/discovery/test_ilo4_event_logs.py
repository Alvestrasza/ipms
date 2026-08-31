from django.test import SimpleTestCase

from .connectors.ilo4_event_logs import discover_ilo4_event_logs


class Ilo4EventLogAdapterTests(SimpleTestCase):
    def test_normalizes_iml_and_iel_without_write_requests(self) -> None:
        documents = {
            "/systems/logs": {"links": {"Member": [{"href": "/systems/iml"}]}},
            "/systems/iml": {"Links": {"Entries": {"href": "/systems/iml/entries"}}},
            "/systems/iml/entries": {"links": {"Member": [{"href": "/systems/iml/1"}]}},
            "/systems/iml/1": {
                "Id": "1",
                "RecordId": 1,
                "Severity": "Warning",
                "Message": "Synthetic hardware warning",
                "Created": "2026-08-30T10:00:00Z",
                "Number": 2,
                "OemRecordFormat": "Hp-IML",
                "Oem": {"Hp": {"Class": 7, "Code": 3, "EventNumber": 9, "Repaired": False}},
            },
            "/managers/logs": {"Members": [{"@odata.id": "/managers/iel"}]},
            "/managers/iel": {"Entries": {"@odata.id": "/managers/iel/entries"}},
            "/managers/iel/entries": {"Members": [{"@odata.id": "/managers/iel/2"}]},
            "/managers/iel/2": {
                "RecordId": "2",
                "Severity": "OK",
                "Message": "Synthetic management event",
                "Created": "2026-08-30T11:00:00Z",
                "OemRecordFormat": "Hp-iLOEventLog",
                "Oem": {"Hp": {"Updated": "2026-08-30T11:01:00Z"}},
            },
        }
        calls = []

        def get(path: str):
            calls.append(path)
            return documents[path]

        snapshot = discover_ilo4_event_logs(
            get,
            system={"Links": {"LogServices": {"href": "/systems/logs"}}},
            manager={"LogServices": {"@odata.id": "/managers/logs"}},
        )

        self.assertEqual(len(snapshot.entries), 2)
        self.assertEqual(snapshot.entries[0]["log_type"], "integrated_management_log")
        self.assertEqual(snapshot.entries[0]["severity"], "warning")
        self.assertEqual(snapshot.entries[0]["repeat_count"], 2)
        self.assertEqual(snapshot.entries[1]["log_type"], "ilo_event_log")
        self.assertEqual(snapshot.entries[1]["severity"], "info")
        self.assertEqual(set(calls), set(documents))
