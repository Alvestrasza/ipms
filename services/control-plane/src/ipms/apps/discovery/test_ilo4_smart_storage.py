from django.test import SimpleTestCase

from .connectors.ilo4_smart_storage import (
    SmartStorageAdapterError,
    discover_smart_storage,
)


class Ilo4SmartStorageAdapterTests(SimpleTestCase):
    def setUp(self) -> None:
        self.documents = {
            "/redfish/v1/Systems/1/SmartStorage/": {
                "Status": {"HealthRollup": "OK", "State": "Enabled"},
                "Links": {
                    "ArrayControllers": {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/"
                    },
                    "HostBusAdapters": {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/HostBusAdapters/"
                    },
                },
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/": {
                "Members": [
                    {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/"
                    }
                ]
            },
            "/redfish/v1/Systems/1/SmartStorage/HostBusAdapters/": {"Members": []},
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/": {
                "Name": "Synthetic Smart Array",
                "Manufacturer": "Example",
                "Model": "Array Fixture",
                "SerialNumber": "SYNTHETIC-CONTROLLER",
                "FirmwareVersion": "1.0",
                "AdapterType": "SmartArray",
                "CurrentOperatingMode": "RAID",
                "LogicalDriveCount": 1,
                "PhysicalDriveCount": 1,
                "CacheMemorySizeMiB": 2048,
                "BackupPowerSourceStatus": "PresentAndCharged",
                "Status": {"Health": "OK", "State": "Enabled"},
                "Links": {
                    "LogicalDrives": {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/LogicalDrives/"
                    },
                    "DiskDrives": {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/DiskDrives/"
                    },
                    "StorageEnclosures": {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/StorageEnclosures/"
                    },
                },
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/LogicalDrives/": {
                "Members": [
                    {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/LogicalDrives/1/"
                    }
                ]
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/LogicalDrives/1/": {
                "Name": "Logical Drive 1",
                "LogicalDriveName": "OS volume",
                "CapacityMiB": 102400,
                "Raid": "1",
                "LogicalDriveType": "Data",
                "Status": {"Health": "OK", "State": "Enabled"},
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/DiskDrives/": {
                "Members": [
                    {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/DiskDrives/1/"
                    }
                ]
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/DiskDrives/1/": {
                "Name": "Physical Drive 1",
                "Model": "Synthetic SSD",
                "SerialNumber": "SYNTHETIC-DRIVE",
                "CapacityGB": 960,
                "MediaType": "SSD",
                "InterfaceType": "SAS",
                "InterfaceSpeedMbps": 12000,
                "Location": "1I:1:1",
                "Status": {"Health": "OK", "State": "Enabled"},
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/StorageEnclosures/": {
                "Members": [
                    {
                        "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/StorageEnclosures/1/"
                    }
                ]
            },
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/StorageEnclosures/1/": {
                "Name": "Internal enclosure",
                "DriveBayCount": 8,
                "Status": {"Health": "OK", "State": "Enabled"},
            },
        }
        self.calls: list[str] = []

    def get(self, path: str):
        self.calls.append(path)
        return self.documents[path]

    def test_normalizes_advertised_ilo4_smart_storage_graph(self) -> None:
        system = {
            "Oem": {
                "Hp": {
                    "Links": {
                        "SmartStorage": {
                            "@odata.id": "/redfish/v1/Systems/1/SmartStorage/"
                        }
                    }
                }
            }
        }

        snapshot = discover_smart_storage(self.get, system)

        self.assertEqual(snapshot.health, "ok")
        self.assertEqual(snapshot.battery_health, "ok")
        self.assertEqual(
            [item["device_type"] for item in snapshot.storage],
            ["storage_controller", "logical_drive"],
        )
        self.assertEqual(snapshot.storage[1]["raid"], "1")
        self.assertEqual(snapshot.storage[1]["capacity_bytes"], 102400 * 1024**2)
        self.assertEqual(
            [item["device_type"] for item in snapshot.device_inventory],
            ["physical_drive", "storage_enclosure"],
        )
        self.assertEqual(snapshot.device_inventory[0]["capacity_bytes"], 960_000_000_000)
        self.assertTrue(
            all(item["source"] == "hpe_ilo4_smart_storage" for item in snapshot.storage)
        )
        self.assertEqual(set(self.calls), set(self.documents))

    def test_skips_adapter_when_smart_storage_is_not_advertised(self) -> None:
        snapshot = discover_smart_storage(self.get, {"Oem": {"Hp": {"Links": {}}}})

        self.assertEqual(snapshot.storage, [])
        self.assertEqual(snapshot.device_inventory, [])
        self.assertEqual(self.calls, [])

    def test_rejects_oversized_controller_collection(self) -> None:
        self.documents[
            "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/"
        ]["Members"] = [
            {"@odata.id": f"/redfish/v1/Systems/1/SmartStorage/ArrayControllers/{index}/"}
            for index in range(33)
        ]
        system = {
            "SmartStorage": {
                "@odata.id": "/redfish/v1/Systems/1/SmartStorage/"
            }
        }

        with self.assertRaisesRegex(
            SmartStorageAdapterError,
            "collection_limit_exceeded",
        ):
            discover_smart_storage(self.get, system)
