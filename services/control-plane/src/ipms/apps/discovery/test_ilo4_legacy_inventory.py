from django.test import SimpleTestCase

from .connectors.ilo4_legacy_inventory import discover_ilo4_legacy_inventory


class Ilo4LegacyInventoryAdapterTests(SimpleTestCase):
    def setUp(self) -> None:
        self.documents = {
            "/redfish/v1/Systems/1/": {
                "Oem": {
                    "Hp": {
                        "links": {
                            "Memory": {
                                "href": "/redfish/v1/Systems/1/Memory/"
                            },
                            "PCIDevices": {
                                "href": "/redfish/v1/Systems/1/PCIDevices/"
                            },
                        }
                    }
                }
            },
            "/redfish/v1/Systems/1/Memory/": {
                "Members": [
                    {"href": "/redfish/v1/Systems/1/Memory/1/"},
                    {"href": "/redfish/v1/Systems/1/Memory/2/"},
                ]
            },
            "/redfish/v1/Systems/1/Memory/1/": {
                "Name": "DIMM 1",
                "SocketLocator": "PROC 1 DIMM 1",
                "SizeMB": 32768,
                "MaximumFrequencyMHz": 2400,
                "DIMMType": "DDR4",
                "DIMMTechnology": "RDIMM",
                "DIMMStatus": "GoodInUse",
                "Manufacturer": "Example",
                "PartNumber": "SYNTHETIC-DIMM",
            },
            "/redfish/v1/Systems/1/Memory/2/": {
                "Name": "DIMM 2",
                "SocketLocator": "PROC 1 DIMM 2",
                "DIMMStatus": "NotPresent",
            },
            "/redfish/v1/Systems/1/PCIDevices/": {
                "links": {
                    "Member": [
                        {"href": "/redfish/v1/Systems/1/PCIDevices/1/"},
                        {"href": "/redfish/v1/Systems/1/PCIDevices/2/"},
                    ]
                }
            },
            "/redfish/v1/Systems/1/PCIDevices/1/": {
                "Name": "Synthetic storage controller",
                "DeviceType": "Other PCI Device",
                "DeviceLocation": "Slot 2",
                "StructuredName": "PCI.Slot.2.1",
                "ClassCode": 12,
                "SubclassCode": 4,
                "VendorID": 4660,
                "DeviceID": 22136,
            },
            "/redfish/v1/Systems/1/PCIDevices/2/": {
                "Name": "Synthetic video controller",
                "DeviceType": "Video",
                "DeviceLocation": "Embedded",
            },
        }
        self.calls: list[str] = []

    def get(self, path: str):
        self.calls.append(path)
        return self.documents[path]

    def test_normalizes_advertised_href_memory_and_pci_resources(self) -> None:
        system = {
            "@odata.id": "/redfish/v1/Systems/1/",
            "Oem": {
                "Hp": {
                    "Links": {
                        "Memory": {"@odata.id": "/redfish/v1/Systems/1/Memory/"},
                        "PCIDevices": {
                            "@odata.id": "/redfish/v1/Systems/1/PCIDevices/"
                        },
                    }
                }
            },
        }

        snapshot = discover_ilo4_legacy_inventory(self.get, system)

        self.assertEqual(len(snapshot.memory), 2)
        self.assertEqual(snapshot.memory[0]["capacity_mib"], 32768)
        self.assertEqual(snapshot.memory[0]["memory_type"], "DDR4 / RDIMM")
        self.assertEqual(snapshot.memory[0]["status"], "ok")
        self.assertEqual(snapshot.memory[1]["state"], "NotPresent")
        self.assertEqual(snapshot.memory[1]["status"], "unknown")
        self.assertEqual(len(snapshot.device_inventory), 2)
        self.assertEqual(
            snapshot.device_inventory[0]["device_type"],
            "fibre_channel_adapter",
        )
        self.assertEqual(snapshot.device_inventory[0]["wwpn"], "")
        self.assertEqual(
            snapshot.device_inventory[0]["wwn_source"],
            "unavailable_in_ilo4_redfish",
        )
        self.assertEqual(len(snapshot.network), 1)
        self.assertEqual(set(self.calls), set(self.documents))

    def test_skips_legacy_fetch_when_no_oem_inventory_link_is_advertised(self) -> None:
        snapshot = discover_ilo4_legacy_inventory(
            self.get,
            {"@odata.id": "/redfish/v1/Systems/1/", "Oem": {"Hp": {}}},
        )

        self.assertEqual(snapshot.memory, [])
        self.assertEqual(snapshot.network, [])
        self.assertEqual(snapshot.device_inventory, [])
        self.assertEqual(self.calls, [])
