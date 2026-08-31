import json
import uuid
from dataclasses import asdict
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .certificates import CertificateObservation, create_certificate_trust_token
from .connectors.ilo_redfish import (
    RedfishConnectorError,
    RedfishTransport,
    _safe_redfish_error_identifiers,
    discover_ilo,
)
from .models import (
    BmcCommunicationLog,
    ConnectorEndpoint,
    ConnectorSecret,
    DiscoveryJob,
    PhysicalSystem,
)
from .secrets import load_connector_secret
from .services import process_discovery_queue


class DiscoveryJobApiTests(TestCase):
    def setUp(self) -> None:
        user_model = get_user_model()
        self.platform_admin = user_model.objects.create_user(
            username="platform-admin",
            password="test-only-password",
            is_staff=True,
        )
        self.tenant_reader = user_model.objects.create_user(
            username="tenant-reader",
            password="test-only-password",
        )
        self.tenant = Tenant.objects.create(slug="example", display_name="Example")
        self.other_tenant = Tenant.objects.create(
            slug="other",
            display_name="Other",
        )
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.tenant_reader,
            role=TenantMembership.Role.READER,
        )
        self.job = DiscoveryJob.objects.create(
            tenant=self.tenant,
            connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
            requested_by="platform-admin",
        )
        self.other_job = DiscoveryJob.objects.create(
            tenant=self.other_tenant,
            connector_type=DiscoveryJob.ConnectorType.HYPER_V,
            requested_by="platform-admin",
        )
        self.list_url = reverse("core:discovery:job-list")

    def tenant_header(self, tenant: Tenant | None = None) -> dict[str, str]:
        return {"HTTP_X_IPMS_TENANT_ID": str((tenant or self.tenant).id)}

    def test_platform_admin_must_select_and_is_scoped_to_one_tenant(self) -> None:
        self.client.force_login(self.platform_admin)

        response = self.client.get(self.list_url, **self.tenant_header())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 1)
        self.assertEqual(response.json()[0]["id"], str(self.job.id))
        self.assertNotIn("parameters", response.json()[0])

    def test_tenant_reader_can_list_jobs_for_own_tenant(self) -> None:
        self.client.force_login(self.tenant_reader)

        response = self.client.get(self.list_url, **self.tenant_header())

        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["id"] for item in response.json()], [str(self.job.id)])

    def test_missing_tenant_context_is_rejected(self) -> None:
        self.client.force_login(self.platform_admin)

        response = self.client.get(self.list_url)

        self.assertEqual(response.status_code, 400)

    def test_cross_tenant_access_does_not_reveal_tenant(self) -> None:
        self.client.force_login(self.tenant_reader)

        response = self.client.get(
            self.list_url,
            **self.tenant_header(self.other_tenant),
        )

        self.assertEqual(response.status_code, 404)

    def test_cross_tenant_job_detail_is_not_found(self) -> None:
        self.client.force_login(self.tenant_reader)
        detail_url = reverse(
            "core:discovery:job-detail",
            kwargs={"pk": self.other_job.id},
        )

        response = self.client.get(detail_url, **self.tenant_header())

        self.assertEqual(response.status_code, 404)

    def test_anonymous_user_is_denied_with_common_error_shape(self) -> None:
        response = self.client.get(self.list_url, **self.tenant_header())

        self.assertEqual(response.status_code, 403)
        error = response.json()["error"]
        self.assertEqual(error["code"], "forbidden")
        uuid.UUID(error["correlation_id"])
        self.assertEqual(
            response.headers["X-Correlation-ID"],
            error["correlation_id"],
        )

    def test_state_changing_method_is_not_available(self) -> None:
        self.client.force_login(self.platform_admin)

        response = self.client.post(
            self.list_url,
            data={},
            **self.tenant_header(),
        )

        self.assertEqual(response.status_code, 405)
        self.assertEqual(DiscoveryJob.objects.count(), 2)


class InventoryApiTests(DiscoveryJobApiTests):
    def setUp(self) -> None:
        super().setUp()
        self.endpoint = ConnectorEndpoint.objects.create(
            tenant=self.tenant,
            connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
            display_name="Fixture iLO",
            base_url="https://192.0.2.10",
            tls_certificate_sha256="a" * 64,
        )
        self.system = PhysicalSystem.objects.create(
            tenant=self.tenant,
            connector=self.endpoint,
            source_resource_id="/redfish/v1/Systems/1/",
            name="Fixture server",
            serial_number="SYNTHETIC",
            health=PhysicalSystem.Health.OK,
            discovered_at=timezone.now(),
        )

    def test_connector_projection_excludes_secret_and_pin(self) -> None:
        self.client.force_login(self.tenant_reader)
        response = self.client.get(reverse("core:connector-list"), **self.tenant_header())
        self.assertEqual(response.status_code, 200)
        projection = response.json()[0]
        self.assertNotIn("credential_reference", projection)
        self.assertNotIn("tls_certificate_sha256", projection)

    def test_physical_inventory_is_tenant_scoped(self) -> None:
        self.client.force_login(self.tenant_reader)
        response = self.client.get(reverse("core:physical-list"), **self.tenant_header())
        self.assertEqual(response.status_code, 200)
        self.assertEqual([item["id"] for item in response.json()], [str(self.system.id)])

    def test_inventory_write_is_not_available(self) -> None:
        self.client.force_login(self.platform_admin)
        response = self.client.post(
            reverse("core:physical-list"),
            data={},
            **self.tenant_header(),
        )
        self.assertEqual(response.status_code, 405)


class FakeRedfishTransport:
    def __init__(
        self,
        documents: dict[str, dict],
        legacy_documents: dict[str, dict] | None = None,
    ) -> None:
        self.documents = documents
        self.legacy_documents = legacy_documents or {}
        self.calls: list[tuple[str, str]] = []
        self.session_path = ""

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path))
        if path not in self.documents:
            raise RedfishConnectorError("fixture_missing")
        return self.documents[path]

    def get_ilo4_legacy(self, path: str) -> dict:
        self.calls.append(("GET", path))
        if path not in self.legacy_documents:
            raise RedfishConnectorError("fixture_missing")
        return self.legacy_documents[path]

    def create_session(self, path: str, username: str, password: str) -> None:
        self.calls.append(("POST", path))
        self.session_path = "/redfish/v1/SessionService/Sessions/fixture"

    def delete_session(self) -> None:
        self.calls.append(("DELETE", self.session_path))
        self.session_path = ""


class IloRedfishConnectorTests(TestCase):
    def fixture(self) -> FakeRedfishTransport:
        return FakeRedfishTransport(
            {
                "/redfish/v1/": {
                    "RedfishVersion": "1.0.0",
                    "Systems": {"@odata.id": "/redfish/v1/Systems/"},
                    "Managers": {"@odata.id": "/redfish/v1/Managers/"},
                    "Chassis": {"@odata.id": "/redfish/v1/Chassis/"},
                    "UpdateService": {"@odata.id": "/redfish/v1/UpdateService/"},
                    "Links": {
                        "Sessions": {
                            "@odata.id": "/redfish/v1/SessionService/Sessions/"
                        }
                    },
                },
                "/redfish/v1/Systems/": {
                    "Members": [{"@odata.id": "/redfish/v1/Systems/1/"}]
                },
                "/redfish/v1/Systems/1/": {
                    "Name": "Fixture server",
                    "Manufacturer": "HPE",
                    "Model": "ProLiant Synthetic",
                    "SerialNumber": "SYNTHETIC",
                    "UUID": "00000000-0000-0000-0000-000000000001",
                    "PowerState": "On",
                    "Status": {"Health": "OK", "State": "Enabled"},
                    "ProcessorSummary": {"Count": 2, "Model": "Fixture CPU"},
                    "MemorySummary": {"TotalSystemMemoryGiB": 128},
                    "BiosVersion": "Fixture BIOS",
                    "Processors": {"@odata.id": "/redfish/v1/Systems/1/Processors/"},
                    "Memory": {"@odata.id": "/redfish/v1/Systems/1/Memory/"},
                    "EthernetInterfaces": {
                        "@odata.id": "/redfish/v1/Systems/1/EthernetInterfaces/"
                    },
                    "Storage": {"@odata.id": "/redfish/v1/Systems/1/Storage/"},
                    "Links": {
                        "Chassis": [{"@odata.id": "/redfish/v1/Chassis/1/"}],
                        "PCIeDevices": [
                            {"@odata.id": "/redfish/v1/Chassis/1/PCIeDevices/1/"}
                        ],
                    },
                    "Oem": {
                        "Hp": {
                            "AggregateHealthStatus": {
                                "AgentlessManagementService": "OK",
                                "SmartStorageBattery": "OK",
                                "FanRedundancy": "Redundant",
                            }
                        }
                    },
                },
                "/redfish/v1/Systems/1/Processors/": {
                    "Members": [{"@odata.id": "/redfish/v1/Systems/1/Processors/1/"}]
                },
                "/redfish/v1/Systems/1/Processors/1/": {
                    "Name": "CPU 1",
                    "Model": "Fixture CPU",
                    "Socket": "Proc 1",
                    "TotalCores": 8,
                    "TotalThreads": 16,
                    "MaxSpeedMHz": 3200,
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/Systems/1/Memory/": {
                    "Members": [{"@odata.id": "/redfish/v1/Systems/1/Memory/1/"}]
                },
                "/redfish/v1/Systems/1/Memory/1/": {
                    "Name": "DIMM 1",
                    "DeviceLocator": "PROC 1 DIMM 1",
                    "CapacityMiB": 32768,
                    "OperatingSpeedMhz": 2933,
                    "MemoryDeviceType": "DDR4",
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/Systems/1/EthernetInterfaces/": {
                    "Members": [
                        {"@odata.id": "/redfish/v1/Systems/1/EthernetInterfaces/1/"}
                    ]
                },
                "/redfish/v1/Systems/1/EthernetInterfaces/1/": {
                    "Name": "Embedded NIC 1",
                    "MACAddress": "00:00:00:00:00:01",
                    "SpeedMbps": 1000,
                    "LinkStatus": "LinkUp",
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/Systems/1/Storage/": {
                    "Members": [{"@odata.id": "/redfish/v1/Systems/1/Storage/1/"}]
                },
                "/redfish/v1/Systems/1/Storage/1/": {
                    "Name": "Smart Array",
                    "Status": {"Health": "OK", "State": "Enabled"},
                    "Drives": [{"@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/1/"}],
                },
                "/redfish/v1/Systems/1/Storage/1/Drives/1/": {
                    "Name": "Drive 1",
                    "Model": "Fixture SSD",
                    "CapacityBytes": 1000000000,
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/Chassis/": {
                    "Members": [{"@odata.id": "/redfish/v1/Chassis/1/"}]
                },
                "/redfish/v1/Chassis/1/": {
                    "Name": "Fixture chassis",
                    "Thermal": {"@odata.id": "/redfish/v1/Chassis/1/Thermal/"},
                    "Power": {"@odata.id": "/redfish/v1/Chassis/1/Power/"},
                },
                "/redfish/v1/Chassis/1/Thermal/": {
                    "Fans": [
                        {
                            "Name": "Fan 1",
                            "Reading": 42,
                            "ReadingUnits": "Percent",
                            "Status": {"Health": "OK", "State": "Enabled"},
                        }
                    ],
                    "Temperatures": [
                        {
                            "Name": "Inlet Ambient",
                            "ReadingCelsius": 23,
                            "UpperThresholdCritical": 42,
                            "Status": {"Health": "OK", "State": "Enabled"},
                        }
                    ],
                    "Redundancy": [
                        {"Name": "Fan Redundancy", "Status": {"Health": "OK"}}
                    ],
                },
                "/redfish/v1/Chassis/1/Power/": {
                    "PowerControl": [{"PowerConsumedWatts": 180, "PowerCapacityWatts": 800}],
                    "PowerSupplies": [
                        {
                            "Name": "Power Supply 1",
                            "PowerCapacityWatts": 800,
                            "Status": {"Health": "OK", "State": "Enabled"},
                        }
                    ],
                    "Redundancy": [
                        {"Name": "Power Redundancy", "Status": {"Health": "OK"}}
                    ],
                },
                "/redfish/v1/Chassis/1/PCIeDevices/1/": {
                    "Name": "Embedded Controller",
                    "DeviceType": "SingleFunction",
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/UpdateService/": {
                    "FirmwareInventory": {
                        "@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/"
                    },
                    "SoftwareInventory": {
                        "@odata.id": "/redfish/v1/UpdateService/SoftwareInventory/"
                    },
                },
                "/redfish/v1/UpdateService/FirmwareInventory/": {
                    "Members": [
                        {"@odata.id": "/redfish/v1/UpdateService/FirmwareInventory/1/"}
                    ]
                },
                "/redfish/v1/UpdateService/FirmwareInventory/1/": {
                    "Name": "System ROM",
                    "Version": "Fixture ROM 1.0",
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/UpdateService/SoftwareInventory/": {
                    "Members": [
                        {"@odata.id": "/redfish/v1/UpdateService/SoftwareInventory/1/"}
                    ]
                },
                "/redfish/v1/UpdateService/SoftwareInventory/1/": {
                    "Name": "Agentless Management Service",
                    "Version": "Fixture AMS 1.0",
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
                "/redfish/v1/Managers/": {
                    "Members": [{"@odata.id": "/redfish/v1/Managers/1/"}]
                },
                "/redfish/v1/Managers/1/": {"FirmwareVersion": "iLO 4 fixture"},
            }
        )

    def test_normalizes_ilo4_summary_and_cleans_up_session(self) -> None:
        transport = self.fixture()
        observations, summary = discover_ilo(transport, "fixture", "not-a-secret")
        self.assertEqual(summary, {"redfish_version": "1.0.0", "system_count": "1"})
        self.assertEqual(asdict(observations[0])["memory_bytes"], 128 * 1024**3)
        self.assertEqual(observations[0].bmc_firmware_version, "iLO 4 fixture")
        detail = observations[0].detail_snapshot
        self.assertEqual(detail["schema_version"], 1)
        self.assertEqual(detail["fans"][0]["reading"], 42)
        self.assertEqual(detail["temperatures"][0]["reading_celsius"], 23)
        self.assertEqual(detail["processors"][0]["cores"], 8)
        self.assertEqual(detail["memory"][0]["capacity_mib"], 32768)
        self.assertEqual(detail["network"][0]["link_status"], "LinkUp")
        self.assertEqual(detail["power"]["consumed_watts"], 180)
        self.assertEqual(detail["firmware"][0]["name"], "System ROM")
        self.assertEqual(detail["software"][0]["name"], "Agentless Management Service")
        self.assertEqual(
            next(
                item
                for item in detail["subsystems"]
                if item["key"] == "fan_redundancy"
            )["value"],
            "redundant",
        )
        self.assertEqual(transport.calls[-1][0], "DELETE")
        self.assertEqual({method for method, _ in transport.calls}, {"GET", "POST", "DELETE"})

    def test_uses_advertised_ilo4_legacy_memory_and_pci_inventory(self) -> None:
        transport = self.fixture()
        system = transport.documents["/redfish/v1/Systems/1/"]
        system.pop("Memory")
        system["Oem"]["Hp"]["Links"] = {
            "Memory": {"@odata.id": "/redfish/v1/Systems/1/Memory/"},
            "PCIDevices": {"@odata.id": "/redfish/v1/Systems/1/PCIDevices/"},
        }
        transport.legacy_documents = {
            "/redfish/v1/Systems/1/": {
                "Oem": {
                    "Hp": {
                        "links": {
                            "Memory": {
                                "href": "/redfish/v1/Systems/1/LegacyMemory/"
                            },
                            "PCIDevices": {
                                "href": "/redfish/v1/Systems/1/LegacyPCI/"
                            },
                        }
                    }
                }
            },
            "/redfish/v1/Systems/1/LegacyMemory/": {
                "Members": [
                    {"href": "/redfish/v1/Systems/1/LegacyMemory/1/"}
                ]
            },
            "/redfish/v1/Systems/1/LegacyMemory/1/": {
                "Name": "DIMM 1",
                "SocketLocator": "PROC 1 DIMM 1",
                "SizeMB": 32768,
                "DIMMStatus": "GoodInUse",
            },
            "/redfish/v1/Systems/1/LegacyPCI/": {
                "links": {
                    "Member": [
                        {"href": "/redfish/v1/Systems/1/LegacyPCI/1/"}
                    ]
                }
            },
            "/redfish/v1/Systems/1/LegacyPCI/1/": {
                "Name": "Synthetic adapter",
                "ClassCode": 12,
                "SubclassCode": 4,
                "DeviceLocation": "Slot 2",
            },
        }

        observations, _ = discover_ilo(transport, "fixture", "not-a-secret")

        detail = observations[0].detail_snapshot
        self.assertEqual(detail["memory"][0]["capacity_mib"], 32768)
        self.assertEqual(
            detail["network"][-1]["device_type"],
            "fibre_channel_adapter",
        )
        self.assertEqual(detail["network"][-1]["wwpn"], "")
        self.assertEqual(
            detail["network"][-1]["wwn_source"],
            "unavailable_in_ilo4_redfish",
        )

    def test_uses_advertised_ilo4_smart_storage_when_standard_storage_is_absent(
        self,
    ) -> None:
        transport = self.fixture()
        system = transport.documents["/redfish/v1/Systems/1/"]
        system.pop("Storage")
        system["Oem"]["Hp"]["Links"] = {
            "SmartStorage": {
                "@odata.id": "/redfish/v1/Systems/1/SmartStorage/"
            }
        }
        transport.documents.update(
            {
                "/redfish/v1/Systems/1/SmartStorage/": {
                    "Status": {"HealthRollUp": "OK", "State": "Enabled"},
                    "Links": {
                        "ArrayControllers": {
                            "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/"
                        }
                    },
                },
                "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/": {
                    "Members": [
                        {
                            "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/"
                        }
                    ]
                },
                "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/": {
                    "Name": "Synthetic Smart Array",
                    "Model": "Array Fixture",
                    "BackupPowerSourceStatus": "PresentAndCharged",
                    "Status": {"Health": "OK", "State": "Enabled"},
                    "Links": {
                        "LogicalDrives": {
                            "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/LogicalDrives/"
                        },
                        "DiskDrives": {
                            "@odata.id": "/redfish/v1/Systems/1/SmartStorage/ArrayControllers/1/DiskDrives/"
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
                    "CapacityMiB": 1024,
                    "Raid": "1",
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
                    "CapacityGB": 960,
                    "MediaType": "SSD",
                    "Status": {"Health": "OK", "State": "Enabled"},
                },
            }
        )

        observations, _ = discover_ilo(transport, "fixture", "not-a-secret")

        detail = observations[0].detail_snapshot
        self.assertEqual(
            [item["device_type"] for item in detail["storage"]],
            ["storage_controller", "logical_drive"],
        )
        self.assertEqual(
            next(
                item
                for item in detail["device_inventory"]
                if item["device_type"] == "physical_drive"
            )["capacity_bytes"],
            960_000_000_000,
        )
        self.assertEqual(
            next(
                item for item in detail["subsystems"] if item["key"] == "storage"
            )["status"],
            "ok",
        )
        self.assertEqual({method for method, _ in transport.calls}, {"GET", "POST", "DELETE"})

    def test_transport_rejects_managed_infrastructure_writes(self) -> None:
        transport = RedfishTransport("https://192.0.2.10", "a" * 64)
        for method, path in (
            ("PATCH", "/redfish/v1/Systems/1/"),
            ("PUT", "/redfish/v1/Systems/1/"),
            ("POST", "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"),
            ("DELETE", "/redfish/v1/Systems/1/"),
        ):
            with self.subTest(method=method):
                with self.assertRaisesRegex(RedfishConnectorError, "request_method_rejected"):
                    transport.request_json(method, path)

    @patch.object(RedfishTransport, "request_json")
    def test_ilo4_legacy_get_omits_odata_version(self, request_json) -> None:
        request_json.return_value = ({}, {}, 200)
        transport = RedfishTransport("https://192.0.2.10", "a" * 64)

        transport.get_ilo4_legacy("/redfish/v1/Systems/1/")

        request_json.assert_called_once_with(
            "GET",
            "/redfish/v1/Systems/1/",
            include_odata_version=False,
        )

    def test_extracts_only_bounded_redfish_error_identifiers(self) -> None:
        content = json.dumps(
            {
                "error": {
                    "code": "iLO.0.10.ExtendedInfo",
                    "message": "must not be retained",
                    "@Message.ExtendedInfo": [
                        {
                            "MessageId": "Base.1.0.SessionLimitExceeded",
                            "Message": "must not be retained",
                            "MessageArgs": ["sensitive-value"],
                        }
                    ],
                }
            }
        ).encode()

        detail = _safe_redfish_error_identifiers(content)

        self.assertEqual(
            detail,
            {
                "redfish_error_code": "iLO.0.10.ExtendedInfo",
                "redfish_message_id": "Base.1.0.SessionLimitExceeded",
            },
        )
        self.assertNotIn("sensitive", str(detail))

    def test_rejects_unbounded_or_malformed_error_identifiers(self) -> None:
        content = json.dumps(
            {
                "error": {
                    "code": "unsafe identifier with spaces",
                    "@Message.ExtendedInfo": [{"MessageId": "x" * 129}],
                }
            }
        ).encode()

        self.assertEqual(_safe_redfish_error_identifiers(content), {})
        self.assertEqual(_safe_redfish_error_identifiers(b"not-json"), {})

    @patch.object(RedfishTransport, "_connection")
    def test_normalizes_ilo4_http_400_unauthorized_login(self, connection) -> None:
        response = Mock()
        response.status = 400
        response.read.return_value = json.dumps(
            {
                "error": {
                    "code": "iLO.0.10.ExtendedInfo",
                    "@Message.ExtendedInfo": [
                        {"MessageId": "iLO.0.10.UnauthorizedLoginAttempt"}
                    ],
                }
            }
        ).encode()
        response.getheaders.return_value = []
        connection.return_value.getresponse.return_value = response
        exchanges = []
        transport = RedfishTransport(
            "https://192.0.2.10",
            "a" * 64,
            event_callback=exchanges.append,
        )

        with self.assertRaises(RedfishConnectorError) as captured:
            transport.request_json(
                "POST",
                "/redfish/v1/SessionService/Sessions/",
                payload={"UserName": "fixture", "Password": "not-a-secret"},
            )

        self.assertEqual(captured.exception.code, "authentication_failed")
        self.assertEqual(
            captured.exception.detail["redfish_message_id"],
            "iLO.0.10.UnauthorizedLoginAttempt",
        )
        self.assertNotIn("not-a-secret", str(captured.exception.detail))
        self.assertEqual(exchanges[0]["error_code"], "authentication_failed")
        self.assertEqual(exchanges[0]["http_status"], 400)
        self.assertNotIn("not-a-secret", str(exchanges))
        self.assertNotIn("Password", str(exchanges))

    @patch.object(RedfishTransport, "request_json")
    def test_session_accepts_absolute_location_only_for_same_pinned_authority(
        self, request_json
    ) -> None:
        request_json.return_value = (
            {},
            {
                "x-auth-token": "synthetic-token",
                "location": (
                    "https://192.0.2.10/redfish/v1/SessionService/Sessions/fixture"
                ),
            },
            201,
        )
        transport = RedfishTransport("https://192.0.2.10", "a" * 64)

        transport.create_session(
            "/redfish/v1/SessionService/Sessions/", "fixture", "not-a-secret"
        )

        self.assertEqual(
            transport.session_path,
            "/redfish/v1/SessionService/Sessions/fixture",
        )

    @patch.object(RedfishTransport, "request_json")
    def test_session_rejects_absolute_location_for_another_authority(
        self, request_json
    ) -> None:
        request_json.return_value = (
            {},
            {
                "x-auth-token": "synthetic-token",
                "location": (
                    "https://192.0.2.11/redfish/v1/SessionService/Sessions/fixture"
                ),
            },
            201,
        )
        transport = RedfishTransport("https://192.0.2.10", "a" * 64)

        with self.assertRaisesRegex(RedfishConnectorError, "session_creation_failed"):
            transport.create_session(
                "/redfish/v1/SessionService/Sessions/", "fixture", "not-a-secret"
            )


class IloPortalEnrollmentTests(TestCase):
    def setUp(self) -> None:
        user_model = get_user_model()
        self.admin = user_model.objects.create_user("tenant-admin", password="test-password")
        self.reader = user_model.objects.create_user("reader", password="test-password")
        self.tenant = Tenant.objects.create(slug="wizard", display_name="Wizard")
        self.other_tenant = Tenant.objects.create(slug="other-wizard", display_name="Other")
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.admin,
            role=TenantMembership.Role.TENANT_ADMIN,
        )
        TenantMembership.objects.create(
            tenant=self.tenant,
            user=self.reader,
            role=TenantMembership.Role.READER,
        )
        self.certificate = CertificateObservation(
            fingerprint_sha256="ab" * 32,
            subject="CN=synthetic-bmc",
            issuer="CN=synthetic-ca",
            serial_number="01",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            dns_names=("synthetic-bmc.example.invalid",),
            trusted_by_system=False,
        )
        probe = patch(
            "ipms.apps.discovery.views.probe_bmc_certificate",
            return_value=self.certificate,
        )
        self.probe_certificate = probe.start()
        self.addCleanup(probe.stop)
        self.payload = {
            "bmc_family": "hpe-ilo4",
            "display_name": "Synthetic iLO",
            "address": "192.0.2.10",
            "port": 443,
            "username": "readonly-user",
            "password": "test-only-secret",
            "certificate_trust_token": create_certificate_trust_token(
                tenant_id=str(self.tenant.id),
                base_url="https://192.0.2.10/",
                observation=self.certificate,
            ),
            "confirm_certificate_trust": True,
        }

    def post(self, user, tenant, payload=None):
        self.client.force_login(user)
        return self.client.post(
            reverse("core:bmc-enroll"),
            data=payload or self.payload,
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(tenant.id)},
        )

    def test_tenant_admin_enrolls_with_encrypted_write_only_secret_and_queued_job(self) -> None:
        response = self.post(self.admin, self.tenant)
        self.assertEqual(response.status_code, 201)
        endpoint = ConnectorEndpoint.objects.get()
        secret = ConnectorSecret.objects.get()
        job = DiscoveryJob.objects.get()
        self.assertEqual(secret.id, endpoint.credential_reference)
        self.assertNotIn(b"readonly-user", bytes(secret.ciphertext))
        self.assertNotIn(b"test-only-secret", bytes(secret.ciphertext))
        self.assertEqual(
            load_connector_secret(tenant_id=self.tenant.id, secret_id=secret.id),
            ("readonly-user", "test-only-secret"),
        )
        self.assertEqual(job.status, DiscoveryJob.Status.QUEUED)
        self.assertEqual(
            AuditEvent.objects.get(action="connector.enroll").tenant,
            self.tenant,
        )
        document = response.json()
        serialized = str(document)
        self.assertNotIn("readonly-user", serialized)
        self.assertNotIn("test-only-secret", serialized)
        self.assertNotIn("credential_reference", serialized)
        self.assertNotIn("certificate_sha256", serialized)

    def test_reader_cannot_enroll_connector(self) -> None:
        response = self.post(self.reader, self.tenant)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ConnectorEndpoint.objects.exists())

    def test_inaccessible_tenant_is_not_disclosed(self) -> None:
        response = self.post(self.admin, self.other_tenant)
        self.assertEqual(response.status_code, 404)

    def test_requires_valid_address_and_port(self) -> None:
        payload = {**self.payload, "address": "https://192.0.2.10/redfish", "port": 0}
        response = self.post(self.admin, self.tenant, payload)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ConnectorEndpoint.objects.exists())

    def test_requires_explicit_certificate_trust(self) -> None:
        response = self.post(
            self.admin,
            self.tenant,
            {**self.payload, "confirm_certificate_trust": False},
        )
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ConnectorEndpoint.objects.exists())

    def test_duplicate_endpoint_is_rejected_without_replacing_credential(self) -> None:
        self.assertEqual(self.post(self.admin, self.tenant).status_code, 201)
        original_ciphertext = bytes(ConnectorSecret.objects.get().ciphertext)
        response = self.post(
            self.admin,
            self.tenant,
            {**self.payload, "password": "replacement-test-secret"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(ConnectorEndpoint.objects.count(), 1)
        self.assertEqual(bytes(ConnectorSecret.objects.get().ciphertext), original_ciphertext)

    def test_tenant_admin_can_queue_a_repeat_discovery(self) -> None:
        self.assertEqual(self.post(self.admin, self.tenant).status_code, 201)
        endpoint = ConnectorEndpoint.objects.get()
        DiscoveryJob.objects.all().delete()
        response = self.client.post(
            reverse("core:connector-discover", kwargs={"pk": endpoint.id}),
            data={},
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(DiscoveryJob.objects.get().connector, endpoint)

    def test_reader_cannot_queue_a_repeat_discovery(self) -> None:
        self.assertEqual(self.post(self.admin, self.tenant).status_code, 201)
        endpoint = ConnectorEndpoint.objects.get()
        self.client.force_login(self.reader)
        response = self.client.post(
            reverse("core:connector-discover", kwargs={"pk": endpoint.id}),
            data={},
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )
        self.assertEqual(response.status_code, 403)

    def test_certificate_probe_returns_display_data_and_signed_token(self) -> None:
        self.client.force_login(self.admin)
        response = self.client.post(
            reverse("core:bmc-certificate-probe"),
            data={
                "bmc_family": "hpe-ilo4",
                "display_name": "Synthetic iLO",
                "address": "192.0.2.10",
                "port": 443,
            },
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )

        self.assertEqual(response.status_code, 200)
        document = response.json()
        self.assertTrue(document["requires_explicit_trust"])
        self.assertEqual(
            document["certificate"]["fingerprint_sha256"],
            self.certificate.fingerprint_sha256,
        )
        self.assertNotIn("password", str(document).lower())
        self.assertTrue(
            BmcCommunicationLog.objects.filter(
                tenant=self.tenant,
                event_type="tls.certificate_probe",
            ).exists()
        )

    def test_tenant_admin_rotates_credentials_and_queues_discovery(self) -> None:
        self.assertEqual(self.post(self.admin, self.tenant).status_code, 201)
        endpoint = ConnectorEndpoint.objects.get()
        DiscoveryJob.objects.all().delete()

        response = self.client.post(
            reverse("core:connector-credentials", kwargs={"pk": endpoint.id}),
            data={"username": "replacement", "password": "replacement-secret"},
            content_type="application/json",
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )

        self.assertEqual(response.status_code, 202)
        self.assertEqual(
            load_connector_secret(
                tenant_id=self.tenant.id,
                secret_id=endpoint.credential_reference,
            ),
            ("replacement", "replacement-secret"),
        )
        self.assertEqual(DiscoveryJob.objects.get().connector, endpoint)
        self.assertTrue(
            AuditEvent.objects.filter(action="connector.credentials.rotate").exists()
        )
        self.assertNotIn("replacement-secret", str(response.json()))

    def test_removal_destroys_secret_and_hides_connector_inventory(self) -> None:
        self.assertEqual(self.post(self.admin, self.tenant).status_code, 201)
        endpoint = ConnectorEndpoint.objects.get()
        PhysicalSystem.objects.create(
            tenant=self.tenant,
            connector=endpoint,
            source_resource_id="/redfish/v1/Systems/1/",
            name="Synthetic host",
            discovered_at=timezone.now(),
        )

        response = self.client.delete(
            reverse("core:connector-detail", kwargs={"pk": endpoint.id}),
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )

        self.assertEqual(response.status_code, 204)
        endpoint.refresh_from_db()
        self.assertIsNotNone(endpoint.removed_at)
        self.assertFalse(endpoint.enabled)
        self.assertFalse(ConnectorSecret.objects.exists())
        self.assertEqual(
            self.client.get(
                reverse("core:connector-list"),
                headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
            ).json(),
            [],
        )
        self.assertEqual(
            self.client.get(
                reverse("core:physical-list"),
                headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
            ).json(),
            [],
        )
        self.assertTrue(AuditEvent.objects.filter(action="connector.remove").exists())
        self.assertTrue(
            BmcCommunicationLog.objects.filter(event_type="connector.removed").exists()
        )

    def test_logs_are_tenant_scoped_filterable_and_csv_safe(self) -> None:
        BmcCommunicationLog.objects.create(
            tenant=self.tenant,
            bmc_name="=synthetic",
            bmc_family="hpe-ilo4",
            severity=BmcCommunicationLog.Severity.ERROR,
            event_type="redfish.exchange",
            method="GET",
            resource_path="/redfish/v1/",
            http_status=500,
        )
        BmcCommunicationLog.objects.create(
            tenant=self.other_tenant,
            bmc_name="Other tenant BMC",
            bmc_family="hpe-ilo4",
            severity=BmcCommunicationLog.Severity.ERROR,
            event_type="redfish.exchange",
        )
        self.client.force_login(self.reader)

        response = self.client.get(
            reverse("core:bmc-log-list"),
            {"severity": "error"},
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual([entry["bmc_name"] for entry in response.json()], ["=synthetic"])

        export = self.client.get(
            reverse("core:bmc-log-export"),
            {"severity": "error"},
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        )
        self.assertEqual(export.status_code, 200)
        content = export.content.decode()
        self.assertIn("'=synthetic", content)
        self.assertNotIn("Other tenant BMC", content)

    @patch("ipms.apps.discovery.services.socket.getaddrinfo")
    @patch("ipms.apps.discovery.services.discover_ilo")
    def test_isolated_queue_processor_updates_inventory(self, discover, getaddrinfo) -> None:
        response = self.post(self.admin, self.tenant)
        self.assertEqual(response.status_code, 201)
        getaddrinfo.return_value = [(2, 1, 6, "", ("10.0.0.20", 0))]
        discover.return_value = (
            self.fixture_observations(),
            {"redfish_version": "1.0.0", "system_count": "1"},
        )
        self.assertEqual(process_discovery_queue(limit=1), 1)
        job = DiscoveryJob.objects.get()
        endpoint = ConnectorEndpoint.objects.get()
        self.assertEqual(job.status, DiscoveryJob.Status.SUCCEEDED)
        self.assertEqual(endpoint.health, ConnectorEndpoint.Health.HEALTHY)
        system = PhysicalSystem.objects.get()
        self.assertEqual(system.name, "Synthetic host")
        self.assertEqual(system.detail_snapshot["schema_version"], 1)
        self.assertEqual(discover.call_args.args[0].timeout, 20)

    @patch("ipms.apps.discovery.services.socket.getaddrinfo")
    @patch("ipms.apps.discovery.services.discover_ilo")
    def test_failed_discovery_exposes_only_safe_request_diagnostics(
        self, discover, getaddrinfo
    ) -> None:
        response = self.post(self.admin, self.tenant)
        self.assertEqual(response.status_code, 201)
        getaddrinfo.return_value = [(2, 1, 6, "", ("10.0.0.20", 0))]
        discover.side_effect = RedfishConnectorError(
            "redfish_request_failed",
            {
                "method": "POST",
                "path": "/redfish/v1/SessionService/Sessions/",
                "http_status": 400,
            },
        )

        self.assertEqual(process_discovery_queue(limit=1), 1)

        endpoint = ConnectorEndpoint.objects.get()
        job = DiscoveryJob.objects.get()
        self.assertEqual(endpoint.last_error_detail["http_status"], 400)
        self.assertEqual(job.error_detail, endpoint.last_error_detail)
        self.client.force_login(self.reader)
        document = self.client.get(
            reverse("core:connector-list"),
            headers={"X-IPMS-Tenant-ID": str(self.tenant.id)},
        ).json()[0]
        self.assertEqual(document["last_error_detail"]["method"], "POST")
        self.assertNotIn("password", str(document).lower())
        self.assertNotIn("token", str(document).lower())

    @staticmethod
    def fixture_observations():
        from .connectors.ilo_redfish import PhysicalSystemObservation

        return [
            PhysicalSystemObservation(
                source_resource_id="/redfish/v1/Systems/1/",
                name="Synthetic host",
                manufacturer="Example",
                model="Fixture",
                serial_number="SYNTHETIC",
                sku="",
                system_uuid="00000000-0000-0000-0000-000000000001",
                power_state="On",
                health="ok",
                state="Enabled",
                processor_count=2,
                processor_model="Fixture CPU",
                total_cores=16,
                memory_bytes=64 * 1024**3,
                bios_version="Fixture BIOS",
                bmc_firmware_version="Fixture BMC",
                detail_snapshot={"schema_version": 1, "subsystems": []},
            )
        ]
