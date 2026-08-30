import uuid
from dataclasses import asdict
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import Tenant, TenantMembership

from .connectors.ilo_redfish import RedfishConnectorError, RedfishTransport, discover_ilo
from .models import ConnectorEndpoint, ConnectorSecret, DiscoveryJob, PhysicalSystem
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
    def __init__(self, documents: dict[str, dict]) -> None:
        self.documents = documents
        self.calls: list[tuple[str, str]] = []
        self.session_path = ""

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path))
        if path not in self.documents:
            raise RedfishConnectorError("fixture_missing")
        return self.documents[path]

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
        self.assertEqual(transport.calls[-1][0], "DELETE")
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
        self.payload = {
            "display_name": "Synthetic iLO",
            "base_url": "https://192.0.2.10/",
            "certificate_sha256": "ab:" * 31 + "ab",
            "username": "readonly-user",
            "password": "test-only-secret",
            "confirm_read_only": True,
        }

    def post(self, user, tenant, payload=None):
        self.client.force_login(user)
        return self.client.post(
            reverse("core:ilo-enroll"),
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

    def test_requires_https_origin_and_read_only_confirmation(self) -> None:
        payload = {**self.payload, "base_url": "http://192.0.2.10/redfish", "confirm_read_only": False}
        response = self.post(self.admin, self.tenant, payload)
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

    @patch("ipms.apps.discovery.services.socket.getaddrinfo")
    @patch("ipms.apps.discovery.services.discover_ilo")
    def test_isolated_queue_processor_updates_inventory(self, discover, getaddrinfo) -> None:
        response = self.post(self.admin, self.tenant)
        self.assertEqual(response.status_code, 201)
        getaddrinfo.return_value = [(2, 1, 6, "", ("10.0.0.20", 0))]
        discover.return_value = (self.fixture_observations(), {"redfish_version": "1.0.0", "system_count": "1"})
        self.assertEqual(process_discovery_queue(limit=1), 1)
        job = DiscoveryJob.objects.get()
        endpoint = ConnectorEndpoint.objects.get()
        self.assertEqual(job.status, DiscoveryJob.Status.SUCCEEDED)
        self.assertEqual(endpoint.health, ConnectorEndpoint.Health.HEALTHY)
        self.assertEqual(PhysicalSystem.objects.get().name, "Synthetic host")

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
            )
        ]
