import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from ipms.apps.tenancy.models import Tenant, TenantMembership

from .models import DiscoveryJob


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
