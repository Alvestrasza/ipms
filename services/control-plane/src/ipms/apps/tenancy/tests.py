from django.db import IntegrityError, transaction
from django.test import TestCase

from .models import Tenant


class TenantModelTests(TestCase):
    def test_tenant_defaults_to_active(self) -> None:
        tenant = Tenant.objects.create(slug="example", display_name="Example")

        self.assertEqual(tenant.status, Tenant.Status.ACTIVE)
        self.assertEqual(tenant.metadata, {})

    def test_tenant_slug_is_unique(self) -> None:
        Tenant.objects.create(slug="example", display_name="First")

        with self.assertRaises(IntegrityError), transaction.atomic():
            Tenant.objects.create(slug="example", display_name="Second")
