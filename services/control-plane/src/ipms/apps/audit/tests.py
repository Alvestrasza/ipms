from django.core.exceptions import ValidationError
from django.db.models.deletion import ProtectedError
from django.test import TestCase

from ipms.apps.tenancy.models import Tenant

from .models import AuditEvent


class AuditEventModelTests(TestCase):
    def setUp(self) -> None:
        self.tenant = Tenant.objects.create(slug="example", display_name="Example")
        self.event = AuditEvent.objects.create(
            tenant=self.tenant,
            actor="test-user",
            action="tenant.view",
            object_type="tenant",
            object_id=str(self.tenant.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
        )

    def test_event_cannot_be_updated_through_model_save(self) -> None:
        self.event.action = "tenant.change"

        with self.assertRaisesMessage(ValidationError, "append-only"):
            self.event.save()

    def test_event_cannot_be_deleted_through_model_delete(self) -> None:
        with self.assertRaisesMessage(ValidationError, "append-only"):
            self.event.delete()

    def test_tenant_with_audit_history_cannot_be_deleted(self) -> None:
        with self.assertRaises(ProtectedError):
            self.tenant.delete()
