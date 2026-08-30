import uuid

from django.core.exceptions import ValidationError
from django.db import models

from ipms.apps.tenancy.models import Tenant


class AuditEvent(models.Model):
    class Outcome(models.TextChoices):
        SUCCEEDED = "succeeded", "Succeeded"
        DENIED = "denied", "Denied"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="audit_events",
        blank=True,
        null=True,
    )
    occurred_at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    object_type = models.CharField(max_length=255, blank=True)
    object_id = models.CharField(max_length=255, blank=True)
    outcome = models.CharField(max_length=16, choices=Outcome.choices)
    correlation_id = models.UUIDField(default=uuid.uuid4, editable=False)
    request_id = models.CharField(max_length=255, blank=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-occurred_at",)
        indexes = [
            models.Index(fields=("tenant", "-occurred_at"), name="audit_tenant_time_idx"),
            models.Index(fields=("correlation_id",), name="audit_correlation_idx"),
        ]

    def save(self, *args, **kwargs) -> None:
        if not self._state.adding:
            raise ValidationError("Audit events are append-only and cannot be updated.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs) -> None:
        raise ValidationError("Audit events are append-only and cannot be deleted.")

    def __str__(self) -> str:
        return f"{self.action}: {self.outcome}"
