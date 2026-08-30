import uuid

from django.db import models

from ipms.apps.tenancy.models import Tenant


class DiscoveryJob(models.Model):
    class ConnectorType(models.TextChoices):
        ILO_REDFISH = "ilo-redfish", "iLO Redfish"
        HYPER_V = "hyper-v", "Hyper-V"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="discovery_jobs",
    )
    connector_type = models.CharField(max_length=32, choices=ConnectorType.choices)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    requested_by = models.CharField(max_length=255)
    correlation_id = models.UUIDField(default=uuid.uuid4, editable=False)
    parameters = models.JSONField(default=dict, blank=True)
    result_summary = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=("tenant", "-created_at"), name="job_tenant_time_idx"),
            models.Index(fields=("status",), name="job_status_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.connector_type}: {self.status}"
