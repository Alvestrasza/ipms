import uuid

from django.db import models

from ipms.apps.tenancy.models import Tenant


class ConnectorEndpoint(models.Model):
    class ConnectorType(models.TextChoices):
        ILO_REDFISH = "ilo-redfish", "iLO Redfish"
        HYPER_V = "hyper-v", "Hyper-V"

    class Health(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        HEALTHY = "healthy", "Healthy"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="connector_endpoints",
    )
    connector_type = models.CharField(max_length=32, choices=ConnectorType.choices)
    display_name = models.CharField(max_length=255)
    base_url = models.URLField(max_length=512)
    credential_reference = models.UUIDField(unique=True, default=uuid.uuid4)
    tls_certificate_sha256 = models.CharField(max_length=64)
    enabled = models.BooleanField(default=True)
    health = models.CharField(
        max_length=16,
        choices=Health.choices,
        default=Health.UNKNOWN,
    )
    last_error_code = models.CharField(max_length=64, blank=True)
    last_error_detail = models.JSONField(default=dict, blank=True)
    last_attempt_at = models.DateTimeField(blank=True, null=True)
    last_success_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("display_name",)
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "base_url"),
                name="unique_tenant_connector_url",
            )
        ]

    def __str__(self) -> str:
        return f"{self.display_name} ({self.connector_type})"


class ConnectorSecret(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="connector_secrets",
    )
    nonce = models.BinaryField()
    ciphertext = models.BinaryField()
    key_version = models.PositiveSmallIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Connector credential {self.id}"


class PhysicalSystem(models.Model):
    class Health(models.TextChoices):
        OK = "ok", "OK"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="physical_systems",
    )
    connector = models.ForeignKey(
        ConnectorEndpoint,
        on_delete=models.PROTECT,
        related_name="physical_systems",
    )
    source_resource_id = models.CharField(max_length=512)
    name = models.CharField(max_length=255)
    manufacturer = models.CharField(max_length=255, blank=True)
    model = models.CharField(max_length=255, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    sku = models.CharField(max_length=255, blank=True)
    system_uuid = models.CharField(max_length=64, blank=True)
    power_state = models.CharField(max_length=32, blank=True)
    health = models.CharField(
        max_length=16,
        choices=Health.choices,
        default=Health.UNKNOWN,
    )
    state = models.CharField(max_length=32, blank=True)
    processor_count = models.PositiveIntegerField(blank=True, null=True)
    processor_model = models.CharField(max_length=255, blank=True)
    total_cores = models.PositiveIntegerField(blank=True, null=True)
    memory_bytes = models.PositiveBigIntegerField(blank=True, null=True)
    bios_version = models.CharField(max_length=255, blank=True)
    bmc_firmware_version = models.CharField(max_length=255, blank=True)
    discovered_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)
        constraints = [
            models.UniqueConstraint(
                fields=("connector", "source_resource_id"),
                name="unique_connector_physical_resource",
            )
        ]
        indexes = [
            models.Index(fields=("tenant", "health"), name="physical_tenant_health")
        ]

    def __str__(self) -> str:
        return self.name


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
    connector = models.ForeignKey(
        ConnectorEndpoint,
        on_delete=models.PROTECT,
        related_name="discovery_jobs",
        blank=True,
        null=True,
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
    error_detail = models.JSONField(default=dict, blank=True)
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
