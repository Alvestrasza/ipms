import uuid

from django.db import models
from django.db.models import Q

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

    class BmcFamily(models.TextChoices):
        HPE_ILO4 = "hpe-ilo4", "HPE iLO 4"
        HPE_ILO_MODERN = "hpe-ilo-modern", "HPE iLO 5/6/7"
        DELL_IDRAC = "dell-idrac", "Dell iDRAC"
        GENERIC_REDFISH = "generic-redfish", "Generic Redfish"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="connector_endpoints",
    )
    connector_type = models.CharField(max_length=32, choices=ConnectorType.choices)
    bmc_family = models.CharField(
        max_length=32,
        choices=BmcFamily.choices,
        default=BmcFamily.HPE_ILO4,
    )
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
    removed_at = models.DateTimeField(blank=True, null=True)
    removed_by = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("display_name",)
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "base_url"),
                condition=Q(removed_at__isnull=True),
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
    detail_snapshot = models.JSONField(default=dict, blank=True)
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


class WindowsServer(models.Model):
    class ServerType(models.TextChoices):
        PHYSICAL = "physical", "Physical"
        VIRTUAL = "virtual", "Virtual"
        UNKNOWN = "unknown", "Unknown"

    class InventorySource(models.TextChoices):
        AGENT = "agent", "IPMS Agent"
        HYPER_V = "hyper-v", "Hyper-V"

    class Health(models.TextChoices):
        HEALTHY = "healthy", "Healthy"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"
        UNKNOWN = "unknown", "Unknown"

    class AgentState(models.TextChoices):
        NOT_ENROLLED = "not-enrolled", "Not enrolled"
        ONLINE = "online", "Online"
        STALE = "stale", "Stale"
        OFFLINE = "offline", "Offline"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="windows_servers",
    )
    connector = models.ForeignKey(
        ConnectorEndpoint,
        on_delete=models.PROTECT,
        related_name="windows_servers",
        blank=True,
        null=True,
    )
    source_id = models.CharField(max_length=255)
    inventory_source = models.CharField(
        max_length=16,
        choices=InventorySource.choices,
    )
    server_type = models.CharField(
        max_length=16,
        choices=ServerType.choices,
        default=ServerType.UNKNOWN,
    )
    hostname = models.CharField(max_length=255)
    fqdn = models.CharField(max_length=255, blank=True)
    domain_name = models.CharField(max_length=255, blank=True)
    operating_system = models.CharField(max_length=255, blank=True)
    os_version = models.CharField(max_length=128, blank=True)
    os_build = models.CharField(max_length=64, blank=True)
    architecture = models.CharField(max_length=32, blank=True)
    manufacturer = models.CharField(max_length=255, blank=True)
    model = models.CharField(max_length=255, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    system_uuid = models.CharField(max_length=64, blank=True)
    logical_processors = models.PositiveIntegerField(blank=True, null=True)
    memory_bytes = models.PositiveBigIntegerField(blank=True, null=True)
    cluster_name = models.CharField(max_length=255, blank=True)
    hypervisor_host = models.CharField(max_length=255, blank=True)
    agent_version = models.CharField(max_length=64, blank=True)
    agent_state = models.CharField(
        max_length=16,
        choices=AgentState.choices,
        default=AgentState.UNKNOWN,
    )
    health = models.CharField(
        max_length=16,
        choices=Health.choices,
        default=Health.UNKNOWN,
    )
    management_packs = models.JSONField(default=list, blank=True)
    network_interfaces = models.JSONField(default=list, blank=True)
    detail_snapshot = models.JSONField(default=dict, blank=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    discovered_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("hostname",)
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "inventory_source", "source_id"),
                name="unique_tenant_windows_source",
            )
        ]
        indexes = [
            models.Index(
                fields=("tenant", "server_type"),
                name="windows_tenant_type_idx",
            ),
            models.Index(
                fields=("tenant", "agent_state"),
                name="windows_tenant_agent_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.fqdn or self.hostname


class WindowsServerTelemetry(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="windows_server_telemetry",
    )
    server = models.OneToOneField(
        WindowsServer,
        on_delete=models.CASCADE,
        related_name="latest_telemetry",
    )
    cpu_used_percent = models.PositiveSmallIntegerField()
    memory_total_bytes = models.PositiveBigIntegerField()
    memory_available_bytes = models.PositiveBigIntegerField()
    memory_used_bytes = models.PositiveBigIntegerField()
    memory_used_percent = models.PositiveSmallIntegerField()
    fixed_volumes = models.JSONField(default=list, blank=True)
    observed_at = models.DateTimeField()
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(
                fields=("tenant", "-observed_at"),
                name="wintelemetry_tenant_time_idx",
            )
        ]
        constraints = [
            models.CheckConstraint(
                condition=Q(cpu_used_percent__lte=100),
                name="wintelemetry_cpu_percent_lte_100",
            ),
            models.CheckConstraint(
                condition=Q(memory_used_percent__lte=100),
                name="wintelemetry_memory_percent_lte_100",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.server}: {self.observed_at.isoformat()}"


class BmcCommunicationLog(models.Model):
    class Severity(models.TextChoices):
        DEBUG = "debug", "Debug"
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="bmc_communication_logs",
    )
    connector = models.ForeignKey(
        ConnectorEndpoint,
        on_delete=models.SET_NULL,
        related_name="communication_logs",
        blank=True,
        null=True,
    )
    bmc_name = models.CharField(max_length=255)
    bmc_family = models.CharField(max_length=32)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    event_type = models.CharField(max_length=64)
    method = models.CharField(max_length=12, blank=True)
    resource_path = models.CharField(max_length=512, blank=True)
    http_status = models.PositiveSmallIntegerField(blank=True, null=True)
    duration_ms = models.PositiveIntegerField(blank=True, null=True)
    error_code = models.CharField(max_length=128, blank=True)
    redfish_error_code = models.CharField(max_length=128, blank=True)
    redfish_message_id = models.CharField(max_length=128, blank=True)
    correlation_id = models.UUIDField(blank=True, null=True)
    occurred_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-occurred_at",)
        indexes = [
            models.Index(
                fields=("tenant", "-occurred_at"),
                name="bmc_log_tenant_time_idx",
            ),
            models.Index(
                fields=("tenant", "severity", "-occurred_at"),
                name="bmc_log_severity_idx",
            ),
            models.Index(
                fields=("connector", "-occurred_at"),
                name="bmc_log_connector_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.bmc_name}: {self.event_type}"


class BmcEventLogEntry(models.Model):
    class LogType(models.TextChoices):
        ILO_EVENT_LOG = "ilo_event_log", "iLO Event Log"
        INTEGRATED_MANAGEMENT_LOG = (
            "integrated_management_log",
            "Integrated Management Log",
        )

    class Severity(models.TextChoices):
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="bmc_event_log_entries",
    )
    connector = models.ForeignKey(
        ConnectorEndpoint,
        on_delete=models.SET_NULL,
        related_name="event_log_entries",
        blank=True,
        null=True,
    )
    bmc_name = models.CharField(max_length=255)
    log_type = models.CharField(max_length=32, choices=LogType.choices)
    source_record_id = models.CharField(max_length=255)
    severity = models.CharField(max_length=16, choices=Severity.choices)
    message = models.TextField(max_length=8192)
    source_created_at = models.DateTimeField(blank=True, null=True)
    source_updated_at = models.DateTimeField(blank=True, null=True)
    repeat_count = models.PositiveIntegerField(blank=True, null=True)
    repaired = models.BooleanField(blank=True, null=True)
    event_class = models.IntegerField(blank=True, null=True)
    event_code = models.IntegerField(blank=True, null=True)
    event_number = models.IntegerField(blank=True, null=True)
    record_format = models.CharField(max_length=64, blank=True)
    first_discovered_at = models.DateTimeField(auto_now_add=True)
    last_discovered_at = models.DateTimeField()

    class Meta:
        ordering = ("-source_created_at", "-last_discovered_at")
        constraints = [
            models.UniqueConstraint(
                fields=("connector", "log_type", "source_record_id"),
                name="unique_bmc_source_log_entry",
            )
        ]
        indexes = [
            models.Index(
                fields=("tenant", "-source_created_at"),
                name="bmc_event_tenant_time_idx",
            ),
            models.Index(
                fields=("tenant", "severity", "-source_created_at"),
                name="bmc_event_severity_idx",
            ),
            models.Index(
                fields=("connector", "log_type", "-source_created_at"),
                name="bmc_event_source_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.bmc_name}: {self.log_type} {self.source_record_id}"


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
