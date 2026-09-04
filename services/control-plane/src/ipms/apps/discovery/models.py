import uuid

from django.db import models
from django.db.models import Q

from ipms.apps.tenancy.models import Tenant


class ConnectorEndpoint(models.Model):
    class ConnectorType(models.TextChoices):
        ILO_REDFISH = "ilo-redfish", "iLO Redfish"
        HYPER_V = "hyper-v", "Hyper-V"
        SOPHOS_FIREWALL = "sophos-firewall", "Sophos Firewall"
        LOADBALANCER_ORG = "loadbalancer-org", "Loadbalancer.org ADC"
        HPE_COMWARE = "hpe-comware", "HPE Comware"

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
    base_url = models.CharField(max_length=512)
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


class ManagedInfrastructureDevice(models.Model):
    class Category(models.TextChoices):
        FIREWALL = "firewall", "Firewall"
        LOAD_BALANCER = "load-balancer", "Load balancer"
        SWITCH = "switch", "Switch"

    class Health(models.TextChoices):
        HEALTHY = "healthy", "Healthy"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT, related_name="managed_infrastructure_devices")
    connector = models.OneToOneField(ConnectorEndpoint, on_delete=models.PROTECT, related_name="managed_device")
    category = models.CharField(max_length=24, choices=Category.choices)
    name = models.CharField(max_length=255)
    vendor = models.CharField(max_length=128)
    product = models.CharField(max_length=128)
    model = models.CharField(max_length=255, blank=True)
    software_version = models.CharField(max_length=255, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    uptime_seconds = models.PositiveBigIntegerField(blank=True, null=True)
    health = models.CharField(max_length=16, choices=Health.choices, default=Health.UNKNOWN)
    interfaces = models.JSONField(default=list, blank=True)
    details = models.JSONField(default=dict, blank=True)
    discovered_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("category", "name")
        constraints = [models.UniqueConstraint(fields=("tenant", "connector"), name="unique_tenant_managed_device_connector")]


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
    class OperatingSystemRole(models.TextChoices):
        CLIENT = "client", "Client"
        SERVER = "server", "Server"
        DOMAIN_CONTROLLER = "domain-controller", "Domain controller"
        UNKNOWN = "unknown", "Unknown"

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

    class RolesFeaturesStatus(models.TextChoices):
        NOT_REPORTED = "not-reported", "Not reported"
        COLLECTED = "collected", "Collected"
        UNAVAILABLE = "unavailable", "Unavailable"
        NOT_APPLICABLE = "not-applicable", "Not applicable"

    class RolesFeaturesError(models.TextChoices):
        COM_INITIALIZATION_FAILED = (
            "com_initialization_failed",
            "COM initialization failed",
        )
        COM_SECURITY_FAILED = "com_security_failed", "COM security failed"
        WMI_LOCATOR_FAILED = "wmi_locator_failed", "WMI locator failed"
        ALLOCATION_FAILED = "allocation_failed", "Allocation failed"
        SERVER_MANAGER_PROVIDER_UNAVAILABLE = (
            "server_manager_provider_unavailable",
            "Server Manager provider unavailable",
        )
        WMI_PROXY_FAILED = "wmi_proxy_failed", "WMI proxy failed"
        SERVER_MANAGER_QUERY_FAILED = (
            "server_manager_query_failed",
            "Server Manager query failed",
        )
        SERVER_MANAGER_QUERY_TIMEOUT = (
            "server_manager_query_timeout",
            "Server Manager query timeout",
        )
        SERVER_MANAGER_RESULT_INVALID = (
            "server_manager_result_invalid",
            "Server Manager result invalid",
        )
        SERVER_FEATURE_FALLBACK_UNAVAILABLE = (
            "server_feature_fallback_unavailable",
            "Server feature fallback unavailable",
        )
        SERVER_FEATURE_FALLBACK_QUERY_FAILED = (
            "server_feature_fallback_query_failed",
            "Server feature fallback query failed",
        )
        SERVER_FEATURE_FALLBACK_QUERY_TIMEOUT = (
            "server_feature_fallback_query_timeout",
            "Server feature fallback query timeout",
        )
        SERVER_FEATURE_FALLBACK_RESULT_INVALID = (
            "server_feature_fallback_result_invalid",
            "Server feature fallback result invalid",
        )
        ITEM_LIMIT_EXCEEDED = "item_limit_exceeded", "Item limit exceeded"
        VALUE_LIMIT_EXCEEDED = "value_limit_exceeded", "Value limit exceeded"
        PAYLOAD_LIMIT_EXCEEDED = "payload_limit_exceeded", "Payload limit exceeded"

    class HyperVInventoryStatus(models.TextChoices):
        NOT_REPORTED = "not-reported", "Not reported"
        NOT_APPLICABLE = "not-applicable", "Not applicable"
        COLLECTED = "collected", "Collected"
        UNAVAILABLE = "unavailable", "Unavailable"

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
    operating_system_role = models.CharField(
        max_length=24,
        choices=OperatingSystemRole.choices,
        default=OperatingSystemRole.SERVER,
    )
    operating_system_family = models.CharField(max_length=64, blank=True)
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
    installed_roles_features_status = models.CharField(
        max_length=16,
        choices=RolesFeaturesStatus.choices,
        default=RolesFeaturesStatus.NOT_REPORTED,
    )
    installed_roles_features_error = models.CharField(max_length=64, blank=True)
    installed_roles_features = models.JSONField(default=list, blank=True)
    hyperv_inventory_status = models.CharField(
        max_length=16,
        choices=HyperVInventoryStatus.choices,
        default=HyperVInventoryStatus.NOT_REPORTED,
    )
    hyperv_inventory_error = models.CharField(max_length=64, blank=True)
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
            models.Index(
                fields=("tenant", "operating_system_role", "server_type"),
                name="windows_tenant_role_idx",
            ),
        ]

    def __str__(self) -> str:
        return self.fqdn or self.hostname


class WindowsServerRole(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    server = models.ForeignKey(
        WindowsServer,
        on_delete=models.CASCADE,
        related_name="installed_roles",
    )
    name = models.CharField(max_length=255)
    display_name = models.CharField(max_length=255)

    class Meta:
        ordering = ("display_name", "name")
        constraints = [
            models.UniqueConstraint(
                fields=("server", "name"),
                name="unique_windows_server_role",
            )
        ]
        indexes = [
            models.Index(fields=("name", "server"), name="windows_role_server_idx")
        ]

    def __str__(self) -> str:
        return f"{self.server}: {self.name}"


class HyperVVirtualMachine(models.Model):
    class State(models.TextChoices):
        RUNNING = "running", "Running"
        STOPPED = "stopped", "Stopped"
        STARTING = "starting", "Starting"
        STOPPING = "stopping", "Stopping"
        PAUSED = "paused", "Paused"
        PAUSING = "pausing", "Pausing"
        SUSPENDED = "suspended", "Suspended"
        SAVING = "saving", "Saving"
        RESUMING = "resuming", "Resuming"
        QUIESCED = "quiesced", "Quiesced"
        OFFLINE = "offline", "Offline"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="hyperv_virtual_machines",
    )
    host = models.ForeignKey(
        WindowsServer,
        on_delete=models.CASCADE,
        related_name="hyperv_virtual_machines",
    )
    source_id = models.CharField(max_length=64)
    name = models.CharField(max_length=255)
    state = models.CharField(
        max_length=16,
        choices=State.choices,
        default=State.UNKNOWN,
    )
    vcpu_count = models.PositiveIntegerField(blank=True, null=True)
    memory_bytes = models.PositiveBigIntegerField(blank=True, null=True)
    uptime_seconds = models.PositiveBigIntegerField(blank=True, null=True)
    configuration_version = models.CharField(max_length=64, blank=True)
    ip_addresses = models.JSONField(default=list, blank=True)
    observed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "source_id")
        constraints = [
            models.UniqueConstraint(
                fields=("host", "source_id"),
                name="unique_hyperv_host_virtual_machine",
            )
        ]
        indexes = [
            models.Index(
                fields=("tenant", "state"),
                name="hyperv_vm_tenant_state_idx",
            )
        ]

    def __str__(self) -> str:
        return f"{self.host}: {self.name}"


class HyperVVirtualMachineActionJob(models.Model):
    class Action(models.TextChoices):
        START = "start", "Start"
        SHUTDOWN = "shutdown", "Shut down"
        STOP = "stop", "Stop"
        PAUSE = "pause", "Pause"
        RESUME = "resume", "Resume"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        DELIVERED = "delivered", "Delivered"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="hyperv_action_jobs",
    )
    enrollment = models.ForeignKey(
        "agent_pki.AgentEnrollment",
        on_delete=models.PROTECT,
        related_name="hyperv_action_jobs",
    )
    virtual_machine = models.ForeignKey(
        HyperVVirtualMachine,
        on_delete=models.SET_NULL,
        related_name="action_jobs",
        blank=True,
        null=True,
    )
    vm_source_id = models.CharField(max_length=64)
    vm_name = models.CharField(max_length=255)
    action = models.CharField(max_length=16, choices=Action.choices)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    requested_by = models.CharField(max_length=255)
    result_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(blank=True, null=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("tenant", "-created_at"),
                name="hyperv_action_tenant_time",
            ),
            models.Index(
                fields=("enrollment", "status"),
                name="hyperv_action_agent_state",
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("enrollment", "vm_source_id"),
                condition=models.Q(status__in=("queued", "delivered", "running")),
                name="unique_active_hyperv_vm_action",
            )
        ]


class LinuxSystem(models.Model):
    class SystemType(models.TextChoices):
        PHYSICAL = "physical", "Physical"
        VIRTUAL = "virtual", "Virtual"
        UNKNOWN = "unknown", "Unknown"

    class Health(models.TextChoices):
        HEALTHY = "healthy", "Healthy"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="linux_systems",
    )
    inventory_source = models.CharField(max_length=32, default="agent")
    source_id = models.CharField(max_length=64)
    hostname = models.CharField(max_length=255)
    fqdn = models.CharField(max_length=255)
    system_type = models.CharField(
        max_length=16,
        choices=SystemType.choices,
        default=SystemType.UNKNOWN,
    )
    distribution = models.CharField(max_length=255, blank=True)
    distribution_version = models.CharField(max_length=128, blank=True)
    kernel_version = models.CharField(max_length=128, blank=True)
    architecture = models.CharField(max_length=32, blank=True)
    manufacturer = models.CharField(max_length=255, blank=True)
    model = models.CharField(max_length=255, blank=True)
    serial_number = models.CharField(max_length=255, blank=True)
    logical_processors = models.PositiveIntegerField(blank=True, null=True)
    memory_bytes = models.PositiveBigIntegerField(blank=True, null=True)
    agent_version = models.CharField(max_length=32)
    health = models.CharField(
        max_length=16,
        choices=Health.choices,
        default=Health.UNKNOWN,
    )
    network_interfaces = models.JSONField(default=list, blank=True)
    fixed_volumes = models.JSONField(default=list, blank=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("fqdn", "hostname")
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "inventory_source", "source_id"),
                name="unique_linux_inventory_source",
            )
        ]
        indexes = [
            models.Index(
                fields=("tenant", "system_type"),
                name="linux_tenant_type_idx",
            )
        ]

    def __str__(self) -> str:
        return self.fqdn or self.hostname


class SoftwareInventorySnapshot(models.Model):
    class Platform(models.TextChoices):
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"

    class Status(models.TextChoices):
        RECEIVING = "receiving", "Receiving"
        COMPLETED = "completed", "Completed"

    id = models.UUIDField(primary_key=True, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="software_inventory_snapshots",
    )
    enrollment = models.ForeignKey(
        "agent_pki.AgentEnrollment",
        on_delete=models.PROTECT,
        related_name="software_inventory_snapshots",
    )
    platform = models.CharField(max_length=16, choices=Platform.choices)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.RECEIVING,
    )
    page_count = models.PositiveSmallIntegerField()
    received_pages = models.JSONField(default=list, blank=True)
    reboot_required = models.BooleanField(blank=True, null=True)
    update_scan_status = models.CharField(max_length=32, default="unknown")
    last_update_scan_at = models.DateTimeField(blank=True, null=True)
    last_update_install_at = models.DateTimeField(blank=True, null=True)
    package_count = models.PositiveIntegerField(default=0)
    updates_available = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("tenant", "enrollment", "status"),
                name="software_snapshot_lookup_idx",
            )
        ]


class SoftwarePackage(models.Model):
    class UpdateState(models.TextChoices):
        CURRENT = "current", "Current"
        AVAILABLE = "update-available", "Update available"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="software_packages",
    )
    snapshot = models.ForeignKey(
        SoftwareInventorySnapshot,
        on_delete=models.CASCADE,
        related_name="packages",
    )
    source_id = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    installed_version = models.CharField(max_length=255, blank=True)
    available_version = models.CharField(max_length=255, blank=True)
    publisher = models.CharField(max_length=255, blank=True)
    package_type = models.CharField(max_length=32)
    update_state = models.CharField(
        max_length=24,
        choices=UpdateState.choices,
        default=UpdateState.UNKNOWN,
    )
    is_os_component = models.BooleanField(default=False)

    class Meta:
        ordering = ("name", "source_id")
        constraints = [
            models.UniqueConstraint(
                fields=("snapshot", "source_id"),
                name="unique_snapshot_software_package",
            )
        ]
        indexes = [
            models.Index(
                fields=("tenant", "update_state"),
                name="software_tenant_update_idx",
            )
        ]


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
        SOPHOS_FIREWALL = "sophos-firewall", "Sophos Firewall"
        LOADBALANCER_ORG = "loadbalancer-org", "Loadbalancer.org ADC"
        HPE_COMWARE = "hpe-comware", "HPE Comware"

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
