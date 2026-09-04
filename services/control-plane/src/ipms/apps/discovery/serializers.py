import ipaddress
import re

from rest_framework import serializers

from .models import (
    BmcCommunicationLog,
    BmcEventLogEntry,
    ConnectorEndpoint,
    DiscoveryJob,
    PhysicalSystem,
    HyperVVirtualMachine,
    HyperVVirtualMachineActionJob,
    HyperVConsoleInputEvent,
    HyperVConsoleSession,
    LinuxSystem,
    ManagedInfrastructureDevice,
    SoftwareInventorySnapshot,
    SoftwarePackage,
    WindowsServer,
    WindowsServerTelemetry,
)


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
INTERNAL_PROTOCOL_PATTERN = re.compile("redfish", re.IGNORECASE)


def neutralize_public_protocol_text(value: str) -> str:
    return INTERNAL_PROTOCOL_PATTERN.sub("bmc_api", value)


def neutralize_public_protocol_details(value):
    if isinstance(value, dict):
        return {
            neutralize_public_protocol_text(str(key)): neutralize_public_protocol_details(
                item
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [neutralize_public_protocol_details(item) for item in value]
    if isinstance(value, str):
        return neutralize_public_protocol_text(value)
    return value


def public_connector_type(value: str) -> str:
    return "bmc-api" if value == ConnectorEndpoint.ConnectorType.ILO_REDFISH else value


def public_bmc_family(value: str) -> str:
    return "generic-bmc-api" if value == ConnectorEndpoint.BmcFamily.GENERIC_REDFISH else value


def normalized_bmc_origin(address: str, port: int) -> str:
    hostname = f"[{address}]" if ":" in address else address
    return f"https://{hostname}{f':{port}' if port != 443 else ''}/"


class ConnectorEndpointSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    connector_type = serializers.SerializerMethodField()
    bmc_family = serializers.SerializerMethodField()
    trust_mode = serializers.SerializerMethodField()
    last_error_code = serializers.SerializerMethodField()
    last_error_detail = serializers.SerializerMethodField()

    class Meta:
        model = ConnectorEndpoint
        fields = (
            "id",
            "tenant_id",
            "connector_type",
            "bmc_family",
            "display_name",
            "base_url",
            "enabled",
            "health",
            "trust_mode",
            "last_error_code",
            "last_error_detail",
            "last_attempt_at",
            "last_success_at",
        )
        read_only_fields = fields

    def get_trust_mode(self, instance: ConnectorEndpoint) -> str:
        return "certificate-pin" if instance.tls_certificate_sha256 else "unconfigured"

    def get_connector_type(self, instance: ConnectorEndpoint) -> str:
        return public_connector_type(instance.connector_type)

    def get_bmc_family(self, instance: ConnectorEndpoint) -> str:
        return public_bmc_family(instance.bmc_family)

    def get_last_error_code(self, instance: ConnectorEndpoint) -> str:
        return neutralize_public_protocol_text(instance.last_error_code)

    def get_last_error_detail(self, instance: ConnectorEndpoint) -> dict:
        return neutralize_public_protocol_details(instance.last_error_detail)


class BmcEndpointSerializer(serializers.Serializer):
    bmc_family = serializers.ChoiceField(
        choices=(
            ConnectorEndpoint.BmcFamily.HPE_ILO4,
            ConnectorEndpoint.BmcFamily.HPE_ILO_MODERN,
            ConnectorEndpoint.BmcFamily.DELL_IDRAC,
            "generic-bmc-api",
        )
    )
    display_name = serializers.CharField(max_length=255)
    address = serializers.CharField(max_length=253)
    port = serializers.IntegerField(min_value=1, max_value=65535, default=443)

    def validate_address(self, value: str) -> str:
        address = value.strip().rstrip(".")
        try:
            return str(ipaddress.ip_address(address))
        except ValueError:
            if not HOSTNAME_PATTERN.fullmatch(address):
                raise serializers.ValidationError(
                    "A valid IP address or DNS hostname is required."
                )
        return address.lower()

    def validate_bmc_family(self, value: str) -> str:
        if value == "generic-bmc-api":
            return ConnectorEndpoint.BmcFamily.GENERIC_REDFISH
        return value

    def validate(self, attrs):
        attrs["base_url"] = normalized_bmc_origin(attrs["address"], attrs["port"])
        return attrs


class BmcCertificateProbeSerializer(BmcEndpointSerializer):
    pass


class BmcConnectorEnrollmentSerializer(BmcEndpointSerializer):
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=4096, write_only=True, trim_whitespace=False)
    certificate_trust_token = serializers.CharField(max_length=4096, write_only=True)
    confirm_certificate_trust = serializers.BooleanField(
        write_only=True,
        default=False,
    )


class ConnectorCredentialSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(
        max_length=4096,
        write_only=True,
        trim_whitespace=False,
    )
    privacy_key = serializers.CharField(
        max_length=4096,
        write_only=True,
        trim_whitespace=False,
        required=False,
        default="",
    )
    api_key = serializers.CharField(
        max_length=4096,
        write_only=True,
        trim_whitespace=False,
        required=False,
        default="",
    )


class ManagedDeviceEndpointSerializer(serializers.Serializer):
    connector_type = serializers.ChoiceField(
        choices=(
            ConnectorEndpoint.ConnectorType.SOPHOS_FIREWALL,
            ConnectorEndpoint.ConnectorType.LOADBALANCER_ORG,
            ConnectorEndpoint.ConnectorType.HPE_COMWARE,
        )
    )
    display_name = serializers.CharField(max_length=255)
    address = serializers.CharField(max_length=253)
    port = serializers.IntegerField(min_value=1, max_value=65535)

    def validate_address(self, value: str) -> str:
        return BmcEndpointSerializer().validate_address(value)

    def validate(self, attrs):
        address = f"[{attrs['address']}]" if ":" in attrs["address"] else attrs["address"]
        scheme = "snmp" if attrs["connector_type"] == ConnectorEndpoint.ConnectorType.HPE_COMWARE else "https"
        attrs["base_url"] = f"{scheme}://{address}:{attrs['port']}"
        return attrs


class ManagedDeviceCertificateProbeSerializer(ManagedDeviceEndpointSerializer):
    def validate_connector_type(self, value: str) -> str:
        if value == ConnectorEndpoint.ConnectorType.HPE_COMWARE:
            raise serializers.ValidationError("SNMP connectors do not use a TLS certificate.")
        return value


class ManagedDeviceEnrollmentSerializer(ManagedDeviceEndpointSerializer):
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=4096, write_only=True, trim_whitespace=False)
    privacy_key = serializers.CharField(max_length=4096, write_only=True, trim_whitespace=False, required=False, default="")
    api_key = serializers.CharField(max_length=4096, write_only=True, trim_whitespace=False, required=False, default="")
    certificate_trust_token = serializers.CharField(max_length=4096, write_only=True, required=False, default="")
    confirm_certificate_trust = serializers.BooleanField(write_only=True, default=False)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if attrs["connector_type"] == ConnectorEndpoint.ConnectorType.HPE_COMWARE:
            if not attrs["privacy_key"]:
                raise serializers.ValidationError({"privacy_key": ["SNMPv3 authPriv requires a privacy key."]})
        else:
            if not attrs["certificate_trust_token"]:
                raise serializers.ValidationError({"certificate_trust_token": ["Certificate confirmation is required."]})
            if (
                attrs["connector_type"]
                == ConnectorEndpoint.ConnectorType.LOADBALANCER_ORG
                and not attrs["api_key"]
            ):
                raise serializers.ValidationError(
                    {"api_key": ["The Loadbalancer.org API key is required."]}
                )
        return attrs


class ManagedInfrastructureDeviceSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    connector_id = serializers.UUIDField(read_only=True)
    connector_type = serializers.CharField(source="connector.connector_type", read_only=True)

    class Meta:
        model = ManagedInfrastructureDevice
        fields = ("id", "tenant_id", "connector_id", "connector_type", "category", "name", "vendor", "product", "model", "software_version", "serial_number", "uptime_seconds", "health", "interfaces", "details", "discovered_at")
        read_only_fields = fields

class PhysicalSystemSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    connector_id = serializers.UUIDField(read_only=True)
    detail_snapshot = serializers.SerializerMethodField()

    class Meta:
        model = PhysicalSystem
        fields = (
            "id",
            "tenant_id",
            "connector_id",
            "name",
            "manufacturer",
            "model",
            "serial_number",
            "sku",
            "system_uuid",
            "power_state",
            "health",
            "state",
            "processor_count",
            "processor_model",
            "total_cores",
            "memory_bytes",
            "bios_version",
            "bmc_firmware_version",
            "detail_snapshot",
            "discovered_at",
        )
        read_only_fields = fields

    def get_detail_snapshot(self, instance: PhysicalSystem) -> dict:
        return neutralize_public_protocol_details(instance.detail_snapshot)


class WindowsServerSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    connector_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = WindowsServer
        fields = (
            "id",
            "tenant_id",
            "connector_id",
            "source_id",
            "inventory_source",
            "server_type",
            "hostname",
            "fqdn",
            "domain_name",
            "operating_system",
            "os_version",
            "os_build",
            "operating_system_role",
            "operating_system_family",
            "architecture",
            "manufacturer",
            "model",
            "serial_number",
            "system_uuid",
            "logical_processors",
            "memory_bytes",
            "cluster_name",
            "hypervisor_host",
            "agent_version",
            "agent_state",
            "health",
            "management_packs",
            "last_seen_at",
            "discovered_at",
        )
        read_only_fields = fields


class WindowsServerTelemetrySerializer(serializers.ModelSerializer):
    server_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = WindowsServerTelemetry
        fields = (
            "server_id",
            "cpu_used_percent",
            "memory_total_bytes",
            "memory_available_bytes",
            "memory_used_bytes",
            "memory_used_percent",
            "fixed_volumes",
            "observed_at",
        )
        read_only_fields = fields


class WindowsServerDetailSerializer(WindowsServerSerializer):
    latest_telemetry = WindowsServerTelemetrySerializer(read_only=True, allow_null=True)

    class Meta(WindowsServerSerializer.Meta):
        fields = WindowsServerSerializer.Meta.fields + (
            "installed_roles_features_status",
            "installed_roles_features_error",
            "installed_roles_features",
            "hyperv_inventory_status",
            "hyperv_inventory_error",
            "network_interfaces",
            "latest_telemetry",
        )
        read_only_fields = fields


class HyperVVirtualMachineSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    host_id = serializers.UUIDField(read_only=True)
    host_fqdn = serializers.CharField(source="host.fqdn", read_only=True)
    host_hostname = serializers.CharField(source="host.hostname", read_only=True)

    class Meta:
        model = HyperVVirtualMachine
        fields = (
            "id",
            "tenant_id",
            "host_id",
            "host_fqdn",
            "host_hostname",
            "source_id",
            "name",
            "state",
            "vcpu_count",
            "memory_bytes",
            "uptime_seconds",
            "configuration_version",
            "ip_addresses",
            "observed_at",
        )
        read_only_fields = fields


class HyperVVirtualMachineActionRequestSerializer(serializers.Serializer):
    action = serializers.ChoiceField(choices=HyperVVirtualMachineActionJob.Action.choices)


class HyperVVirtualMachineActionJobSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    enrollment_id = serializers.UUIDField(read_only=True)
    virtual_machine_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = HyperVVirtualMachineActionJob
        fields = (
            "id",
            "tenant_id",
            "enrollment_id",
            "virtual_machine_id",
            "vm_source_id",
            "vm_name",
            "action",
            "status",
            "result_code",
            "created_at",
            "delivered_at",
            "started_at",
            "completed_at",
        )
        read_only_fields = fields


class HyperVConsoleSessionSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    enrollment_id = serializers.UUIDField(read_only=True)
    virtual_machine_id = serializers.UUIDField(read_only=True, allow_null=True)

    class Meta:
        model = HyperVConsoleSession
        fields = (
            "id",
            "tenant_id",
            "enrollment_id",
            "virtual_machine_id",
            "vm_name",
            "requested_by",
            "status",
            "frame_sequence",
            "frame_width",
            "frame_height",
            "failure_code",
            "created_at",
            "connected_at",
            "last_agent_contact_at",
            "closed_at",
        )
        read_only_fields = fields


class HyperVConsoleInputSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=HyperVConsoleInputEvent.EventType.choices)
    payload = serializers.JSONField()


class LinuxSystemSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = LinuxSystem
        fields = (
            "id",
            "tenant_id",
            "source_id",
            "hostname",
            "fqdn",
            "system_type",
            "distribution",
            "distribution_version",
            "kernel_version",
            "architecture",
            "manufacturer",
            "model",
            "serial_number",
            "logical_processors",
            "memory_bytes",
            "agent_version",
            "health",
            "network_interfaces",
            "fixed_volumes",
            "last_seen_at",
        )
        read_only_fields = fields


class SoftwareInventorySnapshotSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    enrollment_id = serializers.UUIDField(read_only=True)
    device_uri = serializers.CharField(
        source="enrollment.device_uri",
        read_only=True,
    )
    display_name = serializers.CharField(
        source="enrollment.display_name",
        read_only=True,
    )

    class Meta:
        model = SoftwareInventorySnapshot
        fields = (
            "id",
            "tenant_id",
            "enrollment_id",
            "device_uri",
            "display_name",
            "platform",
            "status",
            "reboot_required",
            "update_scan_status",
            "last_update_scan_at",
            "last_update_install_at",
            "package_count",
            "updates_available",
            "completed_at",
        )
        read_only_fields = fields


class SoftwarePackageSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    snapshot_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = SoftwarePackage
        fields = (
            "id",
            "tenant_id",
            "snapshot_id",
            "source_id",
            "name",
            "installed_version",
            "available_version",
            "publisher",
            "package_type",
            "update_state",
            "is_os_component",
        )
        read_only_fields = fields


class DiscoveryJobSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    connector_type = serializers.SerializerMethodField()
    result_summary = serializers.SerializerMethodField()
    error_code = serializers.SerializerMethodField()
    error_detail = serializers.SerializerMethodField()

    class Meta:
        model = DiscoveryJob
        fields = (
            "id",
            "tenant_id",
            "connector_type",
            "status",
            "requested_by",
            "correlation_id",
            "result_summary",
            "error_code",
            "error_detail",
            "created_at",
            "started_at",
            "completed_at",
        )
        read_only_fields = fields

    def get_connector_type(self, instance: DiscoveryJob) -> str:
        return public_connector_type(instance.connector_type)

    def get_result_summary(self, instance: DiscoveryJob) -> dict:
        return neutralize_public_protocol_details(instance.result_summary)

    def get_error_code(self, instance: DiscoveryJob) -> str:
        return neutralize_public_protocol_text(instance.error_code)

    def get_error_detail(self, instance: DiscoveryJob) -> dict:
        return neutralize_public_protocol_details(instance.error_detail)


class BmcCommunicationLogSerializer(serializers.ModelSerializer):
    connector_id = serializers.UUIDField(read_only=True, allow_null=True)
    bmc_family = serializers.SerializerMethodField()
    event_type = serializers.SerializerMethodField()
    resource_path = serializers.SerializerMethodField()
    error_code = serializers.SerializerMethodField()
    api_error_code = serializers.SerializerMethodField()
    api_message_id = serializers.SerializerMethodField()

    class Meta:
        model = BmcCommunicationLog
        fields = (
            "id",
            "connector_id",
            "bmc_name",
            "bmc_family",
            "severity",
            "event_type",
            "method",
            "resource_path",
            "http_status",
            "duration_ms",
            "error_code",
            "api_error_code",
            "api_message_id",
            "correlation_id",
            "occurred_at",
        )
        read_only_fields = fields

    def get_bmc_family(self, instance: BmcCommunicationLog) -> str:
        return public_bmc_family(instance.bmc_family)

    def get_event_type(self, instance: BmcCommunicationLog) -> str:
        return neutralize_public_protocol_text(instance.event_type)

    def get_resource_path(self, instance: BmcCommunicationLog) -> str:
        return neutralize_public_protocol_text(instance.resource_path)

    def get_error_code(self, instance: BmcCommunicationLog) -> str:
        return neutralize_public_protocol_text(instance.error_code)

    def get_api_error_code(self, instance: BmcCommunicationLog) -> str:
        return neutralize_public_protocol_text(instance.redfish_error_code)

    def get_api_message_id(self, instance: BmcCommunicationLog) -> str:
        return neutralize_public_protocol_text(instance.redfish_message_id)


class BmcEventLogEntrySerializer(serializers.ModelSerializer):
    connector_id = serializers.UUIDField(read_only=True, allow_null=True)
    source_record_id = serializers.SerializerMethodField()
    message = serializers.SerializerMethodField()
    record_format = serializers.SerializerMethodField()

    class Meta:
        model = BmcEventLogEntry
        fields = (
            "id",
            "connector_id",
            "bmc_name",
            "log_type",
            "source_record_id",
            "severity",
            "message",
            "source_created_at",
            "source_updated_at",
            "repeat_count",
            "repaired",
            "event_class",
            "event_code",
            "event_number",
            "record_format",
            "last_discovered_at",
        )
        read_only_fields = fields

    def get_message(self, instance: BmcEventLogEntry) -> str:
        return neutralize_public_protocol_text(instance.message)

    def get_source_record_id(self, instance: BmcEventLogEntry) -> str:
        return neutralize_public_protocol_text(instance.source_record_id)

    def get_record_format(self, instance: BmcEventLogEntry) -> str:
        return neutralize_public_protocol_text(instance.record_format)
