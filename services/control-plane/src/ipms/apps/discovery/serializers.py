import ipaddress
import re

from rest_framework import serializers

from .models import (
    BmcCommunicationLog,
    BmcEventLogEntry,
    ConnectorEndpoint,
    DiscoveryJob,
    PhysicalSystem,
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
            "installed_roles_features",
            "network_interfaces",
            "latest_telemetry",
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
