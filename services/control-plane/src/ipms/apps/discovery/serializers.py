import ipaddress
import re

from rest_framework import serializers

from .models import (
    BmcCommunicationLog,
    BmcEventLogEntry,
    ConnectorEndpoint,
    DiscoveryJob,
    PhysicalSystem,
)


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def normalized_bmc_origin(address: str, port: int) -> str:
    hostname = f"[{address}]" if ":" in address else address
    return f"https://{hostname}{f':{port}' if port != 443 else ''}/"


class ConnectorEndpointSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    trust_mode = serializers.SerializerMethodField()

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


class BmcEndpointSerializer(serializers.Serializer):
    bmc_family = serializers.ChoiceField(choices=ConnectorEndpoint.BmcFamily.choices)
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

    class Meta:
        model = PhysicalSystem
        fields = (
            "id",
            "tenant_id",
            "connector_id",
            "source_resource_id",
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


class DiscoveryJobSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)

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


class BmcCommunicationLogSerializer(serializers.ModelSerializer):
    connector_id = serializers.UUIDField(read_only=True, allow_null=True)

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
            "redfish_error_code",
            "redfish_message_id",
            "correlation_id",
            "occurred_at",
        )
        read_only_fields = fields


class BmcEventLogEntrySerializer(serializers.ModelSerializer):
    connector_id = serializers.UUIDField(read_only=True, allow_null=True)

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
