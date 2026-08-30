import re
from urllib.parse import urlsplit

from rest_framework import serializers

from .models import ConnectorEndpoint, DiscoveryJob, PhysicalSystem


class ConnectorEndpointSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)
    trust_mode = serializers.SerializerMethodField()

    class Meta:
        model = ConnectorEndpoint
        fields = (
            "id",
            "tenant_id",
            "connector_type",
            "display_name",
            "base_url",
            "enabled",
            "health",
            "trust_mode",
            "last_error_code",
            "last_attempt_at",
            "last_success_at",
        )
        read_only_fields = fields

    def get_trust_mode(self, instance: ConnectorEndpoint) -> str:
        return "certificate-pin" if instance.tls_certificate_sha256 else "unconfigured"


class IloConnectorEnrollmentSerializer(serializers.Serializer):
    display_name = serializers.CharField(max_length=255)
    base_url = serializers.URLField(max_length=512)
    certificate_sha256 = serializers.CharField(max_length=95)
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=4096, write_only=True, trim_whitespace=False)
    confirm_read_only = serializers.BooleanField(write_only=True)

    def validate_base_url(self, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            raise serializers.ValidationError("A credential-free HTTPS URL is required.")
        if parts.path not in ("", "/") or parts.query or parts.fragment:
            raise serializers.ValidationError("Only the iLO origin URL is allowed.")
        try:
            port = parts.port
        except ValueError as exc:
            raise serializers.ValidationError("The HTTPS port is invalid.") from exc
        hostname = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
        return f"https://{hostname}{f':{port}' if port else ''}/"

    def validate_certificate_sha256(self, value: str) -> str:
        fingerprint = value.replace(":", "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise serializers.ValidationError("The SHA-256 fingerprint is invalid.")
        return fingerprint

    def validate_confirm_read_only(self, value: bool) -> bool:
        if not value:
            raise serializers.ValidationError("Read-only scope confirmation is required.")
        return value

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
            "created_at",
            "started_at",
            "completed_at",
        )
        read_only_fields = fields
