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
