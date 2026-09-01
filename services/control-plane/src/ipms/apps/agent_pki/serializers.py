import ipaddress
import re

from rest_framework import serializers

from .models import WindowsAgentDeployment


HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


class WindowsAgentDeploymentRequestSerializer(serializers.Serializer):
    display_name = serializers.CharField(max_length=255)
    address = serializers.CharField(max_length=253)
    port = serializers.IntegerField(min_value=1, max_value=65535, default=5986)
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(
        max_length=4096,
        write_only=True,
        trim_whitespace=False,
    )

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


class WindowsAgentDeploymentSerializer(serializers.ModelSerializer):
    tenant_id = serializers.UUIDField(read_only=True)

    class Meta:
        model = WindowsAgentDeployment
        fields = (
            "id",
            "tenant_id",
            "display_name",
            "target_address",
            "target_port",
            "status",
            "error_code",
            "created_at",
            "started_at",
            "completed_at",
        )
        read_only_fields = fields
