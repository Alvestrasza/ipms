"""Public management inputs admit only typed, bounded operation documents."""

from rest_framework import serializers

from ipms.apps.agent_pki.hyperv_management_schema import validate_parameters
from ipms.apps.tenancy.serializers import StrictInputSerializer


class ManagementRefreshSerializer(StrictInputSerializer):
    request_id = serializers.UUIDField()


class ManagementDialogSerializer(StrictInputSerializer):
    dialog_id = serializers.UUIDField()
    action = serializers.ChoiceField(choices=("open", "renew", "release"))
    edit = serializers.BooleanField(default=False)


class ManagementOperationSerializer(StrictInputSerializer):
    request_id = serializers.UUIDField()
    settings_dialog_id = serializers.UUIDField(required=False)
    operation = serializers.ChoiceField(
        choices=(
            "checkpoint_create",
            "checkpoint_delete",
            "checkpoint_apply",
            "settings_update",
        )
    )
    expected_revision = serializers.RegexField(r"^[0-9a-f]{64}$", max_length=64)
    parameters = serializers.JSONField()

    def validate(self, attrs):
        if (attrs["operation"] == "settings_update") != ("settings_dialog_id" in attrs):
            raise serializers.ValidationError(
                "Settings updates require a dialog identity; other operations must omit it."
            )
        attrs["parameters"] = validate_parameters(
            attrs["operation"], attrs["parameters"]
        )
        return attrs
