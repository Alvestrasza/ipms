# File Name: contract.py
# Version: v0.1.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Strict bounded WSUS metadata contract, without executable content.
import json
import re
from datetime import timedelta

from django.utils import timezone
from rest_framework import serializers
from rest_framework.parsers import BaseParser

from ipms.apps.core.exceptions import PublicApiError

MAX_BYTES = 1_048_576
STATES = ("unknown", "not_applicable", "not_installed", "downloaded", "installed", "failed", "installed_pending_reboot")


class BoundedJSONParser(BaseParser):
    media_type = "application/json"

    def parse(self, stream, media_type=None, parser_context=None):
        raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise PublicApiError("wsus_payload_too_large", status_code=413)

        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        try:
            return json.loads(raw, object_pairs_hook=unique,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise PublicApiError("wsus_invalid_json") from exc


def normalized_fqdn(value):
    if not isinstance(value, str):
        return ""
    value = value.lower().rstrip(".")
    if len(value) > 253 or "." not in value:
        return ""
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        return ""
    return value


class StrictSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - set(self.fields):
            raise serializers.ValidationError({"non_field_errors": ["Unknown metadata fields."]})
        return super().to_internal_value(data)


class AwareDateTimeField(serializers.DateTimeField):
    def to_internal_value(self, value):
        if not isinstance(value, str) or not re.search(r"(?:Z|[+-]\d\d:\d\d)$", value):
            raise serializers.ValidationError("An explicit UTC offset is required.")
        return super().to_internal_value(value)


class UpdateSerializer(StrictSerializer):
    update_id = serializers.UUIDField()
    revision = serializers.IntegerField(min_value=1, max_value=2_147_483_647)
    title = serializers.CharField(max_length=512)
    kb_articles = serializers.ListField(child=serializers.RegexField(r"^[0-9]{1,12}$"), max_length=20)
    products = serializers.ListField(child=serializers.CharField(max_length=128), max_length=20)
    classification = serializers.CharField(max_length=128, allow_blank=True)
    severity = serializers.CharField(max_length=32, allow_blank=True)


class StateSerializer(StrictSerializer):
    update_id = serializers.UUIDField()
    revision = serializers.IntegerField(min_value=1, max_value=2_147_483_647)
    state = serializers.ChoiceField(choices=STATES)


class ComputerSerializer(StrictSerializer):
    computer_id = serializers.UUIDField()
    fqdn = serializers.CharField(max_length=254)
    reported_at = AwareDateTimeField(allow_null=True)
    updates = StateSerializer(many=True, max_length=1000)

    def validate_fqdn(self, value):
        normalized = normalized_fqdn(value)
        if not normalized:
            raise serializers.ValidationError("A valid full DNS name is required.")
        return normalized


def update_key(update):
    return str(update["update_id"]), update["revision"]


class SnapshotSerializer(StrictSerializer):
    schema_version = serializers.IntegerField(min_value=1, max_value=1)
    snapshot_id = serializers.UUIDField()
    observed_at = AwareDateTimeField()
    complete = serializers.BooleanField()
    scope = serializers.CharField(max_length=255)
    updates = UpdateSerializer(many=True, max_length=1000)
    computers = ComputerSerializer(many=True, max_length=500)

    def validate(self, data):
        if not data["complete"]:
            raise serializers.ValidationError("Only complete snapshots can be published.")
        if data["observed_at"] > timezone.now() + timedelta(minutes=5):
            raise serializers.ValidationError("Observation is in the future.")
        keys = {update_key(u) for u in data["updates"]}
        if len(keys) != len(data["updates"]):
            raise serializers.ValidationError("Duplicate update revision.")
        ids = set()
        states = 0
        for computer in data["computers"]:
            if computer["computer_id"] in ids:
                raise serializers.ValidationError("Duplicate WSUS computer.")
            ids.add(computer["computer_id"])
            if computer["reported_at"] and computer["reported_at"] > data["observed_at"]:
                raise serializers.ValidationError("Report is newer than snapshot.")
            computer_keys = {update_key(u) for u in computer["updates"]}
            if len(computer_keys) != len(computer["updates"]) or not computer_keys <= keys:
                raise serializers.ValidationError("Duplicate or unknown update revision in report.")
            states += len(computer_keys)
        if states > 10000:
            raise serializers.ValidationError("Too many installation states.")
        return data


class InstalledUpdateSerializer(StrictSerializer):
    update_id = serializers.UUIDField()
    revision = serializers.IntegerField(min_value=1, max_value=2_147_483_647)


class AgentUpdateEvidenceSerializer(StrictSerializer):
    source = serializers.ChoiceField(choices=("wua-local-cache",))
    status = serializers.ChoiceField(choices=("collected", "unavailable", "limit-exceeded"))
    observed_at = AwareDateTimeField(allow_null=True)
    updates = InstalledUpdateSerializer(many=True, max_length=128)

    def validate(self, data):
        if data["status"] == "collected" and not data["observed_at"]:
            raise serializers.ValidationError("Collection requires observation time.")
        if data["status"] != "collected" and data["updates"]:
            raise serializers.ValidationError("Failed or truncated collection cannot claim installed updates.")
        if data["observed_at"] and data["observed_at"] > timezone.now() + timedelta(minutes=5):
            raise serializers.ValidationError("Observation is in the future.")
        if len({update_key(u) for u in data["updates"]}) != len(data["updates"]):
            raise serializers.ValidationError("Duplicate installed update evidence.")
        return data
