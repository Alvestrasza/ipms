"""Bounded schema 1 contracts; never accept executable provider object strings."""

import hashlib
import json
import re
import uuid

from django.utils.dateparse import parse_datetime
from django.utils import timezone

from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import HyperVVirtualMachine

MAX_SNAPSHOT_BYTES = 48 * 1024
MAX_CHECKPOINTS = 256
REVISION = re.compile(r"^[0-9a-f]{64}$")
CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
OPERATIONS = (
    "inspect",
    "checkpoint_create",
    "checkpoint_delete",
    "checkpoint_apply",
    "settings_update",
)


def invalid():
    raise PublicApiError("invalid_request")


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        invalid()


def canonical_uuid(value):
    if not isinstance(value, str):
        invalid()
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        invalid()
    if str(parsed) != value:
        invalid()
    return value


def text(value, maximum, *, nullable=False, blank=True):
    if nullable and value is None:
        return
    if not isinstance(value, str) or len(value) > maximum or (not blank and not value):
        invalid()
    if any(ord(character) < 32 and character not in "\r\n\t" for character in value):
        invalid()


def integer(value, maximum, *, nullable=False, minimum=0):
    if nullable and value is None:
        return
    if type(value) is not int or not minimum <= value <= maximum:
        invalid()


def boolean(value, *, nullable=False):
    if nullable and value is None:
        return
    if type(value) is not bool:
        invalid()


def canonical_document(value):
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        invalid()


def document_digest(value):
    return hashlib.sha256(canonical_document(value)).hexdigest()


def validate_snapshot(document):
    if len(canonical_document(document)) > MAX_SNAPSHOT_BYTES:
        invalid()
    exact(
        document,
        (
            "schema_version",
            "vm_source_id",
            "vm_name",
            "state",
            "revision",
            "settings",
            "checkpoints",
            "devices",
            "capabilities",
            "collection_status",
        ),
    )
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        invalid()
    canonical_uuid(document["vm_source_id"])
    text(document["vm_name"], 256, blank=False)
    if (
        document["state"] not in HyperVVirtualMachine.State.values
        or not isinstance(document["revision"], str)
        or not REVISION.fullmatch(document["revision"])
    ):
        invalid()
    exact(document["collection_status"], ("settings", "checkpoints", "devices"))
    if any(
        value not in ("collected", "unavailable", "not-reported")
        for value in document["collection_status"].values()
    ):
        invalid()
    settings = document["settings"]
    exact(
        settings,
        (
            "name",
            "notes",
            "configuration_version",
            "generation",
            "processor",
            "memory",
            "automatic_start_action",
            "automatic_start_delay",
            "automatic_stop_action",
            "checkpoint_policy",
        ),
    )
    for key, maximum in (("name", 256), ("notes", 4096), ("configuration_version", 64)):
        text(settings[key], maximum, nullable=True)
    integer(settings["generation"], 2, minimum=1, nullable=True)
    exact(
        settings["processor"],
        (
            "count",
            "reservation_milli_percent",
            "limit_milli_percent",
            "weight",
            "compatibility_for_migration",
        ),
    )
    for key, maximum in (
        ("count", 2048),
        ("reservation_milli_percent", 100000),
        ("limit_milli_percent", 100000),
        ("weight", 10000),
    ):
        integer(settings["processor"][key], maximum, nullable=True)
    boolean(settings["processor"]["compatibility_for_migration"], nullable=True)
    exact(
        settings["memory"],
        (
            "startup_mib",
            "minimum_mib",
            "maximum_mib",
            "dynamic_enabled",
            "buffer_percent",
            "weight",
        ),
    )
    for key in ("startup_mib", "minimum_mib", "maximum_mib"):
        integer(settings["memory"][key], 2**40, nullable=True)
    for key in ("buffer_percent", "weight"):
        integer(settings["memory"][key], 10000, nullable=True)
    boolean(settings["memory"]["dynamic_enabled"], nullable=True)
    for key in ("automatic_start_action", "automatic_stop_action"):
        integer(settings[key], 65535, nullable=True)
    integer(settings["checkpoint_policy"], 5, minimum=2, nullable=True)
    text(settings["automatic_start_delay"], 32, nullable=True)
    exact(document["devices"], ("network_adapters", "storage"))
    # This inspector version does not yet attest a typed device schema. Unknown
    # arrays must not become an unvalidated provider-property execution surface.
    if (
        document["devices"] != {"network_adapters": [], "storage": []}
        or document["collection_status"]["devices"] == "collected"
    ):
        invalid()
    exact(document["capabilities"], OPERATIONS)
    for value in document["capabilities"].values():
        boolean(value)
    checkpoints = document["checkpoints"]
    if not isinstance(checkpoints, list) or len(checkpoints) > MAX_CHECKPOINTS:
        invalid()
    if document["collection_status"]["checkpoints"] != "collected" and checkpoints:
        invalid()
    parents = {}
    current_count = 0
    for checkpoint in checkpoints:
        exact(
            checkpoint,
            (
                "id",
                "parent_id",
                "name",
                "created_at",
                "type",
                "is_current",
                "can_apply",
                "can_delete",
            ),
        )
        checkpoint_id = canonical_uuid(checkpoint["id"])
        if checkpoint_id in parents:
            invalid()
        parent_id = checkpoint["parent_id"]
        if parent_id is not None:
            canonical_uuid(parent_id)
        parents[checkpoint_id] = parent_id
        text(checkpoint["name"], 256, blank=False)
        if checkpoint["created_at"] is not None:
            text(checkpoint["created_at"], 40, blank=False)
            try:
                parsed = parse_datetime(checkpoint["created_at"])
            except ValueError:
                invalid()
            if parsed is None or timezone.is_naive(parsed):
                invalid()
        if checkpoint["type"] not in ("standard", "production", "recovery", "unknown"):
            invalid()
        for key in ("is_current", "can_apply", "can_delete"):
            boolean(checkpoint[key])
        current_count += checkpoint["is_current"]
    if current_count > 1:
        invalid()
    for checkpoint_id in parents:
        visited = set()
        cursor = checkpoint_id
        while cursor is not None:
            if cursor in visited or cursor not in parents:
                invalid()
            visited.add(cursor)
            cursor = parents[cursor]
    return document


def validate_parameters(operation, parameters):
    if operation == "inspect":
        exact(parameters, ())
    elif operation == "checkpoint_create":
        exact(parameters, ("policy",))
        if parameters["policy"] != "configured":
            invalid()
    elif operation == "checkpoint_delete":
        exact(parameters, ("checkpoint_id", "acknowledged_checkpoint_ids"))
        canonical_uuid(parameters["checkpoint_id"])
        values = parameters["acknowledged_checkpoint_ids"]
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_CHECKPOINTS:
            invalid()
        for value in values:
            canonical_uuid(value)
        if len(set(values)) != len(values):
            invalid()
        parameters = {**parameters, "acknowledged_checkpoint_ids": sorted(values)}
    elif operation == "checkpoint_apply":
        exact(
            parameters,
            ("checkpoint_id", "confirmation_vm_name", "confirmation_checkpoint_name"),
        )
        canonical_uuid(parameters["checkpoint_id"])
        text(parameters["confirmation_vm_name"], 256, blank=False)
        text(parameters["confirmation_checkpoint_name"], 256, blank=False)
    elif operation == "settings_update":
        exact(parameters, ("section", "values"))
        section = parameters["section"]
        values = parameters["values"]
        if section == "general":
            exact(values, ("name", "notes"))
            text(values["name"], 100, blank=False)
            text(values["notes"], 4096)
            try:
                if (
                    len(values["name"].encode("utf-16-le")) > 200
                    or len(values["name"].encode("utf-8")) > 256
                    or len(values["notes"].encode("utf-8")) > 4096
                ):
                    invalid()
            except UnicodeError:
                invalid()
            if not values["name"].strip() or any(
                character in values["name"] for character in "\r\n\t"
            ):
                invalid()
        elif section == "processor":
            exact(values, ("count",))
            integer(values["count"], 2048, minimum=1)
        elif section == "memory":
            exact(
                values, ("startup_mib", "minimum_mib", "maximum_mib", "dynamic_enabled")
            )
            for key in ("startup_mib", "minimum_mib", "maximum_mib"):
                integer(values[key], 2**40, minimum=1)
            boolean(values["dynamic_enabled"])
            if (
                not values["minimum_mib"]
                <= values["startup_mib"]
                <= values["maximum_mib"]
            ):
                invalid()
        else:
            invalid()
    else:
        invalid()
    return parameters
