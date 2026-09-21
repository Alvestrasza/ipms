# File Name: contract.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Strict HGS planning and evidence contract; no executable or secret payloads.
import hashlib
import ipaddress
import json
import re
import uuid

from django.core.exceptions import ValidationError

PROFILES = ({"id": "vtpm", "label": "vTPM"}, {"id": "shielded", "label": "Shielded VMs"})
OPERATIONS = frozenset({"inspect", "install_role", "create_forest", "join_node", "initialize", "verify", "reboot"})
READ_ONLY = frozenset({"inspect", "verify"})
ACTIVE = ("queued", "offered", "running", "waiting_for_reboot")
TERMINAL = ("succeeded", "failed", "cancelled", "reconciliation_required")
BOOLEAN_OBSERVATIONS = frozenset({
    "is_server", "domain_joined", "role_installed", "service_initialized",
    "signing_certificate_ready", "encryption_certificate_ready", "feature_source_ready",
    "dsrm_secret_ready", "join_secret_ready", "reboot_pending", "service_healthy",
    "key_access_verified", "mode_supported", "offline_source_policy_ready",
})
OBSERVATIONS = BOOLEAN_OBSERVATIONS | {"os_build", "computer_name", "domain_name", "domain_role", "attestation_mode", "boot_id",
    "configured_service_name", "configured_signing_thumbprint", "configured_encryption_thumbprint"}
RESULT_CODES = frozenset({"hgs_inspected", "hgs_verified", "hgs_step_succeeded", "hgs_reboot_required", "hgs_reboot_observed",
    "hgs_job_expired", "hgs_authority_lost", "hgs_prerequisite_failed", "hgs_provider_failed", "hgs_postcondition_failed",
    "hgs_reconciliation_required", "hgs_unsupported_platform"})
UNCLAIMED_FAILURES = frozenset({"hgs_job_expired", "hgs_authority_lost", "hgs_prerequisite_failed", "hgs_provider_failed", "hgs_unsupported_platform"})
CONFIG_FIELDS = {"feature_source", "signing_thumbprint", "encryption_thumbprint", "dsrm_secret_ref", "join_secret_ref", "allow_reboot", "primary_server"}
PLAN_FIELDS = CONFIG_FIELDS | {"name", "profile", "attestation_mode", "domain_name", "service_name", "node_ids"}


def reject():
    raise ValidationError("hgs_contract_invalid")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def text(value, minimum=1, maximum=255):
    return isinstance(value, str) and minimum <= len(value) <= maximum and all(32 <= ord(char) < 127 for char in value)


def identifier(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def dns(value):
    return text(value, 3, 253) and "." in value and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split("."))


def validate_plan(document):
    if not isinstance(document, dict) or set(document) != PLAN_FIELDS:
        reject()
    value = dict(document)
    if not text(value["name"], 1, 128) or value["name"] != value["name"].strip():
        reject()
    if value["profile"] not in ("vtpm", "shielded") or value["attestation_mode"] not in ("host_key", "tpm"):
        reject()
    if value["profile"] == "shielded" and value["attestation_mode"] != "tpm":
        reject()
    if not dns(value["domain_name"]) or len(value["domain_name"].split(".")[0]) > 15:
        reject()
    if not text(value["service_name"], 1, 63) or not re.fullmatch(r"[a-z][a-z0-9-]{0,61}[a-z0-9]|[a-z]", value["service_name"]):
        reject()
    source = value["feature_source"]
    if (not text(source, 4, 240) or not re.fullmatch(r"[A-Za-z]:\\[^<>\"|?*]+", source)
            or ":" in source[2:] or ".." in source or any(char in source for char in "$;`")
            or any(part == "." for part in source.split("\\"))):
        reject()
    for field in ("signing_thumbprint", "encryption_thumbprint"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9A-Fa-f]{40}", value[field]):
            reject()
        value[field] = value[field].upper()
    if value["signing_thumbprint"] == value["encryption_thumbprint"]:
        reject()
    for field in ("dsrm_secret_ref", "join_secret_ref"):
        if not isinstance(value[field], str) or not re.fullmatch(r"[A-Za-z0-9_-]{0,64}", value[field]):
            reject()
    if not value["dsrm_secret_ref"] or type(value["allow_reboot"]) is not bool:
        reject()
    ids = value["node_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 8 or not all(identifier(item) for item in ids) or len(set(ids)) != len(ids):
        reject()
    primary = value["primary_server"]
    if not text(primary, 0, 45) or "%" in primary:
        reject()
    if primary:
        try:
            address = ipaddress.ip_address(primary)
            if address.is_unspecified or address.is_loopback or address.is_multicast:
                reject()
        except ValueError:
            reject()
    if len(ids) > 1 and (not primary or not value["join_secret_ref"]):
        reject()
    return value


def validate_observation(value):
    if not isinstance(value, dict) or set(value) != OBSERVATIONS:
        reject()
    if any(type(value[key]) is not bool for key in BOOLEAN_OBSERVATIONS):
        reject()
    if type(value["domain_role"]) is not int or not 0 <= value["domain_role"] <= 5:
        reject()
    if value["attestation_mode"] not in ("none", "host_key", "tpm"):
        reject()
    for key, maximum in (("os_build", 16), ("computer_name", 255), ("domain_name", 253), ("boot_id", 64)):
        if not text(value[key], 0 if key == "domain_name" else 1, maximum):
            reject()
    if not re.fullmatch(r"[0-9]{1,16}", value["os_build"]):
        reject()
    if not text(value["configured_service_name"], 0, 253):
        reject()
    for key in ("configured_signing_thumbprint", "configured_encryption_thumbprint"):
        if not isinstance(value[key], str) or not re.fullmatch(r"(?:[0-9A-F]{40})?", value[key]):
            reject()
    return value


def node_steps(node):
    return ("install_role", "reboot", "create_forest" if node.role == "primary" else "join_node", "reboot", "initialize", "verify")


def readiness_blockers(config, observation, *, hostname, role, initial=False):
    o = validate_observation(observation)
    blockers = []
    if initial and o["domain_joined"]:
        blockers.append("fresh_workgroup_node_required")
    if not o["is_server"] or o["os_build"] not in ("20348", "26100"):
        blockers.append("unsupported_windows_version")
    if o["computer_name"].lower().split(".")[0] != hostname.lower().split(".")[0]:
        blockers.append("node_identity_changed")
    if o["domain_joined"] and o["domain_name"].lower() != config["domain_name"]:
        blockers.append("different_domain_membership")
    if o["service_initialized"] and o["attestation_mode"] != config["attestation_mode"]:
        blockers.append("attestation_mode_mismatch")
    if o["service_initialized"] and (o["configured_service_name"].lower() != config["service_name"]
            or o["configured_signing_thumbprint"] != config["signing_thumbprint"]
            or o["configured_encryption_thumbprint"] != config["encryption_thumbprint"]):
        blockers.append("hgs_configuration_mismatch")
    if not o["signing_certificate_ready"] or not o["encryption_certificate_ready"]:
        blockers.append("certificate_private_key_unavailable")
    if not o["role_installed"] and (not o["feature_source_ready"] or not o["offline_source_policy_ready"]):
        blockers.append("offline_feature_source_unavailable")
    if o["domain_role"] < 4 and not o["dsrm_secret_ready"]:
        blockers.append("dsrm_secret_unavailable")
    if role == "additional" and o["domain_role"] < 4 and not o["join_secret_ready"]:
        blockers.append("join_secret_unavailable")
    if not o["mode_supported"]:
        blockers.append("provider_unavailable")
    if not config["allow_reboot"] and (o["reboot_pending"] or not o["role_installed"] or o["domain_role"] < 4):
        blockers.append("planned_reboot_not_authorized")
    return blockers


def postcondition(operation, config, observation):
    o = validate_observation(observation)
    if operation == "inspect":
        return True
    if operation == "install_role":
        return o["role_installed"]
    if operation in ("create_forest", "join_node"):
        return o["domain_joined"] and o["domain_name"].lower() == config["domain_name"] and o["domain_role"] >= 4
    if operation == "reboot":
        return not o["reboot_pending"]
    if operation in ("initialize", "verify"):
        valid = (not o["reboot_pending"] and o["role_installed"] and o["domain_joined"] and o["domain_role"] >= 4
                 and o["domain_name"].lower() == config["domain_name"]
                 and o["service_initialized"] and o["attestation_mode"] == config["attestation_mode"]
                 and o["key_access_verified"]
                 and o["signing_certificate_ready"] and o["encryption_certificate_ready"]
                 and o["configured_service_name"].lower() == config["service_name"]
                 and o["configured_signing_thumbprint"] == config["signing_thumbprint"]
                 and o["configured_encryption_thumbprint"] == config["encryption_thumbprint"])
        return valid and (operation != "verify" or (o["service_healthy"] and o["key_access_verified"]))
    return False
