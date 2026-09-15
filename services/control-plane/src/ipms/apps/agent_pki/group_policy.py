# File Name: group_policy.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Bounded validation for native read-only computer Group Policy observations.
from datetime import datetime, timedelta
import hashlib
import json
import re
import uuid

from django.core.exceptions import ValidationError

MAX_GROUP_POLICY_BYTES = 64 * 1024
MAX_GROUP_POLICY_GPOS = 256
GROUP_POLICY_CLOCK_SKEW = timedelta(minutes=5)
_FIELDS = {"schema_version", "source", "scope", "status", "observed_at", "domain_dns", "domain_guid", "gpos"}
_GPO_FIELDS = {"guid", "version", "status", "processed_at"}
_STATUSES = {"collected", "incomplete", "unavailable", "not-domain-joined"}
_GPO_STATUSES = {"applied", "excluded", "failed", "unknown"}
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_CONTEXT_FIELDS = {"enrollment_id", "domain_name", "operating_system_role", "os_build", "operating_system", "received_at"}
_WATERMARK_FIELDS = {"schema_version", "enrollment_id", "identity_sha256", "domain_guid",
                     "highest_observed", "report_sha256", "blocked_through", "recorded_at"}


def utc_timestamp(value):
    if not isinstance(value, str) or _UTC.fullmatch(value) is None:
        raise ValueError("A UTC Z timestamp is required.")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def canonical_guid(value):
    if not isinstance(value, str) or len(value) != 36:
        raise ValueError("A canonical GUID is required.")
    parsed = uuid.UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError("A canonical GUID is required.")
    return value


def canonical_domain(value):
    if not isinstance(value, str) or not 3 <= len(value) <= 253:
        raise ValueError("A canonical DNS domain is required.")
    labels = value.split(".")
    if len(labels) < 2 or all(label.isdecimal() for label in labels) or any(
        _DNS_LABEL.fullmatch(label) is None for label in labels
    ):
        raise ValueError("A canonical DNS domain is required.")
    return value


def validate_group_policy(value, *, inventory_domain, now):
    """Validate a whole observation; never salvage positive rows from a bad one.

    The authenticated receiver supplies the inventory domain and clock. The
    Agent observation/processing clocks are retained, including expired data.
    A fresh receipt must not make an old queued observation appear current.
    """
    try:
        if (not isinstance(value, dict) or set(value) != _FIELDS
                or value["schema_version"] != "1" or value["source"] != "windows-rsop-computer"
                or value["scope"] != "computer" or not isinstance(value["status"], str)
                or value["status"] not in _STATUSES
                or not isinstance(value["gpos"], list) or len(value["gpos"]) > MAX_GROUP_POLICY_GPOS):
            raise ValueError()
        observed = utc_timestamp(value["observed_at"])
        if observed > now + GROUP_POLICY_CLOCK_SKEW:
            raise ValueError()
        dns, guid = value["domain_dns"], value["domain_guid"]
        if dns is not None and (canonical_domain(dns) != inventory_domain.casefold()):
            raise ValueError()
        if guid is not None:
            canonical_guid(guid)
        if value["status"] == "collected" and (dns is None or guid is None):
            raise ValueError()
        if value["status"] != "collected" and value["gpos"]:
            raise ValueError()
        if value["status"] == "not-domain-joined" and (dns is not None or guid is not None):
            raise ValueError()
        seen, gpos = set(), []
        for row in value["gpos"]:
            if (not isinstance(row, dict) or set(row) != _GPO_FIELDS
                    or type(row["version"]) is not int or not 0 <= row["version"] <= 2**32 - 1
                    or not isinstance(row["status"], str) or row["status"] not in _GPO_STATUSES):
                raise ValueError()
            identity = canonical_guid(row["guid"])
            if identity in seen:
                raise ValueError()
            seen.add(identity)
            processed = utc_timestamp(row["processed_at"]) if row["processed_at"] is not None else None
            if (processed is not None and processed > observed) or (row["status"] == "applied" and processed is None):
                raise ValueError()
            gpos.append(dict(row))
        report = {**value, "gpos": gpos}
        if len(json.dumps(report, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")) > MAX_GROUP_POLICY_BYTES:
            raise ValueError()
        return report
    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        raise ValidationError("The Agent Group Policy report is invalid.") from exc


def _sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _identity(context):
    return _sha256({key: context[key] for key in _CONTEXT_FIELDS - {"received_at"}})


def _watermark(value, enrollment_id):
    """Parse bounded server-owned state without reducing clocks after clock correction."""
    if (not isinstance(value, dict) or set(value) != _WATERMARK_FIELDS or value["schema_version"] != "1"
            or canonical_guid(value["enrollment_id"]) != enrollment_id
            or not isinstance(value["identity_sha256"], str) or _SHA256.fullmatch(value["identity_sha256"]) is None):
        raise ValueError("Invalid Group Policy evidence watermark.")
    if value["domain_guid"] is not None:
        canonical_guid(value["domain_guid"])
    state = {**value, **{key: utc_timestamp(value[key]) if value[key] is not None else None
                        for key in ("highest_observed", "blocked_through", "recorded_at")}}
    try:
        latest_allowed = state["recorded_at"] + GROUP_POLICY_CLOCK_SKEW if state["recorded_at"] else None
    except OverflowError as exc:
        raise ValueError("Invalid Group Policy evidence watermark.") from exc
    if (state["recorded_at"] is None or (state["highest_observed"] is None) != (value["report_sha256"] is None)
            or (value["report_sha256"] is not None and (
                not isinstance(value["report_sha256"], str) or _SHA256.fullmatch(value["report_sha256"]) is None))
            or any(state[key] is not None and state[key] > latest_allowed
                   for key in ("highest_observed", "blocked_through"))):
        raise ValueError("Invalid Group Policy evidence watermark.")
    return state


def watermark_matches_report(snapshot, report, context, *, state=None):
    """A raw report alone cannot undo a receiver tombstone or change its identity."""
    try:
        state = state or _watermark(snapshot.get("group_policy_watermark"), context["enrollment_id"])
        observed = utc_timestamp(report["observed_at"])
        return bool(
            state["identity_sha256"] == _identity(context)
            and state["highest_observed"] == observed and state["report_sha256"] == _sha256(report)
            and (state["blocked_through"] is None or observed > state["blocked_through"])
            and (report["domain_guid"] is None or report["domain_guid"] == state["domain_guid"])
            and utc_timestamp(context["received_at"]) <= state["recorded_at"]
        )
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def _previous_report(snapshot, state, now):
    context = snapshot.get("group_policy_context")
    if not isinstance(context, dict) or set(context) != _CONTEXT_FIELDS:
        return None
    try:
        report = validate_group_policy(snapshot.get("group_policy"), inventory_domain=context["domain_name"], now=now)
        received = utc_timestamp(context["received_at"])
        if (received > now + GROUP_POLICY_CLOCK_SKEW
                or utc_timestamp(report["observed_at"]) > received + GROUP_POLICY_CLOCK_SKEW
                or not watermark_matches_report(snapshot, report, context, state=state)):
            return None
        return {"group_policy": report, "group_policy_context": context}
    except (ValidationError, ValueError, TypeError, OverflowError):
        return None


def _legacy_watermark(previous, context, now):
    """Admit a valid earlier snapshot without pretending a missing one was positive."""
    prior_context = previous.get("group_policy_context")
    if (not isinstance(prior_context, dict)
            or set(prior_context) not in (_CONTEXT_FIELDS, _CONTEXT_FIELDS | {"evidence_conflict"})
            or prior_context["enrollment_id"] != context["enrollment_id"]
            or ("evidence_conflict" in prior_context and prior_context["evidence_conflict"] is not True)):
        raise ValueError("Invalid previous Group Policy evidence.")
    report = validate_group_policy(previous.get("group_policy"), inventory_domain=prior_context["domain_name"], now=now)
    observed, received = utc_timestamp(report["observed_at"]), utc_timestamp(prior_context["received_at"])
    if observed > received + GROUP_POLICY_CLOCK_SKEW or received > now + GROUP_POLICY_CLOCK_SKEW:
        raise ValueError("Invalid previous Group Policy evidence.")
    return {
        "schema_version": "1", "enrollment_id": context["enrollment_id"],
        "identity_sha256": _identity(prior_context), "domain_guid": report["domain_guid"],
        "highest_observed": observed, "report_sha256": _sha256(report),
        "blocked_through": observed if prior_context.get("evidence_conflict") else None,
        "recorded_at": max(now, received),
    }


def preserve_newer_group_policy(previous, incoming, *, now):
    """Keep a monotonic enrollment-bound tombstone when application evidence clears.

    Omission and identity changes have no trustworthy ordering within the old
    identity. Their barrier includes the allowed five-minute Agent clock skew:
    an unseen queued report in that window must not restore an old positive.
    Report/context are absent while blocked; the bounded server watermark
    survives. Only an observation beyond both clocks can restore evidence.
    """
    context, report = incoming["group_policy_context"], incoming.get("group_policy")
    identity = _identity(context)
    state = {
        "schema_version": "1", "enrollment_id": context["enrollment_id"],
        "identity_sha256": identity, "domain_guid": None, "highest_observed": None,
        "report_sha256": None, "blocked_through": None, "recorded_at": now,
    }
    invalid = previous is not None and not isinstance(previous, dict)
    previous = previous if isinstance(previous, dict) else {}
    try:
        if "group_policy_watermark" in previous:
            state = _watermark(previous["group_policy_watermark"], context["enrollment_id"])
        elif "group_policy" in previous or "group_policy_context" in previous:
            state = _legacy_watermark(previous, context, now)
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        invalid = True
        # Recover trustworthy legacy clocks where possible, but never restore
        # the actual report from malformed watermark state in this receipt.
        try:
            state = _legacy_watermark(previous, context, now)
        except (ValidationError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
            pass
    prior_highest, prior_hash = state["highest_observed"], state["report_sha256"]
    prior = _previous_report(previous, state, now)
    if (prior_highest is not None
            and (state["blocked_through"] is None or prior_highest > state["blocked_through"])
            and prior is None):
        invalid = True
    observed = utc_timestamp(report["observed_at"]) if report else None
    report_hash = _sha256(report) if report else None
    reported_domain = report["domain_guid"] if report else None
    changed_inventory = identity != state["identity_sha256"]
    changed_identity = changed_inventory or (
        reported_domain is not None and state["domain_guid"] is not None and reported_domain != state["domain_guid"]
    )
    barrier = state["blocked_through"]
    if invalid or report is None or changed_identity:
        barrier = max(value for value in (barrier, prior_highest, now + GROUP_POLICY_CLOCK_SKEW) if value is not None)
    elif observed == prior_highest and report_hash != prior_hash:
        barrier = max(value for value in (barrier, prior_highest) if value is not None)
    # Decide against the previous clocks before advancing the high watermark.
    accepted = None
    if not invalid and report is not None and not changed_identity:
        if (prior_highest is None or observed > prior_highest) and (barrier is None or observed > barrier):
            accepted = incoming
        elif prior is not None and (barrier is None or prior_highest > barrier):
            accepted = prior
    if observed is not None and (prior_highest is None or observed > prior_highest):
        state["highest_observed"], state["report_sha256"] = observed, report_hash
    state.update(
        identity_sha256=identity, blocked_through=barrier, recorded_at=max(state["recorded_at"], now),
        domain_guid=reported_domain if reported_domain is not None else (
            None if changed_inventory else state["domain_guid"]
        ),
    )
    serialized = {**state, **{key: state[key].isoformat().replace("+00:00", "Z") if state[key] is not None else None
                             for key in ("highest_observed", "blocked_through", "recorded_at")}}
    return {**(accepted or {}), "group_policy_watermark": serialized}
