# File Name: evaluator.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Server-side comparison of complete immutable manifests with bounded native observations.
from collections import Counter


def value_matches_type(value, value_type):
    if value_type == "dword":
        return type(value) is int and 0 <= value <= 0xFFFFFFFF
    if value_type == "string":
        return isinstance(value, str) and len(value) <= 4096 and "\x00" not in value
    if value_type == "string_list":
        return (isinstance(value, list) and len(value) <= 256
                and all(isinstance(item, str) and len(item) <= 512 and "\x00" not in item for item in value))
    return False


def evaluate(manifest, observations, system):
    """Every source control receives a finding; uncertainty can never pass."""
    findings = []
    for control in manifest["controls"]:
        observation = observations[control["id"]]
        status, reason = "unknown", observation["read_status"]
        actual = observation["value"]
        scope = control["scope"]
        comparison = control["comparison"]
        if scope != "machine":
            reason = "scope_unverified"
        elif control["kind"] == "unsupported" or comparison == "unsupported":
            reason = "unsupported"
        elif control["kind"] == "system_access" and system["join_state"] != "workgroup":
            # Local SAM values do not establish domain/FGPP account policy.
            reason = "scope_unverified"
        elif comparison == "absent" and observation["read_status"] in ("ok", "missing"):
            status, reason = ("passed", "matched") if observation["read_status"] == "missing" else ("failed", "different")
        elif observation["read_status"] == "ok":
            if not value_matches_type(actual, control["value_type"]):
                reason = "invalid_value"
            else:
                expected = control["expected"]
                # Explicit privilege assignments are SID sets. Registry multi-
                # strings keep their ordering and are compared exactly.
                equal = (sorted(actual) == sorted(expected) if control["kind"] == "privilege_right"
                         else type(actual) is type(expected) and actual == expected)
                status, reason = ("passed", "matched") if equal else ("failed", "different")
        findings.append({
            "control_id": control["id"], "label": control["label"], "scope": scope,
            "kind": control["kind"], "status": status, "reason": reason,
            "expected": control["expected"], "observed": actual,
        })
    counts = Counter(row["status"] for row in findings)
    return {
        "findings": findings, "total_controls": len(findings),
        "passed_controls": counts["passed"], "failed_controls": counts["failed"],
        "unknown_controls": counts["unknown"], "not_applicable_controls": 0,
        "scope_verified": bool(findings) and not counts["unknown"],
    }
