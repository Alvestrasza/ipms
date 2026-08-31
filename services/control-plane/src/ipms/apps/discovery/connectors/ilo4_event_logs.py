from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


MAX_LOG_SERVICES = 16
MAX_LOG_ENTRIES = 1024
MAX_LOG_MESSAGE_LENGTH = 8192


class Ilo4EventLogError(Exception):
    pass


@dataclass(frozen=True)
class Ilo4EventLogSnapshot:
    entries: list[dict[str, Any]]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _path(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    path = value.get("@odata.id") or value.get("href")
    return path if isinstance(path, str) else ""


def _links(document: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(document.get("Links") or document.get("links"))


def _resource_path(document: dict[str, Any], key: str) -> str:
    return _path(document.get(key)) or _path(_links(document).get(key))


def _member_paths(document: dict[str, Any], *, limit: int) -> list[str]:
    members = document.get("Members")
    if not isinstance(members, list):
        members = _links(document).get("Member", [])
    if not isinstance(members, list) or len(members) > limit:
        raise Ilo4EventLogError("collection_limit_exceeded")
    paths = [_path(member) for member in members]
    if any(not path for path in paths):
        raise Ilo4EventLogError("malformed_response")
    return paths


def _collection(
    get: Callable[[str], dict[str, Any]],
    document: dict[str, Any],
    key: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    path = _resource_path(document, key)
    if not path:
        return []
    collection = get(path)
    return [get(member) for member in _member_paths(collection, limit=limit)]


def _severity(value: Any) -> str:
    normalized = str(value or "").casefold()
    if normalized == "ok":
        return "info"
    if normalized in {"warning", "critical"}:
        return normalized
    return "unknown"


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _non_negative_int(value: Any) -> int | None:
    parsed = _optional_int(value)
    return parsed if parsed is not None and parsed >= 0 else None


def _entry(resource: dict[str, Any], *, log_type: str) -> dict[str, Any]:
    hp = _as_dict(_as_dict(resource.get("Oem")).get("Hp"))
    source_record_id = resource.get("RecordId") or resource.get("Id")
    if source_record_id is None:
        raise Ilo4EventLogError("malformed_response")
    return {
        "log_type": log_type,
        "source_record_id": str(source_record_id)[:255],
        "severity": _severity(resource.get("Severity")),
        "message": str(resource.get("Message") or "")[:MAX_LOG_MESSAGE_LENGTH],
        "created_at": str(resource.get("Created") or ""),
        "updated_at": str(hp.get("Updated") or ""),
        "repeat_count": _non_negative_int(resource.get("Number")),
        "repaired": hp.get("Repaired") if isinstance(hp.get("Repaired"), bool) else None,
        "event_class": _optional_int(hp.get("Class")),
        "event_code": _optional_int(hp.get("Code")),
        "event_number": _optional_int(hp.get("EventNumber")),
        "record_format": str(resource.get("OemRecordFormat") or ""),
    }


def discover_ilo4_event_logs(
    get: Callable[[str], dict[str, Any]],
    *,
    system: dict[str, Any],
    manager: dict[str, Any],
) -> Ilo4EventLogSnapshot:
    """Read and normalize advertised iLO 4 IML and IEL resources."""
    entries: list[dict[str, Any]] = []
    for owner, log_type in (
        (system, "integrated_management_log"),
        (manager, "ilo_event_log"),
    ):
        services = _collection(
            get,
            owner,
            "LogServices",
            limit=MAX_LOG_SERVICES,
        )
        for service in services:
            entries.extend(
                _entry(resource, log_type=log_type)
                for resource in _collection(
                    get,
                    service,
                    "Entries",
                    limit=MAX_LOG_ENTRIES,
                )
            )
    return Ilo4EventLogSnapshot(entries)
