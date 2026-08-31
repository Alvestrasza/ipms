from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


MAX_CONTROLLERS = 32
MAX_CHILD_RESOURCES = 256
MIB = 1024**2


class SmartStorageAdapterError(Exception):
    pass


@dataclass(frozen=True)
class SmartStorageSnapshot:
    storage: list[dict[str, Any]]
    device_inventory: list[dict[str, Any]]
    health: str
    battery_health: str


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _link(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, dict):
        return ""
    path = value.get("@odata.id") or value.get("href")
    return path if isinstance(path, str) else ""


def _resource_link(document: dict[str, Any], key: str) -> str:
    return _link(document, key) or _link(
        _as_dict(document.get("Links") or document.get("links")),
        key,
    )


def _condition(value: Any) -> str:
    if isinstance(value, dict):
        status = value.get("Status")
        if isinstance(status, dict):
            value = status
        value = (
            value.get("HealthRollup")
            or value.get("HealthRollUp")
            or value.get("Health")
            or value.get("State")
        )
    normalized = str(value or "").casefold().replace("_", "").replace(" ", "")
    if normalized in {
        "ok",
        "enabled",
        "present",
        "presentandcharged",
        "redundant",
    }:
        return "ok"
    if normalized in {"warning", "degraded", "presentandcharging", "starting"}:
        return "warning"
    if normalized in {"critical", "failed", "failure", "disabled", "offline"}:
        return "critical"
    return "unknown"


def _combined_condition(values: list[str]) -> str:
    if "critical" in values:
        return "critical"
    if "warning" in values:
        return "warning"
    if "ok" in values:
        return "ok"
    return "unknown"


def _members(document: dict[str, Any], *, limit: int) -> list[str]:
    members = document.get("Members")
    if not isinstance(members, list):
        members = _as_dict(document.get("Links") or document.get("links")).get(
            "Member",
            [],
        )
    if not isinstance(members, list) or len(members) > limit:
        raise SmartStorageAdapterError("collection_limit_exceeded")
    paths = []
    for member in members:
        path = _link({"member": member}, "member")
        if not path:
            raise SmartStorageAdapterError("malformed_response")
        paths.append(path)
    return paths


def _collection(
    get: Callable[[str], dict[str, Any]],
    document: dict[str, Any],
    key: str,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    path = _resource_link(document, key)
    if not path:
        return []
    collection = get(path)
    return [get(member) for member in _members(collection, limit=limit)]


def _base_row(resource: dict[str, Any], *, device_type: str) -> dict[str, Any]:
    status = _as_dict(resource.get("Status"))
    return {
        "name": str(resource.get("Name") or resource.get("Id") or ""),
        "model": str(resource.get("Model") or resource.get("PartNumber") or ""),
        "manufacturer": str(resource.get("Manufacturer") or ""),
        "serial_number": str(resource.get("SerialNumber") or ""),
        "firmware_version": str(
            resource.get("FirmwareVersion")
            or resource.get("CurrentFirmwareVersion")
            or ""
        ),
        "status": _condition(status),
        "state": str(status.get("State") or ""),
        "device_type": device_type,
        "location": str(resource.get("Location") or ""),
        "location_format": str(resource.get("LocationFormat") or ""),
        "description": str(resource.get("Description") or ""),
        "source": "hpe_ilo4_smart_storage",
    }


def _capacity_bytes(resource: dict[str, Any]) -> int | None:
    capacity_mib = resource.get("CapacityMiB")
    if isinstance(capacity_mib, (int, float)) and capacity_mib >= 0:
        return round(capacity_mib * MIB)
    capacity_gb = resource.get("CapacityGB")
    if isinstance(capacity_gb, (int, float)) and capacity_gb >= 0:
        return round(capacity_gb * 1_000_000_000)
    return None


def _controller_row(resource: dict[str, Any]) -> dict[str, Any]:
    row = _base_row(resource, device_type="storage_controller")
    row.update(
        {
            "adapter_type": str(resource.get("AdapterType") or ""),
            "operating_mode": str(resource.get("CurrentOperatingMode") or ""),
            "logical_drive_count": resource.get("LogicalDriveCount"),
            "physical_drive_count": resource.get("PhysicalDriveCount"),
            "array_count": resource.get("ArrayCount"),
            "cache_memory_mib": resource.get("CacheMemorySizeMiB"),
            "internal_port_count": resource.get("InternalPortCount"),
            "external_port_count": resource.get("ExternalPortCount"),
            "hardware_revision": str(resource.get("HardwareRevision") or ""),
            "backup_power_source_status": str(
                resource.get("BackupPowerSourceStatus") or ""
            ),
            "encryption_enabled": resource.get("EncryptionEnabled"),
            "encryption_locked": resource.get("EncryptionFwLocked"),
            "encryption_mixed_volumes": resource.get(
                "EncryptionMixedVolumesEnabled"
            ),
        }
    )
    return row


def _logical_drive_row(resource: dict[str, Any]) -> dict[str, Any]:
    row = _base_row(resource, device_type="logical_drive")
    row.update(
        {
            "name": str(
                resource.get("LogicalDriveName")
                or resource.get("Name")
                or resource.get("Id")
                or ""
            ),
            "capacity_bytes": _capacity_bytes(resource),
            "raid": str(resource.get("Raid") or ""),
            "logical_drive_type": str(resource.get("LogicalDriveType") or ""),
            "drive_access_name": str(resource.get("DriveAccessName") or ""),
            "rebuild_percentage": resource.get("RebuildCompletionPercentage"),
            "block_size_bytes": resource.get("BlockSizeBytes"),
            "stripe_size_bytes": resource.get("StripeSizeBytes"),
            "logical_drive_number": resource.get("LogicalDriveNumber"),
            "logical_drive_encryption": resource.get("LogicalDriveEncryption"),
            "volume_unique_identifier": str(
                resource.get("VolumeUniqueIdentifier") or ""
            ),
        }
    )
    return row


def _physical_drive_row(resource: dict[str, Any]) -> dict[str, Any]:
    row = _base_row(resource, device_type="physical_drive")
    row.update(
        {
            "capacity_bytes": _capacity_bytes(resource),
            "media_type": str(resource.get("MediaType") or ""),
            "interface_type": str(resource.get("InterfaceType") or ""),
            "interface_speed_mbps": resource.get("InterfaceSpeedMbps"),
            "power_on_hours": resource.get("PowerOnHours"),
            "block_size_bytes": resource.get("BlockSizeBytes"),
            "rotational_speed_rpm": resource.get("RotationalSpeedRpm"),
            "temperature_celsius": resource.get("TemperatureCelsius"),
            "current_temperature_celsius": resource.get(
                "CurrentTemperatureCelsius"
            ),
            "maximum_temperature_celsius": resource.get(
                "MaximumTemperatureCelsius"
            ),
            "predicted_media_life_left_percent": resource.get(
                "PredictedMediaLifeLeftPercent"
            ),
            "uncorrected_read_errors": resource.get("UncorrectedReadErrors"),
            "uncorrected_write_errors": resource.get("UncorrectedWriteErrors"),
            "wwid": str(resource.get("WWID") or ""),
        }
    )
    return row


def discover_smart_storage(
    get: Callable[[str], dict[str, Any]],
    system: dict[str, Any],
) -> SmartStorageSnapshot:
    """Normalize the advertised legacy HPE SmartStorage graph without writes."""
    oem = _as_dict(system.get("Oem"))
    hpe = _as_dict(oem.get("Hpe") or oem.get("Hp"))
    smart_storage_path = _resource_link(
        system,
        "SmartStorage",
    ) or _resource_link(hpe, "SmartStorage")
    if not smart_storage_path:
        return SmartStorageSnapshot([], [], "unknown", "unknown")

    smart_storage = get(smart_storage_path)
    controllers = _collection(
        get,
        smart_storage,
        "ArrayControllers",
        limit=MAX_CONTROLLERS,
    )
    host_bus_adapters = _collection(
        get,
        smart_storage,
        "HostBusAdapters",
        limit=MAX_CONTROLLERS,
    )

    storage_rows: list[dict[str, Any]] = []
    device_rows: list[dict[str, Any]] = []
    battery_conditions: list[str] = []
    for controller in [*controllers, *host_bus_adapters]:
        controller_row = _controller_row(controller)
        storage_rows.append(controller_row)
        battery_conditions.append(
            _condition(controller.get("BackupPowerSourceStatus"))
        )
        storage_rows.extend(
            _logical_drive_row(resource)
            for resource in _collection(
                get,
                controller,
                "LogicalDrives",
                limit=MAX_CHILD_RESOURCES,
            )
        )
        physical_drives = _collection(
            get,
            controller,
            "DiskDrives",
            limit=MAX_CHILD_RESOURCES,
        )
        enclosure_rows = []
        for enclosure in _collection(
            get,
            controller,
            "StorageEnclosures",
            limit=MAX_CHILD_RESOURCES,
        ):
            enclosure_row = _base_row(enclosure, device_type="storage_enclosure")
            enclosure_row["drive_bay_count"] = enclosure.get("DriveBayCount")
            enclosure_row["wwid"] = str(enclosure.get("WWID") or "")
            enclosure_rows.append(enclosure_row)
            physical_drives.extend(
                _collection(
                    get,
                    enclosure,
                    "DiskDrives",
                    limit=MAX_CHILD_RESOURCES,
                )
            )
        seen_drives: set[tuple[str, str, str]] = set()
        for resource in physical_drives:
            identity = (
                str(resource.get("SerialNumber") or ""),
                str(resource.get("Location") or ""),
                str(resource.get("Name") or resource.get("Id") or ""),
            )
            if identity in seen_drives:
                continue
            seen_drives.add(identity)
            device_rows.append(_physical_drive_row(resource))
        device_rows.extend(enclosure_rows)

    health = _condition(smart_storage.get("Status"))
    if health == "unknown":
        health = _combined_condition(
            [row["status"] for row in [*storage_rows, *device_rows]]
        )
    return SmartStorageSnapshot(
        storage=storage_rows,
        device_inventory=device_rows,
        health=health,
        battery_health=_combined_condition(battery_conditions),
    )
