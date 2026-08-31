from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


MAX_LEGACY_RESOURCES = 256


class Ilo4LegacyInventoryError(Exception):
    pass


@dataclass(frozen=True)
class Ilo4LegacyInventorySnapshot:
    memory: list[dict[str, Any]]
    network: list[dict[str, Any]]
    device_inventory: list[dict[str, Any]]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _path(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    path = value.get("@odata.id") or value.get("href")
    return path if isinstance(path, str) else ""


def _links(document: dict[str, Any]) -> dict[str, Any]:
    return _as_dict(document.get("Links") or document.get("links"))


def _resource_link(document: dict[str, Any], key: str) -> str:
    return _path(document.get(key)) or _path(_links(document).get(key))


def _members(document: dict[str, Any]) -> list[str]:
    members = document.get("Members")
    if not isinstance(members, list):
        members = _links(document).get("Member", [])
    if not isinstance(members, list) or len(members) > MAX_LEGACY_RESOURCES:
        raise Ilo4LegacyInventoryError("collection_limit_exceeded")
    paths = [_path(member) for member in members]
    if any(not path for path in paths):
        raise Ilo4LegacyInventoryError("malformed_response")
    return paths


def _collection(
    get: Callable[[str], dict[str, Any]],
    document: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    path = _resource_link(document, key)
    if not path:
        return []
    collection = get(path)
    return [get(member) for member in _members(collection)]


def _dimm_condition(value: Any) -> str:
    normalized = str(value or "").casefold().replace("_", "").replace(" ", "")
    if normalized in {"goodinuse", "presentspare", "goodpartiallyinuse"}:
        return "ok"
    if normalized in {
        "presentunused",
        "addedbutunused",
        "upgradedbutunused",
        "degraded",
    }:
        return "warning"
    if normalized in {"expectedbutmissing", "doesnotmatch", "configurationerror"}:
        return "critical"
    return "unknown"


def _memory_row(resource: dict[str, Any]) -> dict[str, Any]:
    state = str(resource.get("DIMMStatus") or "")
    memory_types = [
        str(value)
        for value in (resource.get("DIMMType"), resource.get("DIMMTechnology"))
        if value
    ]
    return {
        "name": str(resource.get("Name") or resource.get("Id") or ""),
        "model": str(resource.get("PartNumber") or ""),
        "manufacturer": str(resource.get("Manufacturer") or ""),
        "serial_number": str(resource.get("SerialNumber") or ""),
        "firmware_version": "",
        "status": _dimm_condition(state),
        "state": state,
        "location": str(resource.get("SocketLocator") or ""),
        "capacity_mib": resource.get("SizeMB"),
        "speed_mhz": resource.get("MaximumFrequencyMHz"),
        "memory_type": " / ".join(memory_types),
        "rank": resource.get("Rank"),
        "error_correction": str(resource.get("ErrorCorrection") or ""),
        "source": "hpe_ilo4_legacy_inventory",
    }


def _firmware_version(resource: dict[str, Any]) -> str:
    firmware = _as_dict(resource.get("Firmware"))
    current = _as_dict(firmware.get("Current"))
    return str(current.get("VersionString") or "")


def _is_fibre_channel(resource: dict[str, Any]) -> bool:
    def numeric(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                return None
        return None

    # PCI class 0x0c (serial bus), subclass 0x04 is Fibre Channel.
    if numeric(resource.get("ClassCode")) == 12 and numeric(
        resource.get("SubclassCode")
    ) == 4:
        return True
    description = " ".join(
        str(resource.get(key) or "")
        for key in ("Name", "DeviceType", "StructuredName")
    ).casefold()
    return any(
        marker in description
        for marker in ("fibre channel", "fiber channel", "fc hba", "fibrechannel")
    )


def _pci_row(resource: dict[str, Any]) -> dict[str, Any]:
    is_fibre_channel = _is_fibre_channel(resource)
    return {
        "name": str(resource.get("Name") or resource.get("Id") or ""),
        "model": str(resource.get("DeviceType") or ""),
        "manufacturer": "",
        "serial_number": "",
        "firmware_version": _firmware_version(resource),
        "status": "unknown",
        "state": "",
        "device_type": (
            "fibre_channel_adapter" if is_fibre_channel else "pcie_device"
        ),
        "location": str(resource.get("DeviceLocation") or ""),
        "structured_name": str(resource.get("StructuredName") or ""),
        "vendor_id": resource.get("VendorID"),
        "device_id": resource.get("DeviceID"),
        "wwpn": "",
        "wwnn": "",
        "wwn_source": "unavailable_in_ilo4_redfish" if is_fibre_channel else "",
        "source": "hpe_ilo4_legacy_inventory",
    }


def discover_ilo4_legacy_inventory(
    get: Callable[[str], dict[str, Any]],
    system: dict[str, Any],
) -> Ilo4LegacyInventorySnapshot:
    """Normalize advertised iLO 4 pre-Redfish inventory without writes."""
    hp = _as_dict(_as_dict(system.get("Oem")).get("Hp"))
    hp_links = _links(hp)
    if not any(key in hp_links for key in ("Memory", "PCIDevices")):
        return Ilo4LegacyInventorySnapshot([], [], [])

    system_path = _path(system)
    if not system_path:
        raise Ilo4LegacyInventoryError("malformed_response")
    legacy_system = get(system_path)
    legacy_hp = _as_dict(_as_dict(legacy_system.get("Oem")).get("Hp"))

    memory = [
        _memory_row(resource)
        for resource in _collection(get, legacy_hp, "Memory")
    ]
    pci_devices = [
        _pci_row(resource)
        for resource in _collection(get, legacy_hp, "PCIDevices")
    ]
    network = [
        {
            **resource,
            "mac_address": "",
            "speed_mbps": None,
            "link_status": "",
            "interface_enabled": None,
        }
        for resource in pci_devices
        if resource["device_type"] == "fibre_channel_adapter"
    ]
    return Ilo4LegacyInventorySnapshot(memory, network, pci_devices)
