from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from .ilo4_legacy_inventory import (
    Ilo4LegacyInventoryError,
    discover_ilo4_legacy_inventory,
)
from .ilo4_smart_storage import SmartStorageAdapterError, discover_smart_storage


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COLLECTION_MEMBERS = 256
SAFE_REDFISH_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class RedfishConnectorError(Exception):
    def __init__(self, code: str, detail: dict[str, str | int] | None = None) -> None:
        self.code = code
        self.detail = detail or {}
        super().__init__(code)


def _safe_redfish_error_identifiers(content: bytes) -> dict[str, str]:
    """Extract bounded registry identifiers without retaining response content."""
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}
    if not isinstance(document, dict) or not isinstance(document.get("error"), dict):
        return {}

    error = document["error"]
    detail: dict[str, str] = {}
    error_code = error.get("code")
    if isinstance(error_code, str) and SAFE_REDFISH_IDENTIFIER.fullmatch(error_code):
        detail["redfish_error_code"] = error_code

    extended_info = error.get("@Message.ExtendedInfo")
    if not isinstance(extended_info, list):
        extended_info = error.get("ExtendedInfo")
    if isinstance(extended_info, list):
        for item in extended_info:
            if not isinstance(item, dict):
                continue
            message_id = item.get("MessageId", item.get("MessageID"))
            if isinstance(message_id, str) and SAFE_REDFISH_IDENTIFIER.fullmatch(
                message_id
            ):
                detail["redfish_message_id"] = message_id
                break
    return detail


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, certificate_sha256: str, **kwargs) -> None:
        self._certificate_sha256 = certificate_sha256.lower()
        super().__init__(*args, **kwargs)

    def connect(self) -> None:
        super().connect()
        if self.sock is None:
            raise RedfishConnectorError("connection_failed")
        actual = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
        if actual != self._certificate_sha256:
            self.close()
            raise RedfishConnectorError("certificate_pin_mismatch")


def _validated_endpoint(base_url: str) -> tuple[str, int]:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise RedfishConnectorError("invalid_endpoint")
    port = parsed.port or 443
    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise RedfishConnectorError("dns_failed") from exc
    if not addresses or any(
        not address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        for address in addresses
    ):
        raise RedfishConnectorError("endpoint_address_rejected")
    return parsed.hostname, port


class RedfishTransport:
    def __init__(
        self,
        base_url: str,
        certificate_sha256: str,
        *,
        timeout: float = 10,
        event_callback: Callable[[dict[str, str | int]], None] | None = None,
    ) -> None:
        if len(certificate_sha256) != 64:
            raise RedfishConnectorError("invalid_certificate_pin")
        try:
            int(certificate_sha256, 16)
        except ValueError as exc:
            raise RedfishConnectorError("invalid_certificate_pin") from exc
        self.host, self.port = _validated_endpoint(base_url)
        self.certificate_sha256 = certificate_sha256
        self.timeout = timeout
        self.event_callback = event_callback
        self.token = ""
        self.session_path = ""

    def _emit_exchange(
        self,
        *,
        method: str,
        path: str,
        severity: str,
        duration_ms: int,
        http_status: int | None = None,
        error_code: str = "",
        detail: dict[str, str | int] | None = None,
    ) -> None:
        if self.event_callback is None:
            return
        event: dict[str, str | int] = {
            "event_type": "redfish.exchange",
            "method": method,
            "resource_path": path,
            "severity": severity,
            "duration_ms": duration_ms,
        }
        if http_status is not None:
            event["http_status"] = http_status
        if error_code:
            event["error_code"] = error_code
        for key in ("redfish_error_code", "redfish_message_id"):
            value = (detail or {}).get(key)
            if isinstance(value, str):
                event[key] = value
        try:
            self.event_callback(event)
        except Exception:
            # Observability must never alter connector behavior.
            return

    def _connection(self) -> _PinnedHTTPSConnection:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return _PinnedHTTPSConnection(
            self.host,
            self.port,
            timeout=self.timeout,
            context=context,
            certificate_sha256=self.certificate_sha256,
        )

    def request_json(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, str] | None = None,
        include_odata_version: bool = True,
    ) -> tuple[dict[str, Any], dict[str, str], int]:
        normalized_method = method.upper()
        if not path.startswith("/redfish/v1/") or "://" in path:
            raise RedfishConnectorError("request_path_rejected")
        if normalized_method not in {"GET", "HEAD", "POST", "DELETE"}:
            raise RedfishConnectorError("request_method_rejected")
        if normalized_method == "POST" and not path.rstrip("/").endswith(
            "/SessionService/Sessions"
        ):
            raise RedfishConnectorError("request_method_rejected")
        if normalized_method == "DELETE" and path != self.session_path:
            raise RedfishConnectorError("request_method_rejected")

        headers = {"Accept": "application/json"}
        if include_odata_version:
            headers["OData-Version"] = "4.0"
        if self.token:
            headers["X-Auth-Token"] = self.token
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload, separators=(",", ":")).encode()

        connection = self._connection()
        started = time.monotonic()
        try:
            connection.request(normalized_method, path, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise RedfishConnectorError("redirect_rejected")
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise RedfishConnectorError("response_limit_exceeded")
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            registry_detail = _safe_redfish_error_identifiers(content)
            unauthorized_login = registry_detail.get(
                "redfish_message_id", ""
            ).endswith(".UnauthorizedLoginAttempt")
            if response.status in (401, 403) or unauthorized_login:
                detail = {
                    "method": normalized_method,
                    "path": path,
                    "http_status": response.status,
                }
                detail.update(registry_detail)
                raise RedfishConnectorError(
                    "authentication_failed",
                    detail,
                )
            if response.status >= 400:
                detail = {
                    "method": normalized_method,
                    "path": path,
                    "http_status": response.status,
                }
                detail.update(registry_detail)
                raise RedfishConnectorError(
                    "redfish_request_failed",
                    detail,
                )
            document = json.loads(content) if content else {}
            if not isinstance(document, dict):
                raise RedfishConnectorError("malformed_response")
            self._emit_exchange(
                method=normalized_method,
                path=path,
                severity=(
                    "info" if normalized_method in {"POST", "DELETE"} else "debug"
                ),
                duration_ms=round((time.monotonic() - started) * 1000),
                http_status=response.status,
            )
            return document, response_headers, response.status
        except RedfishConnectorError as exc:
            self._emit_exchange(
                method=normalized_method,
                path=path,
                severity=(
                    "warning"
                    if exc.code in {"redirect_rejected", "certificate_pin_mismatch"}
                    else "error"
                ),
                duration_ms=round((time.monotonic() - started) * 1000),
                http_status=(
                    exc.detail.get("http_status")
                    if isinstance(exc.detail.get("http_status"), int)
                    else None
                ),
                error_code=exc.code,
                detail=exc.detail,
            )
            raise
        except (TimeoutError, socket.timeout) as exc:
            self._emit_exchange(
                method=normalized_method,
                path=path,
                severity="error",
                duration_ms=round((time.monotonic() - started) * 1000),
                error_code="connection_timeout",
            )
            raise RedfishConnectorError("connection_timeout") from exc
        except (ssl.SSLError, OSError) as exc:
            self._emit_exchange(
                method=normalized_method,
                path=path,
                severity="error",
                duration_ms=round((time.monotonic() - started) * 1000),
                error_code="connection_failed",
            )
            raise RedfishConnectorError("connection_failed") from exc
        except json.JSONDecodeError as exc:
            self._emit_exchange(
                method=normalized_method,
                path=path,
                severity="error",
                duration_ms=round((time.monotonic() - started) * 1000),
                error_code="malformed_response",
            )
            raise RedfishConnectorError("malformed_response") from exc
        finally:
            connection.close()

    def get(self, path: str) -> dict[str, Any]:
        return self.request_json("GET", path)[0]

    def get_ilo4_legacy(self, path: str) -> dict[str, Any]:
        return self.request_json(
            "GET",
            path,
            include_odata_version=False,
        )[0]

    def create_session(self, path: str, username: str, password: str) -> None:
        _, headers, status = self.request_json(
            "POST",
            path,
            payload={"UserName": username, "Password": password},
        )
        token = headers.get("x-auth-token", "")
        location = headers.get("location", "")
        session_path = location
        if location.startswith("https://"):
            parsed_location = urlsplit(location)
            location_port = parsed_location.port or 443
            if (
                parsed_location.scheme == "https"
                and parsed_location.hostname
                and parsed_location.hostname.casefold() == self.host.casefold()
                and location_port == self.port
                and not parsed_location.username
                and not parsed_location.password
                and not parsed_location.query
                and not parsed_location.fragment
            ):
                session_path = parsed_location.path
        if status != 201 or not token or not session_path.startswith("/redfish/v1/"):
            raise RedfishConnectorError(
                "session_creation_failed",
                {
                    "method": "POST",
                    "path": path,
                    "http_status": status,
                    "token_state": "present" if token else "missing",
                    "location_state": (
                        "valid"
                        if session_path.startswith("/redfish/v1/")
                        else "missing_or_invalid"
                    ),
                },
            )
        self.token = token
        self.session_path = session_path

    def delete_session(self) -> None:
        if not self.session_path:
            return
        try:
            self.request_json("DELETE", self.session_path)
        finally:
            self.token = ""
            self.session_path = ""


@dataclass(frozen=True)
class PhysicalSystemObservation:
    source_resource_id: str
    name: str
    manufacturer: str
    model: str
    serial_number: str
    sku: str
    system_uuid: str
    power_state: str
    health: str
    state: str
    processor_count: int | None
    processor_model: str
    total_cores: int | None
    memory_bytes: int | None
    bios_version: str
    bmc_firmware_version: str
    detail_snapshot: dict[str, Any]


def _link(document: dict[str, Any], key: str) -> str:
    value = document.get(key, {})
    return value.get("@odata.id", "") if isinstance(value, dict) else ""


def _members(document: dict[str, Any]) -> list[str]:
    values = document.get("Members", [])
    if not isinstance(values, list) or len(values) > MAX_COLLECTION_MEMBERS:
        raise RedfishConnectorError("collection_limit_exceeded")
    members = [_link({"member": value}, "member") for value in values]
    if any(not member for member in members):
        raise RedfishConnectorError("malformed_response")
    return members


def _health(value: Any) -> str:
    normalized = str(value or "").lower()
    return normalized if normalized in {"ok", "warning", "critical"} else "unknown"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _link_values(document: dict[str, Any], key: str) -> list[str]:
    value = document.get(key)
    if isinstance(value, dict):
        path = value.get("@odata.id")
        return [path] if isinstance(path, str) and path else []
    if isinstance(value, list):
        paths = []
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("@odata.id"), str):
                paths.append(item["@odata.id"])
        return paths
    return []


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
    if normalized in {"ok", "enabled", "redundant", "fullyredundant", "standbyoffline"}:
        return "ok"
    if normalized in {"warning", "degraded", "nonredundant", "starting"}:
        return "warning"
    if normalized in {"critical", "failed", "failure", "disabled", "unavailableoffline"}:
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


def _safe_get(transport: RedfishTransport, path: str) -> dict[str, Any]:
    try:
        return transport.get(path)
    except RedfishConnectorError as exc:
        if exc.code == "redfish_request_failed" and exc.detail.get("http_status") in {
            404,
            405,
        }:
            return {}
        raise


def _linked_documents(
    transport: RedfishTransport,
    document: dict[str, Any],
    key: str,
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for path in _link_values(document, key):
        linked = _safe_get(transport, path)
        if not linked:
            continue
        if isinstance(linked.get("Members"), list):
            resources.extend(
                resource
                for member in _members(linked)
                if (resource := _safe_get(transport, member))
            )
        else:
            resources.append(linked)
    return resources


def _hpe_oem(document: dict[str, Any]) -> dict[str, Any]:
    oem = _as_dict(document.get("Oem"))
    return _as_dict(oem.get("Hpe") or oem.get("Hp"))


def _aggregate_lookup(aggregate: dict[str, Any], *names: str) -> Any:
    normalized = {
        re.sub(r"[^a-z0-9]", "", str(key).casefold()): value
        for key, value in aggregate.items()
    }
    for name in names:
        value = normalized.get(re.sub(r"[^a-z0-9]", "", name.casefold()))
        if value is not None:
            return value
    return None


def _status_value(condition: str, *, redundant: bool = False) -> str:
    if redundant and condition == "ok":
        return "redundant"
    return condition


def _inventory_row(resource: dict[str, Any]) -> dict[str, Any]:
    status = _condition(resource.get("Status"))
    return {
        "name": str(resource.get("Name") or resource.get("Id") or ""),
        "model": str(resource.get("Model") or resource.get("PartNumber") or ""),
        "manufacturer": str(resource.get("Manufacturer") or ""),
        "serial_number": str(resource.get("SerialNumber") or ""),
        "firmware_version": str(
            resource.get("FirmwareVersion") or resource.get("Version") or ""
        ),
        "status": status,
        "state": str(_as_dict(resource.get("Status")).get("State") or ""),
    }


def _build_detail_snapshot(
    transport: RedfishTransport,
    *,
    root: dict[str, Any],
    system: dict[str, Any],
    manager: dict[str, Any],
) -> dict[str, Any]:
    processors = _linked_documents(transport, system, "Processors")
    memory_modules = _linked_documents(transport, system, "Memory")
    network_interfaces = _linked_documents(transport, system, "EthernetInterfaces")
    storage_resources = _linked_documents(transport, system, "Storage")
    simple_storage = _linked_documents(transport, system, "SimpleStorage")

    system_links = _as_dict(system.get("Links"))
    chassis_documents = _linked_documents(transport, system_links, "Chassis")
    if not chassis_documents:
        chassis_documents = _linked_documents(transport, root, "Chassis")[:1]
    chassis = chassis_documents[0] if chassis_documents else {}
    thermal_documents = _linked_documents(transport, chassis, "Thermal")
    power_documents = _linked_documents(transport, chassis, "Power")
    thermal = thermal_documents[0] if thermal_documents else {}
    power = power_documents[0] if power_documents else {}

    fans = []
    for index, fan in enumerate(_as_list(thermal.get("Fans"))):
        if not isinstance(fan, dict):
            continue
        fans.append(
            {
                "name": str(fan.get("Name") or f"Fan {index + 1}"),
                "status": _condition(fan.get("Status")),
                "state": str(_as_dict(fan.get("Status")).get("State") or ""),
                "reading": fan.get("Reading"),
                "units": str(fan.get("ReadingUnits") or ""),
                "context": str(fan.get("PhysicalContext") or ""),
            }
        )

    temperatures = []
    for index, sensor in enumerate(_as_list(thermal.get("Temperatures"))):
        if not isinstance(sensor, dict):
            continue
        temperatures.append(
            {
                "name": str(sensor.get("Name") or f"Temperature {index + 1}"),
                "status": _condition(sensor.get("Status")),
                "reading_celsius": sensor.get("ReadingCelsius"),
                "upper_caution_celsius": sensor.get("UpperThresholdNonCritical"),
                "upper_critical_celsius": sensor.get("UpperThresholdCritical"),
                "context": str(sensor.get("PhysicalContext") or ""),
            }
        )

    power_supplies = []
    for supply in _as_list(power.get("PowerSupplies")):
        if not isinstance(supply, dict):
            continue
        row = _inventory_row(supply)
        row.update(
            {
                "capacity_watts": supply.get("PowerCapacityWatts"),
                "last_output_watts": supply.get("LastPowerOutputWatts"),
            }
        )
        power_supplies.append(row)
    power_control = next(
        (item for item in _as_list(power.get("PowerControl")) if isinstance(item, dict)),
        {},
    )

    processor_rows = []
    for processor in processors:
        row = _inventory_row(processor)
        row.update(
            {
                "socket": str(processor.get("Socket") or ""),
                "cores": processor.get("TotalCores"),
                "threads": processor.get("TotalThreads"),
                "speed_mhz": processor.get("MaxSpeedMHz") or processor.get("OperatingSpeedMHz"),
                "architecture": str(processor.get("ProcessorArchitecture") or ""),
            }
        )
        processor_rows.append(row)

    memory_rows = []
    for module in memory_modules:
        row = _inventory_row(module)
        row.update(
            {
                "location": str(module.get("DeviceLocator") or module.get("SocketLocator") or ""),
                "capacity_mib": module.get("CapacityMiB"),
                "speed_mhz": module.get("OperatingSpeedMhz")
                or module.get("OperatingSpeedMHz"),
                "memory_type": str(
                    module.get("MemoryDeviceType") or module.get("MemoryType") or ""
                ),
            }
        )
        memory_rows.append(row)

    network_rows = []
    for interface in network_interfaces:
        row = _inventory_row(interface)
        row.update(
            {
                "mac_address": str(
                    interface.get("MACAddress")
                    or interface.get("PermanentMACAddress")
                    or ""
                ),
                "speed_mbps": interface.get("SpeedMbps"),
                "link_status": str(interface.get("LinkStatus") or ""),
                "interface_enabled": interface.get("InterfaceEnabled"),
            }
        )
        network_rows.append(row)

    try:
        legacy_inventory = discover_ilo4_legacy_inventory(
            transport.get_ilo4_legacy,
            system,
        )
    except Ilo4LegacyInventoryError as exc:
        raise RedfishConnectorError(str(exc)) from exc
    if not memory_rows:
        memory_rows.extend(legacy_inventory.memory)
    network_rows.extend(legacy_inventory.network)

    storage_rows = []
    device_inventory = []
    for storage in storage_resources:
        row = _inventory_row(storage)
        controllers = _as_list(storage.get("StorageControllers"))
        if isinstance(controllers, list) and controllers:
            controller = next((item for item in controllers if isinstance(item, dict)), {})
            row.update(
                {
                    "name": str(controller.get("Name") or row["name"]),
                    "model": str(controller.get("Model") or row["model"]),
                    "firmware_version": str(
                        controller.get("FirmwareVersion") or row["firmware_version"]
                    ),
                    "status": (
                        controller_status
                        if (controller_status := _condition(controller.get("Status")))
                        != "unknown"
                        else row["status"]
                    ),
                }
            )
        storage_rows.append(row)
        for drive in _linked_documents(transport, storage, "Drives"):
            drive_row = _inventory_row(drive)
            drive_row["device_type"] = "drive"
            drive_row["capacity_bytes"] = drive.get("CapacityBytes")
            device_inventory.append(drive_row)
    for simple in simple_storage:
        storage_rows.append(_inventory_row(simple))
        for device in _as_list(simple.get("Devices")):
            if isinstance(device, dict):
                device_row = _inventory_row(device)
                device_row["device_type"] = "storage_device"
                device_inventory.append(device_row)

    try:
        smart_storage = discover_smart_storage(
            lambda path: _safe_get(transport, path),
            system,
        )
    except SmartStorageAdapterError as exc:
        raise RedfishConnectorError(str(exc)) from exc
    if not storage_rows:
        storage_rows.extend(smart_storage.storage)
    if not any(
        row.get("device_type") in {"drive", "storage_device", "physical_drive"}
        for row in device_inventory
    ):
        device_inventory.extend(smart_storage.device_inventory)

    for key in ("PCIeDevices", "PCIeFunctions"):
        for resource in _linked_documents(transport, system_links, key):
            row = _inventory_row(resource)
            row["device_type"] = key
            device_inventory.append(row)
    device_inventory.extend(legacy_inventory.device_inventory)

    firmware_rows: list[dict[str, Any]] = []
    software_rows: list[dict[str, Any]] = []
    update_services = _linked_documents(transport, root, "UpdateService")
    if update_services:
        update_service = update_services[0]
        firmware_rows = [
            _inventory_row(resource)
            for resource in _linked_documents(transport, update_service, "FirmwareInventory")
        ]
        software_rows = [
            _inventory_row(resource)
            for resource in _linked_documents(transport, update_service, "SoftwareInventory")
        ]
    if not firmware_rows:
        firmware_rows = [
            {
                "name": "System BIOS",
                "firmware_version": str(system.get("BiosVersion") or ""),
                "status": _condition(system.get("Status")),
            },
            {
                "name": str(manager.get("Name") or "BMC"),
                "firmware_version": str(manager.get("FirmwareVersion") or ""),
                "status": _condition(manager.get("Status")),
            },
        ]

    hpe_system = _hpe_oem(system)
    hpe_chassis = _hpe_oem(chassis)
    hpe_manager = _hpe_oem(manager)
    aggregate = _as_dict(
        hpe_system.get("AggregateHealthStatus")
        or hpe_chassis.get("AggregateHealthStatus")
        or hpe_manager.get("AggregateHealthStatus")
    )
    batteries = _as_list(hpe_chassis.get("SmartStorageBattery"))
    battery_conditions = [
        _condition(item.get("Status")) for item in batteries if isinstance(item, dict)
    ]
    if smart_storage.battery_health != "unknown":
        battery_conditions.append(smart_storage.battery_health)
    fan_conditions = [row["status"] for row in fans]
    temperature_conditions = [row["status"] for row in temperatures]
    power_supply_conditions = [row["status"] for row in power_supplies]
    processor_conditions = [row["status"] for row in processor_rows]
    memory_conditions = [row["status"] for row in memory_rows]
    network_conditions = [row["status"] for row in network_rows]
    storage_conditions = [row["status"] for row in storage_rows]

    def subsystem(
        key: str,
        raw: Any,
        fallback: str,
        *,
        redundant: bool = False,
    ) -> dict[str, str]:
        condition = _condition(raw) if raw is not None else fallback
        return {
            "key": key,
            "status": condition,
            "value": _status_value(condition, redundant=redundant),
        }

    thermal_redundancy = _as_list(thermal.get("Redundancy"))
    power_redundancy = _as_list(power.get("Redundancy"))
    subsystems = [
        subsystem(
            "agentless_management_service",
            _aggregate_lookup(aggregate, "AgentlessManagementService", "AgentlessManagement"),
            "unknown",
        ),
        subsystem(
            "smart_storage_battery_status",
            _aggregate_lookup(aggregate, "SmartStorageBattery", "SmartStorageBatteryStatus"),
            _combined_condition(battery_conditions),
        ),
        subsystem(
            "bios_hardware_health",
            _aggregate_lookup(aggregate, "BiosOrHardwareHealth", "BIOSHardwareHealth"),
            _condition(system.get("Status")),
        ),
        subsystem(
            "fan_redundancy",
            _aggregate_lookup(aggregate, "FanRedundancy"),
            _combined_condition(
                [
                    _condition(item.get("Status"))
                    for item in thermal_redundancy
                    if isinstance(item, dict)
                ]
            ),
            redundant=bool(thermal_redundancy),
        ),
        subsystem(
            "fans",
            _aggregate_lookup(aggregate, "Fans"),
            _combined_condition(fan_conditions),
        ),
        subsystem(
            "memory",
            _aggregate_lookup(aggregate, "Memory"),
            _combined_condition(memory_conditions) or _condition(system.get("MemorySummary")),
        ),
        subsystem(
            "network",
            _aggregate_lookup(aggregate, "Network"),
            _combined_condition(network_conditions),
        ),
        subsystem(
            "power_status",
            _aggregate_lookup(aggregate, "PowerStatus", "PowerRedundancy"),
            _combined_condition(
                [
                    _condition(item.get("Status"))
                    for item in power_redundancy
                    if isinstance(item, dict)
                ]
            ),
            redundant=bool(power_redundancy),
        ),
        subsystem(
            "power_supplies",
            _aggregate_lookup(aggregate, "PowerSupplies"),
            _combined_condition(power_supply_conditions),
        ),
        subsystem(
            "processors",
            _aggregate_lookup(aggregate, "Processors"),
            _combined_condition(processor_conditions),
        ),
        subsystem(
            "storage",
            _aggregate_lookup(aggregate, "Storage"),
            (
                smart_storage.health
                if smart_storage.health != "unknown"
                else _combined_condition(storage_conditions)
            ),
        ),
        subsystem(
            "temperatures",
            _aggregate_lookup(aggregate, "Temperatures"),
            _combined_condition(temperature_conditions),
        ),
    ]

    return {
        "schema_version": 1,
        "subsystems": subsystems,
        "fans": fans,
        "temperatures": temperatures,
        "power": {
            "consumed_watts": power_control.get("PowerConsumedWatts"),
            "capacity_watts": power_control.get("PowerCapacityWatts"),
            "supplies": power_supplies,
        },
        "processors": processor_rows,
        "memory": memory_rows,
        "network": network_rows,
        "device_inventory": device_inventory,
        "storage": storage_rows,
        "firmware": firmware_rows,
        "software": software_rows,
    }


def discover_ilo(
    transport: RedfishTransport,
    username: str,
    password: str,
) -> tuple[list[PhysicalSystemObservation], dict[str, str]]:
    root = transport.get("/redfish/v1/")
    if str(root.get("RedfishVersion", "")) < "1.0.0":
        raise RedfishConnectorError("unsupported_service")
    session_path = _link(root.get("Links", {}), "Sessions")
    if not session_path:
        session_service_path = _link(root, "SessionService")
        session_path = _link(transport.get(session_service_path), "Sessions")
    if not session_path:
        raise RedfishConnectorError("unsupported_service")

    transport.create_session(session_path, username, password)
    try:
        manager_firmware = ""
        manager: dict[str, Any] = {}
        managers_path = _link(root, "Managers")
        if managers_path:
            manager_members = _members(transport.get(managers_path))
            if manager_members:
                manager = transport.get(manager_members[0])
                firmware = manager.get("Firmware", {})
                current = firmware.get("Current", {}) if isinstance(firmware, dict) else {}
                manager_firmware = str(
                    manager.get("FirmwareVersion") or current.get("VersionString") or ""
                )

        systems_path = _link(root, "Systems")
        if not systems_path:
            raise RedfishConnectorError("unsupported_service")
        observations = []
        for system_path in _members(transport.get(systems_path)):
            system = transport.get(system_path)
            if not isinstance(system.get("@odata.id"), str):
                system = {**system, "@odata.id": system_path}
            status = system.get("Status", {})
            processors = system.get("ProcessorSummary", {})
            memory = system.get("MemorySummary", {})
            total_gib = memory.get("TotalSystemMemoryGiB")
            observations.append(
                PhysicalSystemObservation(
                    source_resource_id=system_path,
                    name=str(system.get("HostName") or system.get("Name") or "Unknown system"),
                    manufacturer=str(system.get("Manufacturer") or ""),
                    model=str(system.get("Model") or ""),
                    serial_number=str(system.get("SerialNumber") or ""),
                    sku=str(system.get("SKU") or ""),
                    system_uuid=str(system.get("UUID") or ""),
                    power_state=str(system.get("PowerState") or ""),
                    health=_health(status.get("HealthRollUp") or status.get("Health")),
                    state=str(status.get("State") or ""),
                    processor_count=processors.get("Count"),
                    processor_model=str(processors.get("Model") or ""),
                    total_cores=processors.get("CoreCount"),
                    memory_bytes=(
                        round(float(total_gib) * 1024**3)
                        if total_gib is not None
                        else None
                    ),
                    bios_version=str(system.get("BiosVersion") or ""),
                    bmc_firmware_version=manager_firmware,
                    detail_snapshot=_build_detail_snapshot(
                        transport,
                        root=root,
                        system=system,
                        manager=manager,
                    ),
                )
            )
        return observations, {
            "redfish_version": str(root.get("RedfishVersion", "")),
            "system_count": str(len(observations)),
        }
    finally:
        transport.delete_session()
