from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COLLECTION_MEMBERS = 256


class RedfishConnectorError(Exception):
    def __init__(self, code: str, detail: dict[str, str | int] | None = None) -> None:
        self.code = code
        self.detail = detail or {}
        super().__init__(code)


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
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
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
        self.token = ""
        self.session_path = ""

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

        headers = {"Accept": "application/json", "OData-Version": "4.0"}
        if self.token:
            headers["X-Auth-Token"] = self.token
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload, separators=(",", ":")).encode()

        connection = self._connection()
        try:
            connection.request(normalized_method, path, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise RedfishConnectorError("redirect_rejected")
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise RedfishConnectorError("response_limit_exceeded")
            response_headers = {key.lower(): value for key, value in response.getheaders()}
            if response.status in (401, 403):
                raise RedfishConnectorError("authentication_failed")
            if response.status >= 400:
                raise RedfishConnectorError(
                    "redfish_request_failed",
                    {
                        "method": normalized_method,
                        "path": path,
                        "http_status": response.status,
                    },
                )
            document = json.loads(content) if content else {}
            if not isinstance(document, dict):
                raise RedfishConnectorError("malformed_response")
            return document, response_headers, response.status
        except (TimeoutError, socket.timeout) as exc:
            raise RedfishConnectorError("connection_timeout") from exc
        except (ssl.SSLError, OSError) as exc:
            raise RedfishConnectorError("connection_failed") from exc
        except json.JSONDecodeError as exc:
            raise RedfishConnectorError("malformed_response") from exc
        finally:
            connection.close()

    def get(self, path: str) -> dict[str, Any]:
        return self.request_json("GET", path)[0]

    def create_session(self, path: str, username: str, password: str) -> None:
        _, headers, status = self.request_json(
            "POST",
            path,
            payload={"UserName": username, "Password": password},
        )
        token = headers.get("x-auth-token", "")
        location = headers.get("location", "")
        if status != 201 or not token or not location.startswith("/redfish/v1/"):
            raise RedfishConnectorError("session_creation_failed")
        self.token = token
        self.session_path = location

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
                    memory_bytes=(round(float(total_gib) * 1024**3) if total_gib is not None else None),
                    bios_version=str(system.get("BiosVersion") or ""),
                    bmc_firmware_version=manager_firmware,
                )
            )
        return observations, {
            "redfish_version": str(root.get("RedfishVersion", "")),
            "system_count": str(len(observations)),
        }
    finally:
        transport.delete_session()
