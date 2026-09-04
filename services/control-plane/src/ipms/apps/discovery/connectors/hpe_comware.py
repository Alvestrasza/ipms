import asyncio
from dataclasses import dataclass

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    usmAesCfb128Protocol,
    usmHMACSHAAuthProtocol,
)


class ComwareConnectorError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ComwareObservation:
    name: str
    model: str
    software_version: str
    uptime_seconds: int | None
    interfaces: list[dict]
    details: dict


async def _get(
    hostname: str,
    port: int,
    username: str,
    auth_key: str,
    privacy_key: str,
) -> ComwareObservation:
    engine = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(
            (hostname, port), timeout=5, retries=1
        )
        user = UsmUserData(
            username,
            auth_key,
            privacy_key,
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        error_indication, error_status, _, var_binds = await get_cmd(
            engine,
            user,
            target,
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.3.0")),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.5.0")),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.2.1.0")),
        )
        if error_indication or error_status:
            raise ComwareConnectorError("snmp_request_failed")
        values = [str(value) for _, value in var_binds]
        if len(values) != 4:
            raise ComwareConnectorError("snmp_response_invalid")
        description, uptime_ticks, name, interface_count = values
        model = "HPE Comware switch"
        for candidate in ("5130", "5900AF", "5900"):
            if candidate.casefold() in description.casefold():
                model = f"HPE {candidate}"
                break
        try:
            uptime_seconds = int(uptime_ticks) // 100
        except ValueError:
            uptime_seconds = None
        interface_rows: dict[int, dict] = {}
        columns = {
            "1.3.6.1.2.1.2.2.1.2": "name",
            "1.3.6.1.2.1.2.2.1.7": "admin_status",
            "1.3.6.1.2.1.2.2.1.8": "operational_status",
            "1.3.6.1.2.1.31.1.1.1.15": "speed_mbps",
            "1.3.6.1.2.1.31.1.1.1.18": "description",
        }
        for oid, field in columns.items():
            row_count = 0
            async for walk_error, walk_status, _, walk_binds in bulk_walk_cmd(
                engine,
                user,
                target,
                ContextData(),
                0,
                25,
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
                maxRows=256,
            ):
                if walk_error or walk_status:
                    raise ComwareConnectorError("snmp_request_failed")
                for object_name, object_value in walk_binds:
                    object_oid = str(object_name)
                    if not object_oid.startswith(f"{oid}."):
                        continue
                    try:
                        index = int(object_oid.rsplit(".", 1)[-1])
                    except ValueError:
                        continue
                    value = str(object_value)[:255]
                    if field in {"admin_status", "operational_status"}:
                        value = {"1": "up", "2": "down", "3": "testing"}.get(
                            value,
                            "unknown",
                        )
                    elif field == "speed_mbps":
                        value = int(value) if value.isdigit() else 0
                    interface_rows.setdefault(index, {"index": index})[field] = value
                    row_count += 1
                    if row_count >= 256:
                        break
                if row_count >= 256:
                    break
        interfaces = [
            {
                "index": index,
                "name": str(row.get("name", f"Interface {index}"))[:128],
                "description": str(row.get("description", ""))[:255],
                "admin_status": row.get("admin_status", "unknown"),
                "operational_status": row.get("operational_status", "unknown"),
                "speed_mbps": row.get("speed_mbps", 0),
            }
            for index, row in sorted(interface_rows.items())[:256]
        ]
        return ComwareObservation(
            name=name[:255] or model,
            model=model,
            software_version=description[:255],
            uptime_seconds=uptime_seconds,
            interfaces=interfaces,
            details={
                "interface_count": (
                    int(interface_count) if interface_count.isdigit() else None
                ),
                "snmp_version": "3",
                "security_level": "authPriv",
                "authentication_protocol": "SHA-1",
                "privacy_protocol": "AES-128",
            },
        )
    finally:
        engine.close_dispatcher()


def discover_comware(
    hostname: str,
    port: int,
    username: str,
    auth_key: str,
    privacy_key: str,
) -> ComwareObservation:
    try:
        return asyncio.run(_get(hostname, port, username, auth_key, privacy_key))
    except ComwareConnectorError:
        raise
    except (OSError, ValueError) as exc:
        raise ComwareConnectorError("snmp_connection_failed") from exc
