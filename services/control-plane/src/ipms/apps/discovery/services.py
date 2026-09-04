import ipaddress
import socket
from datetime import timezone as datetime_timezone
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from ipms.apps.audit.models import AuditEvent

from .connectors.ilo_redfish import RedfishConnectorError, RedfishTransport, discover_ilo
from .connectors.hpe_comware import ComwareConnectorError, discover_comware
from .connectors.loadbalancer_org import LoadbalancerConnectorError, discover_loadbalancer
from .connectors.pinned_https import PinnedHttpsClient
from .connectors.sophos_firewall import SophosConnectorError, discover_sophos
from .models import (
    BmcCommunicationLog,
    BmcEventLogEntry,
    ConnectorEndpoint,
    ConnectorSecret,
    DiscoveryJob,
    ManagedInfrastructureDevice,
    PhysicalSystem,
)
from .secrets import load_connector_secret_document


class ConnectorExecutionError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _source_datetime(value: str):
    parsed = parse_datetime(value) if value else None
    if parsed is not None and timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, datetime_timezone.utc)
    return parsed


def _communication_logger(endpoint: ConnectorEndpoint, correlation_id):
    def record(event: dict[str, str | int]) -> None:
        BmcCommunicationLog.objects.create(
            tenant=endpoint.tenant,
            connector=endpoint,
            bmc_name=endpoint.display_name,
            bmc_family=endpoint.bmc_family,
            severity=str(event.get("severity", BmcCommunicationLog.Severity.INFO)),
            event_type=str(event.get("event_type", "redfish.exchange")),
            method=str(event.get("method", "")),
            resource_path=str(event.get("resource_path", "")),
            http_status=(
                int(event["http_status"]) if "http_status" in event else None
            ),
            duration_ms=(
                int(event["duration_ms"]) if "duration_ms" in event else None
            ),
            error_code=str(event.get("error_code", "")),
            redfish_error_code=str(event.get("redfish_error_code", "")),
            redfish_message_id=str(event.get("redfish_message_id", "")),
            correlation_id=correlation_id,
        )

    return record


def _validate_private_target(base_url: str) -> tuple[str, ...]:
    hostname = urlsplit(base_url).hostname
    if not hostname:
        raise ConnectorExecutionError("target_invalid")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    except socket.gaierror as exc:
        raise ConnectorExecutionError("target_unresolved") from exc
    if not addresses:
        raise ConnectorExecutionError("target_unresolved")
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        if not parsed.is_private or any(
            (
                parsed.is_loopback,
                parsed.is_link_local,
                parsed.is_multicast,
                parsed.is_reserved,
                parsed.is_unspecified,
            )
        ):
            raise ConnectorExecutionError("target_not_private")
    return tuple(sorted(addresses))


def _finish_failed(
    job: DiscoveryJob,
    endpoint: ConnectorEndpoint,
    code: str,
    detail: dict[str, str | int] | None = None,
) -> None:
    completed_at = timezone.now()
    safe_detail = detail or {}
    job.status = DiscoveryJob.Status.FAILED
    job.error_code = code
    job.error_detail = safe_detail
    job.completed_at = completed_at
    job.save(update_fields=("status", "error_code", "error_detail", "completed_at"))
    endpoint.health = ConnectorEndpoint.Health.CRITICAL
    endpoint.last_error_code = code
    endpoint.last_error_detail = safe_detail
    endpoint.save(
        update_fields=(
            "health",
            "last_error_code",
            "last_error_detail",
            "updated_at",
        )
    )
    AuditEvent.objects.create(
        tenant=endpoint.tenant,
        actor=job.requested_by,
        action="connector.discovery",
        object_type="connector_endpoint",
        object_id=str(endpoint.id),
        outcome=AuditEvent.Outcome.FAILED,
        correlation_id=job.correlation_id,
        details={"connector_type": endpoint.connector_type, "error_code": code},
    )


def process_discovery_job(job: DiscoveryJob) -> None:
    endpoint = job.connector
    if endpoint is None or not endpoint.enabled:
        job.status = DiscoveryJob.Status.FAILED
        job.error_code = "connector_unavailable"
        job.completed_at = timezone.now()
        job.save(update_fields=("status", "error_code", "completed_at"))
        return

    job.status = DiscoveryJob.Status.RUNNING
    job.started_at = timezone.now()
    job.save(update_fields=("status", "started_at"))
    endpoint.last_attempt_at = job.started_at
    endpoint.save(update_fields=("last_attempt_at", "updated_at"))

    try:
        validated_addresses = _validate_private_target(endpoint.base_url)
        secret_document = load_connector_secret_document(
            tenant_id=endpoint.tenant_id,
            secret_id=endpoint.credential_reference,
        )
        username = secret_document["username"]
        password = secret_document["password"]
        device_observation = None
        if endpoint.connector_type == ConnectorEndpoint.ConnectorType.ILO_REDFISH:
            observations, summary = discover_ilo(
                RedfishTransport(
                    endpoint.base_url,
                    endpoint.tls_certificate_sha256,
                    timeout=settings.BMC_CONNECT_TIMEOUT_SECONDS,
                    event_callback=_communication_logger(endpoint, job.correlation_id),
                ),
                username,
                password,
            )
        elif endpoint.connector_type == ConnectorEndpoint.ConnectorType.SOPHOS_FIREWALL:
            device_observation = discover_sophos(
                PinnedHttpsClient(
                    endpoint.base_url,
                    endpoint.tls_certificate_sha256,
                    timeout=settings.BMC_CONNECT_TIMEOUT_SECONDS,
                ),
                username,
                password,
            )
            observations, summary = [], {
                "device_count": "1",
                "interface_count": str(len(device_observation.interfaces)),
            }
        elif endpoint.connector_type == ConnectorEndpoint.ConnectorType.LOADBALANCER_ORG:
            extra = secret_document.get("extra", {})
            if not isinstance(extra, dict):
                raise ValueError("invalid connector secret")
            device_observation = discover_loadbalancer(
                PinnedHttpsClient(
                    endpoint.base_url,
                    endpoint.tls_certificate_sha256,
                    timeout=settings.BMC_CONNECT_TIMEOUT_SECONDS,
                ),
                username,
                password,
                str(extra.get("api_key", "")),
            )
            observations, summary = [], {
                "device_count": "1",
                "interface_count": str(len(device_observation.interfaces)),
            }
        elif endpoint.connector_type == ConnectorEndpoint.ConnectorType.HPE_COMWARE:
            target = urlsplit(endpoint.base_url)
            extra = secret_document.get("extra", {})
            if not isinstance(extra, dict):
                raise ValueError("invalid connector secret")
            device_observation = discover_comware(
                validated_addresses[0],
                target.port or 161,
                username,
                password,
                str(extra.get("privacy_key", "")),
            )
            observations, summary = [], {
                "device_count": "1",
                "interface_count": str(
                    device_observation.details.get("interface_count") or 0
                ),
            }
        else:
            raise ConnectorExecutionError("connector_type_unsupported")
    except ConnectorExecutionError as exc:
        _finish_failed(job, endpoint, exc.code)
        return
    except ConnectorSecret.DoesNotExist:
        _finish_failed(job, endpoint, "credential_unavailable")
        return
    except (InvalidTag, ValueError, KeyError):
        _finish_failed(job, endpoint, "credential_invalid")
        return
    except RedfishConnectorError as exc:
        _finish_failed(job, endpoint, exc.code, exc.detail)
        return
    except (SophosConnectorError, LoadbalancerConnectorError, ComwareConnectorError) as exc:
        _finish_failed(job, endpoint, exc.code)
        return

    completed_at = timezone.now()
    with transaction.atomic():
        event_log_count = 0
        for observation in observations:
            PhysicalSystem.objects.update_or_create(
                connector=endpoint,
                source_resource_id=observation.source_resource_id,
                defaults={
                    "tenant": endpoint.tenant,
                    "name": observation.name,
                    "manufacturer": observation.manufacturer,
                    "model": observation.model,
                    "serial_number": observation.serial_number,
                    "sku": observation.sku,
                    "system_uuid": observation.system_uuid,
                    "power_state": observation.power_state,
                    "health": observation.health,
                    "state": observation.state,
                    "processor_count": observation.processor_count,
                    "processor_model": observation.processor_model,
                    "total_cores": observation.total_cores,
                    "memory_bytes": observation.memory_bytes,
                    "bios_version": observation.bios_version,
                    "bmc_firmware_version": observation.bmc_firmware_version,
                    "detail_snapshot": observation.detail_snapshot,
                    "discovered_at": completed_at,
                },
            )
            for entry in observation.event_logs:
                BmcEventLogEntry.objects.update_or_create(
                    connector=endpoint,
                    log_type=entry["log_type"],
                    source_record_id=entry["source_record_id"],
                    defaults={
                        "tenant": endpoint.tenant,
                        "bmc_name": endpoint.display_name,
                        "severity": entry["severity"],
                        "message": entry["message"],
                        "source_created_at": _source_datetime(entry["created_at"]),
                        "source_updated_at": _source_datetime(entry["updated_at"]),
                        "repeat_count": entry["repeat_count"],
                        "repaired": entry["repaired"],
                        "event_class": entry["event_class"],
                        "event_code": entry["event_code"],
                        "event_number": entry["event_number"],
                        "record_format": entry["record_format"],
                        "last_discovered_at": completed_at,
                    },
                )
                event_log_count += 1
        if device_observation is not None:
            if endpoint.connector_type == ConnectorEndpoint.ConnectorType.SOPHOS_FIREWALL:
                category, vendor, product = ManagedInfrastructureDevice.Category.FIREWALL, "Sophos", "Sophos Firewall"
            elif endpoint.connector_type == ConnectorEndpoint.ConnectorType.LOADBALANCER_ORG:
                category, vendor, product = ManagedInfrastructureDevice.Category.LOAD_BALANCER, "Loadbalancer.org", "Enterprise ADC"
            else:
                category, vendor, product = ManagedInfrastructureDevice.Category.SWITCH, "HPE", "Comware 7 switch"
            ManagedInfrastructureDevice.objects.update_or_create(
                tenant=endpoint.tenant,
                connector=endpoint,
                defaults={
                    "category": category,
                    "name": device_observation.name or endpoint.display_name,
                    "vendor": vendor,
                    "product": product,
                    "model": getattr(device_observation, "model", ""),
                    "software_version": device_observation.software_version,
                    "serial_number": getattr(device_observation, "serial_number", ""),
                    "uptime_seconds": getattr(device_observation, "uptime_seconds", None),
                    "health": ManagedInfrastructureDevice.Health.HEALTHY,
                    "interfaces": getattr(device_observation, "interfaces", []),
                    "details": device_observation.details,
                    "discovered_at": completed_at,
                },
            )
        summary = {**summary, "event_log_count": str(event_log_count)}
        job.status = DiscoveryJob.Status.SUCCEEDED
        job.result_summary = summary
        job.completed_at = completed_at
        job.save(update_fields=("status", "result_summary", "completed_at"))
        endpoint.health = ConnectorEndpoint.Health.HEALTHY
        endpoint.last_error_code = ""
        endpoint.last_error_detail = {}
        endpoint.last_success_at = completed_at
        endpoint.save(
            update_fields=(
                "health",
                "last_error_code",
                "last_error_detail",
                "last_success_at",
                "updated_at",
            )
        )
        AuditEvent.objects.create(
            tenant=endpoint.tenant,
            actor=job.requested_by,
            action="connector.discovery",
            object_type="connector_endpoint",
            object_id=str(endpoint.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            correlation_id=job.correlation_id,
            details={"connector_type": endpoint.connector_type, **summary},
        )


def process_discovery_queue(*, limit: int = 5) -> int:
    processed = 0
    for _ in range(limit):
        with transaction.atomic():
            job = (
                DiscoveryJob.objects.select_for_update(skip_locked=True, of=("self",))
                .select_related("connector", "connector__tenant")
                .filter(
                    status=DiscoveryJob.Status.QUEUED,
                    connector_type__in=(
                        DiscoveryJob.ConnectorType.ILO_REDFISH,
                        DiscoveryJob.ConnectorType.SOPHOS_FIREWALL,
                        DiscoveryJob.ConnectorType.LOADBALANCER_ORG,
                        DiscoveryJob.ConnectorType.HPE_COMWARE,
                    ),
                )
                .order_by("created_at")
                .first()
            )
            if job is None:
                break
            job.status = DiscoveryJob.Status.RUNNING
            job.started_at = timezone.now()
            job.save(update_fields=("status", "started_at"))
        process_discovery_job(job)
        processed += 1
    return processed
