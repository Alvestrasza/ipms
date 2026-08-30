import ipaddress
import socket
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent

from .connectors.ilo_redfish import RedfishConnectorError, RedfishTransport, discover_ilo
from .models import ConnectorEndpoint, ConnectorSecret, DiscoveryJob, PhysicalSystem
from .secrets import load_connector_secret


class ConnectorExecutionError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _validate_private_target(base_url: str) -> None:
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
        _validate_private_target(endpoint.base_url)
        username, password = load_connector_secret(
            tenant_id=endpoint.tenant_id,
            secret_id=endpoint.credential_reference,
        )
        observations, summary = discover_ilo(
            RedfishTransport(endpoint.base_url, endpoint.tls_certificate_sha256),
            username,
            password,
        )
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

    completed_at = timezone.now()
    with transaction.atomic():
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
                    "discovered_at": completed_at,
                },
            )
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
                    connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
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
