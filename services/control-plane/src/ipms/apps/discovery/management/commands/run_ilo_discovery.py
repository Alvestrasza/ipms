import json
import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.connectors.ilo_redfish import (
    RedfishConnectorError,
    RedfishTransport,
    discover_ilo,
)
from ipms.apps.discovery.models import ConnectorEndpoint, DiscoveryJob, PhysicalSystem


def _credentials(reference) -> tuple[str, str]:
    directory = os.environ.get("IPMS_CONNECTOR_SECRET_DIRECTORY", "").strip()
    if not directory:
        raise CommandError("Connector secret storage is not configured.")
    path = Path(directory) / f"{reference}.json"
    try:
        stat = path.stat()
        if stat.st_mode & 0o027:
            raise CommandError("The connector credential file permissions are unsafe.")
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CommandError("The connector credential could not be loaded.") from exc
    username = document.get("username", "")
    password = document.get("password", "")
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise CommandError("The connector credential is invalid.")
    return username, password


class Command(BaseCommand):
    help = "Run one tenant-attributed, read-only iLO Redfish discovery job."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--endpoint-id", required=True)
        parser.add_argument("--requested-by", required=True)

    def handle(self, *args, **options) -> None:
        try:
            endpoint = ConnectorEndpoint.objects.select_related("tenant").get(
                id=options["endpoint_id"],
                connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
                enabled=True,
            )
        except ConnectorEndpoint.DoesNotExist as exc:
            raise CommandError("The enabled iLO endpoint does not exist.") from exc

        job = DiscoveryJob.objects.create(
            tenant=endpoint.tenant,
            connector=endpoint,
            connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
            status=DiscoveryJob.Status.RUNNING,
            requested_by=options["requested_by"],
            started_at=timezone.now(),
        )
        endpoint.last_attempt_at = job.started_at
        endpoint.save(update_fields=("last_attempt_at", "updated_at"))

        try:
            username, password = _credentials(endpoint.credential_reference)
            observations, summary = discover_ilo(
                RedfishTransport(endpoint.base_url, endpoint.tls_certificate_sha256),
                username,
                password,
            )
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
                endpoint.last_success_at = completed_at
                endpoint.save(
                    update_fields=(
                        "health",
                        "last_error_code",
                        "last_success_at",
                        "updated_at",
                    )
                )
                AuditEvent.objects.create(
                    tenant=endpoint.tenant,
                    actor=options["requested_by"],
                    action="connector.discovery",
                    object_type="connector_endpoint",
                    object_id=str(endpoint.id),
                    outcome=AuditEvent.Outcome.SUCCEEDED,
                    correlation_id=job.correlation_id,
                    details={"connector_type": endpoint.connector_type, **summary},
                )
        except (CommandError, RedfishConnectorError) as exc:
            code = exc.code if isinstance(exc, RedfishConnectorError) else "credential_unavailable"
            completed_at = timezone.now()
            job.status = DiscoveryJob.Status.FAILED
            job.error_code = code
            job.completed_at = completed_at
            job.save(update_fields=("status", "error_code", "completed_at"))
            endpoint.health = ConnectorEndpoint.Health.CRITICAL
            endpoint.last_error_code = code
            endpoint.save(update_fields=("health", "last_error_code", "updated_at"))
            AuditEvent.objects.create(
                tenant=endpoint.tenant,
                actor=options["requested_by"],
                action="connector.discovery",
                object_type="connector_endpoint",
                object_id=str(endpoint.id),
                outcome=AuditEvent.Outcome.FAILED,
                correlation_id=job.correlation_id,
                details={"connector_type": endpoint.connector_type, "error_code": code},
            )
            raise CommandError(f"iLO discovery failed: {code}") from exc

        self.stdout.write(json.dumps({"job_id": str(job.id), **summary}, separators=(",", ":")))
