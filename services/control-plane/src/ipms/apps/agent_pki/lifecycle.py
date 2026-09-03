import hashlib
import re
import zipfile
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent

from .models import AgentEnrollment, AgentLifecycleJob


ACTIVE_STATUSES = (
    AgentLifecycleJob.Status.QUEUED,
    AgentLifecycleJob.Status.DELIVERED,
    AgentLifecycleJob.Status.RUNNING,
)
RESULT_STATUSES = {
    "running": AgentLifecycleJob.Status.RUNNING,
    "succeeded": AgentLifecycleJob.Status.SUCCEEDED,
    "failed": AgentLifecycleJob.Status.FAILED,
}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
RESULT_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")


def _verified_package_path() -> Path:
    path = Path(settings.AGENT_WINDOWS_PACKAGE_PATH)
    if not path.is_file():
        raise ValidationError("The Agent package is unavailable.")
    if not 1 <= path.stat().st_size <= 128 * 1024 * 1024:
        raise ValidationError("The Agent package size is invalid.")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != settings.AGENT_WINDOWS_PACKAGE_SHA256:
        raise ValidationError("The Agent package integrity check failed.")
    return path


def current_windows_agent_artifact() -> tuple[str, bytes, str]:
    path = _verified_package_path()
    try:
        with zipfile.ZipFile(path) as archive:
            matches = [item for item in archive.infolist() if item.filename == "ipms-agent.exe"]
            if len(matches) != 1 or not 1 <= matches[0].file_size <= 64 * 1024 * 1024:
                raise ValidationError("The Agent service binary entry is invalid.")
            binary = archive.read("ipms-agent.exe")
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise ValidationError("The Agent package does not contain the service binary.") from exc
    if not binary or len(binary) > 64 * 1024 * 1024:
        raise ValidationError("The Agent service binary size is invalid.")
    return settings.AGENT_WINDOWS_VERSION, binary, hashlib.sha256(binary).hexdigest()


def create_lifecycle_job(*, enrollment, action: str, actor: str) -> AgentLifecycleJob:
    if enrollment.status != AgentEnrollment.Status.ACTIVE:
        raise ValidationError("The Agent enrollment is not active.")
    if action not in AgentLifecycleJob.Action.values:
        raise ValidationError("The Agent lifecycle action is invalid.")
    if AgentLifecycleJob.objects.filter(
        enrollment=enrollment,
        status__in=ACTIVE_STATUSES,
    ).exists():
        raise ValidationError("An Agent lifecycle job is already active.")
    target_version = ""
    artifact_sha256 = ""
    if action == AgentLifecycleJob.Action.UPDATE:
        target_version, _, artifact_sha256 = current_windows_agent_artifact()
    return AgentLifecycleJob.objects.create(
        tenant=enrollment.tenant,
        enrollment=enrollment,
        action=action,
        target_version=target_version,
        artifact_sha256=artifact_sha256,
        requested_by=actor,
    )


@transaction.atomic
def offer_lifecycle_job(enrollment) -> dict | None:
    job = (
        AgentLifecycleJob.objects.select_for_update()
        .filter(
            enrollment=enrollment,
            status__in=(
                AgentLifecycleJob.Status.QUEUED,
                AgentLifecycleJob.Status.DELIVERED,
            ),
        )
        .order_by("created_at")
        .first()
    )
    if job is None:
        return None
    if job.status == AgentLifecycleJob.Status.QUEUED:
        job.status = AgentLifecycleJob.Status.DELIVERED
        job.delivered_at = timezone.now()
        job.save(update_fields=("status", "delivered_at"))
        AuditEvent.objects.create(
            tenant=enrollment.tenant,
            actor=enrollment.device_uri,
            action="agent.lifecycle.deliver",
            object_type="agent_lifecycle_job",
            object_id=str(job.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            details={"action": job.action, "target_version": job.target_version},
        )
    return {
        "job_id": str(job.id),
        "action": job.action,
        "target_version": job.target_version,
        "artifact_sha256": job.artifact_sha256,
    }


@transaction.atomic
def record_lifecycle_result(
    enrollment,
    *,
    job_id: str,
    result: str,
    result_code: str,
) -> AgentLifecycleJob:
    if result not in RESULT_STATUSES:
        raise ValidationError("The Agent lifecycle result is invalid.")
    job = AgentLifecycleJob.objects.select_for_update().filter(
        id=job_id,
        enrollment=enrollment,
        tenant=enrollment.tenant,
    ).first()
    if job is None or job.status not in ACTIVE_STATUSES:
        raise ValidationError("The Agent lifecycle job is unavailable.")
    if result == "running" and job.status not in (
        AgentLifecycleJob.Status.QUEUED,
        AgentLifecycleJob.Status.DELIVERED,
    ):
        raise ValidationError("The Agent lifecycle job transition is invalid.")
    if result in {"succeeded", "failed"} and job.status != AgentLifecycleJob.Status.RUNNING:
        raise ValidationError("The Agent lifecycle job transition is invalid.")
    if not RESULT_CODE_PATTERN.fullmatch(result_code):
        raise ValidationError("The Agent lifecycle result code is invalid.")
    job.status = RESULT_STATUSES[result]
    job.result_code = result_code
    update_fields = ["status", "result_code"]
    if result == "running":
        job.started_at = timezone.now()
        update_fields.append("started_at")
    else:
        job.completed_at = timezone.now()
        update_fields.append("completed_at")
    job.save(update_fields=update_fields)
    AuditEvent.objects.create(
        tenant=enrollment.tenant,
        actor=enrollment.device_uri,
        action=f"agent.lifecycle.{result}",
        object_type="agent_lifecycle_job",
        object_id=str(job.id),
        outcome=(
            AuditEvent.Outcome.FAILED
            if result == "failed"
            else AuditEvent.Outcome.SUCCEEDED
        ),
        details={"action": job.action, "result_code": result_code},
    )
    return job


def lifecycle_artifact(enrollment, *, job_id: str) -> tuple[bytes, str]:
    job = AgentLifecycleJob.objects.filter(
        id=job_id,
        enrollment=enrollment,
        tenant=enrollment.tenant,
        action=AgentLifecycleJob.Action.UPDATE,
        status__in=(
            AgentLifecycleJob.Status.DELIVERED,
            AgentLifecycleJob.Status.RUNNING,
        ),
    ).first()
    if job is None or not SHA256_PATTERN.fullmatch(job.artifact_sha256):
        raise ValidationError("The Agent lifecycle artifact is unavailable.")
    _, binary, digest = current_windows_agent_artifact()
    if digest != job.artifact_sha256:
        raise ValidationError("The Agent lifecycle artifact changed after assignment.")
    return binary, digest
