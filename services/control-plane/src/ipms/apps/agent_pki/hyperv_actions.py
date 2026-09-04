import re

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import HyperVVirtualMachine, HyperVVirtualMachineActionJob

from .models import AgentEnrollment


ACTIVE_STATUSES = (
    HyperVVirtualMachineActionJob.Status.QUEUED,
    HyperVVirtualMachineActionJob.Status.DELIVERED,
    HyperVVirtualMachineActionJob.Status.RUNNING,
)
RESULT_STATUSES = {
    "running": HyperVVirtualMachineActionJob.Status.RUNNING,
    "succeeded": HyperVVirtualMachineActionJob.Status.SUCCEEDED,
    "failed": HyperVVirtualMachineActionJob.Status.FAILED,
}
ALLOWED_STATES = {
    HyperVVirtualMachineActionJob.Action.START: {HyperVVirtualMachine.State.STOPPED},
    HyperVVirtualMachineActionJob.Action.SHUTDOWN: {HyperVVirtualMachine.State.RUNNING},
    HyperVVirtualMachineActionJob.Action.STOP: {
        HyperVVirtualMachine.State.RUNNING,
        HyperVVirtualMachine.State.PAUSED,
    },
    HyperVVirtualMachineActionJob.Action.PAUSE: {HyperVVirtualMachine.State.RUNNING},
    HyperVVirtualMachineActionJob.Action.RESUME: {HyperVVirtualMachine.State.PAUSED},
}
EXPECTED_STATES = {
    HyperVVirtualMachineActionJob.Action.START: HyperVVirtualMachine.State.RUNNING,
    HyperVVirtualMachineActionJob.Action.SHUTDOWN: HyperVVirtualMachine.State.STOPPED,
    HyperVVirtualMachineActionJob.Action.STOP: HyperVVirtualMachine.State.STOPPED,
    HyperVVirtualMachineActionJob.Action.PAUSE: HyperVVirtualMachine.State.PAUSED,
    HyperVVirtualMachineActionJob.Action.RESUME: HyperVVirtualMachine.State.RUNNING,
}
RESULT_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")
FIRST_CAPABLE_AGENT_VERSION = (0, 2, 3)


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


@transaction.atomic
def create_hyperv_action_job(*, virtual_machine, action: str, actor: str):
    virtual_machine = HyperVVirtualMachine.objects.select_for_update().select_related("host").get(
        id=virtual_machine.id,
        tenant=virtual_machine.tenant,
    )
    if action not in HyperVVirtualMachineActionJob.Action.values:
        raise ValidationError("The Hyper-V virtual machine action is invalid.")
    if virtual_machine.state not in ALLOWED_STATES[action]:
        raise ValidationError("The Hyper-V virtual machine state does not allow this action.")
    agent_version = _version_tuple(virtual_machine.host.agent_version)
    if agent_version is None or agent_version < FIRST_CAPABLE_AGENT_VERSION:
        raise ValidationError("The Hyper-V host Agent must be updated before it can run VM actions.")
    enrollment = AgentEnrollment.objects.filter(
        tenant=virtual_machine.tenant,
        device_uri=virtual_machine.host.source_id,
        platform=AgentEnrollment.Platform.WINDOWS,
        status=AgentEnrollment.Status.ACTIVE,
    ).first()
    if enrollment is None:
        raise ValidationError("The Hyper-V host Agent is unavailable.")
    if HyperVVirtualMachineActionJob.objects.filter(
        enrollment=enrollment,
        vm_source_id=virtual_machine.source_id,
        status__in=ACTIVE_STATUSES,
    ).exists():
        raise ValidationError("A Hyper-V virtual machine action is already active.")
    job = HyperVVirtualMachineActionJob.objects.create(
        tenant=virtual_machine.tenant,
        enrollment=enrollment,
        virtual_machine=virtual_machine,
        vm_source_id=virtual_machine.source_id,
        vm_name=virtual_machine.name,
        action=action,
        requested_by=actor,
    )
    AuditEvent.objects.create(
        tenant=virtual_machine.tenant,
        actor=actor,
        action="hyperv.virtual_machine.action.queue",
        object_type="hyperv_virtual_machine_action_job",
        object_id=str(job.id),
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"action": action, "virtual_machine_id": str(virtual_machine.id)},
    )
    return job


@transaction.atomic
def offer_hyperv_action_job(enrollment) -> dict | None:
    job = (
        HyperVVirtualMachineActionJob.objects.select_for_update()
        .filter(
            enrollment=enrollment,
            status__in=(
                HyperVVirtualMachineActionJob.Status.QUEUED,
                HyperVVirtualMachineActionJob.Status.DELIVERED,
            ),
        )
        .order_by("created_at")
        .first()
    )
    if job is None:
        return None
    if job.status == HyperVVirtualMachineActionJob.Status.QUEUED:
        job.status = HyperVVirtualMachineActionJob.Status.DELIVERED
        job.delivered_at = timezone.now()
        job.save(update_fields=("status", "delivered_at"))
        AuditEvent.objects.create(
            tenant=enrollment.tenant,
            actor=enrollment.device_uri,
            action="hyperv.virtual_machine.action.deliver",
            object_type="hyperv_virtual_machine_action_job",
            object_id=str(job.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            details={"action": job.action},
        )
    return {
        "job_id": str(job.id),
        "action": job.action,
        "vm_source_id": job.vm_source_id,
        "expected_state": EXPECTED_STATES[job.action],
    }


@transaction.atomic
def record_hyperv_action_result(enrollment, *, job_id: str, result: str, result_code: str):
    if result not in RESULT_STATUSES or not RESULT_CODE_PATTERN.fullmatch(result_code):
        raise ValidationError("The Hyper-V virtual machine action result is invalid.")
    job = HyperVVirtualMachineActionJob.objects.select_for_update().filter(
        id=job_id,
        enrollment=enrollment,
        tenant=enrollment.tenant,
    ).first()
    if job is None or job.status not in ACTIVE_STATUSES:
        raise ValidationError("The Hyper-V virtual machine action is unavailable.")
    if result == "running" and job.status not in (
        HyperVVirtualMachineActionJob.Status.QUEUED,
        HyperVVirtualMachineActionJob.Status.DELIVERED,
    ):
        raise ValidationError("The Hyper-V virtual machine action transition is invalid.")
    if result in {"succeeded", "failed"} and job.status != HyperVVirtualMachineActionJob.Status.RUNNING:
        raise ValidationError("The Hyper-V virtual machine action transition is invalid.")
    job.status = RESULT_STATUSES[result]
    job.result_code = result_code
    update_fields = ["status", "result_code"]
    if result == "running":
        job.started_at = timezone.now()
        update_fields.append("started_at")
    else:
        job.completed_at = timezone.now()
        update_fields.append("completed_at")
        if result == "succeeded" and job.virtual_machine_id:
            HyperVVirtualMachine.objects.filter(id=job.virtual_machine_id).update(
                state=EXPECTED_STATES[job.action],
                observed_at=timezone.now(),
            )
    job.save(update_fields=update_fields)
    AuditEvent.objects.create(
        tenant=enrollment.tenant,
        actor=enrollment.device_uri,
        action=f"hyperv.virtual_machine.action.{result}",
        object_type="hyperv_virtual_machine_action_job",
        object_id=str(job.id),
        outcome=AuditEvent.Outcome.FAILED if result == "failed" else AuditEvent.Outcome.SUCCEEDED,
        details={"action": job.action, "result_code": result_code},
    )
    return job
