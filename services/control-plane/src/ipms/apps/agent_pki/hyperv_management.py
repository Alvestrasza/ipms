"""Durable, tenant-bound Hyper-V management authorization; no provider execution."""

from datetime import timedelta
import re

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import (
    HyperVConsoleSession,
    HyperVManagementJob,
    HyperVManagementSnapshot,
    HyperVVirtualMachine,
    HyperVVirtualMachineActionJob,
    WindowsServer,
)
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .models import AgentEnrollment, AgentLifecycleJob
from .hyperv_management_schema import (
    CODE,
    REVISION,
    canonical_uuid,
    document_digest,
    integer,
    validate_parameters,
    validate_settings_change,
    validate_snapshot,
)

ACTIVE_STATUSES = ("queued", "delivered", "running", "requires_reconciliation")
TERMINAL_STATUSES = ("succeeded", "failed", "cancelled")
OBSERVABLE_STATUSES = ("running", "requires_reconciliation")
FRESH_SECONDS = 60
EXECUTION_LEASE_SECONDS = 15
OPERATION_PERMISSIONS = {
    "inspect": Permission.INVENTORY_VIEW,
    "checkpoint_create": Permission.VIRTUAL_MACHINES_CHECKPOINTS_MANAGE,
    "checkpoint_delete": Permission.VIRTUAL_MACHINES_CHECKPOINTS_MANAGE,
    "checkpoint_apply": Permission.VIRTUAL_MACHINES_CHECKPOINTS_MANAGE,
    "settings_update": Permission.VIRTUAL_MACHINES_CONFIGURE,
}


def deny(code, status=409):
    raise PublicApiError(code, status_code=status)


def active_management_jobs(tenant_id, *, enrollment_id=None, vm_source_id=None):
    jobs = HyperVManagementJob.objects.filter(
        tenant_id=tenant_id, status__in=ACTIVE_STATUSES
    )
    if enrollment_id is not None:
        jobs = jobs.filter(enrollment_id=enrollment_id)
    if vm_source_id is not None:
        jobs = jobs.filter(vm_source_id=vm_source_id)
    return jobs


def management_job_conflicts(virtual_machine, enrollment=None):
    jobs = active_management_jobs(
        virtual_machine.tenant_id, vm_source_id=virtual_machine.source_id
    )
    if enrollment is not None:
        jobs = jobs.filter(enrollment=enrollment)
    else:
        jobs = jobs.filter(virtual_machine=virtual_machine)
    return jobs.exists()


def _audit(job, event, *, outcome=AuditEvent.Outcome.SUCCEEDED):
    AuditEvent.objects.create(
        tenant_id=job.tenant_id,
        actor=job.requested_by,
        action=f"hyperv.management.{event}",
        object_type="hyperv_management_job",
        object_id=str(job.pk),
        outcome=outcome,
        details={
            "actor_user_id": str(job.actor_id),
            "operation": job.operation,
            "virtual_machine_id": (
                str(job.virtual_machine_id) if job.virtual_machine_id else None
            ),
            "status": job.status,
            "result_code": job.result_code,
        },
    )


def _fresh_actor(actor_id, tenant, operation):
    actor = get_user_model().objects.filter(pk=actor_id).first()
    permission = OPERATION_PERMISSIONS.get(operation)
    if (
        actor is None
        or permission is None
        or not has_tenant_permission(actor, tenant, permission)
    ):
        deny("forbidden", 403)
    return actor


def _tenant(tenant_id, *, active=True):
    tenant = Tenant.objects.select_for_update(no_key=True).get(pk=tenant_id)
    if active and tenant.status != Tenant.Status.ACTIVE:
        deny("management_tenant_unavailable")
    return tenant


def _eligible(vm, enrollment, *, check_contact=True):
    host = vm.host
    if (
        vm.tenant_id != enrollment.tenant_id
        or host.tenant_id != enrollment.tenant_id
        or host.source_id != enrollment.device_uri
        or enrollment.status != "active"
        or enrollment.platform != "windows"
        or host.inventory_source != "agent"
        or host.hyperv_inventory_status != "collected"
    ):
        deny("management_agent_unavailable")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", host.agent_version) or tuple(
        int(part) for part in host.agent_version.split(".")
    ) < (0, 2, 27):
        deny("management_agent_upgrade_required")
    if check_contact:
        contact = max(
            (
                value
                for value in (enrollment.last_heartbeat_at, enrollment.last_seen_at)
                if value is not None
            ),
            default=None,
        )
        now = timezone.now()
        if contact is None or not now - timedelta(
            seconds=45
        ) <= contact <= now + timedelta(seconds=5):
            deny("management_agent_unavailable")


def _reporting_enrollment(enrollment):
    fresh = (
        AgentEnrollment.objects.select_for_update()
        .filter(
            pk=enrollment.pk,
            tenant_id=enrollment.tenant_id,
            status="active",
            platform="windows",
        )
        .first()
    )
    if fresh is None:
        deny("management_agent_unavailable")
    host = WindowsServer.objects.filter(
        tenant_id=fresh.tenant_id, source_id=fresh.device_uri, inventory_source="agent"
    ).first()
    if (
        host is None
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", host.agent_version)
        or tuple(int(part) for part in host.agent_version.split(".")) < (0, 2, 27)
    ):
        deny("management_agent_upgrade_required")
    return fresh


def _locked_vm(tenant_id, vm_id, expected_enrollment=None):
    routing = (
        HyperVVirtualMachine.objects.select_related("host")
        .filter(pk=vm_id, tenant_id=tenant_id)
        .first()
    )
    if routing is None:
        deny("management_vm_not_found", 404)
    enrollment = (
        AgentEnrollment.objects.select_for_update()
        .filter(tenant_id=tenant_id, device_uri=routing.host.source_id)
        .first()
    )
    if enrollment is None or (
        expected_enrollment is not None and enrollment.pk != expected_enrollment
    ):
        deny("management_agent_unavailable")
    vm = (
        HyperVVirtualMachine.objects.select_for_update(of=("self",))
        .select_related("host")
        .get(pk=vm_id, tenant_id=tenant_id)
    )
    _eligible(vm, enrollment)
    return vm, enrollment


def _check_conflicts(vm, enrollment, operation, *, exclude_job=None):
    from .deployment import pending_agent_deployments

    active = active_management_jobs(
        vm.tenant_id, enrollment_id=enrollment.pk, vm_source_id=vm.source_id
    )
    if exclude_job is not None:
        active = active.exclude(pk=exclude_job)
    if (
        active.exists()
        or pending_agent_deployments(enrollment, vm.host).exists()
        or AgentLifecycleJob.objects.filter(
            tenant_id=vm.tenant_id,
            enrollment=enrollment,
            status__in=("queued", "delivered", "running"),
        ).exists()
        or HyperVVirtualMachineActionJob.objects.filter(
            tenant_id=vm.tenant_id,
            enrollment=enrollment,
            vm_source_id=vm.source_id,
            status__in=("queued", "delivered", "running"),
        ).exists()
    ):
        deny("management_operation_conflict")
    if (
        operation == "checkpoint_apply"
        and HyperVConsoleSession.objects.filter(
            tenant_id=vm.tenant_id,
            enrollment=enrollment,
            vm_source_id=vm.source_id,
            status__in=("requested", "active"),
            lease_expires_at__gt=timezone.now(),
        ).exists()
    ):
        deny("management_console_active")


def _check_snapshot(vm, enrollment, operation, expected_revision, parameters):
    if operation == "inspect":
        return
    snapshot = HyperVManagementSnapshot.objects.filter(
        virtual_machine=vm,
        tenant_id=vm.tenant_id,
        enrollment=enrollment,
    ).first()
    now = timezone.now()
    if (
        snapshot is None
        or not now - timedelta(seconds=FRESH_SECONDS) <= snapshot.observed_at <= now
    ):
        deny("management_snapshot_stale")
    if snapshot.revision != expected_revision:
        deny("management_revision_changed")
    document = validate_snapshot(snapshot.document)
    if (
        document["vm_source_id"] != vm.source_id
        or document["vm_name"] != vm.name
        or document["state"] != vm.state
    ):
        deny("management_revision_changed")
    if not document["capabilities"].get(operation, False):
        deny("management_operation_unsupported")
    if document["collection_status"]["settings"] != "collected":
        deny("management_snapshot_unavailable")
    if operation == "settings_update":
        if "expected_state" in parameters and (
            not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", vm.host.agent_version)
            or tuple(int(part) for part in vm.host.agent_version.split("."))
            < (0, 2, 28)
        ):
            deny("management_agent_upgrade_required")
        validate_settings_change(parameters, document)
        return
    if document["collection_status"]["checkpoints"] != "collected":
        deny("management_snapshot_unavailable")
    if operation == "checkpoint_create":
        # The provider, not this enum, decides whether configured checkpoint
        # consistency is available. There is no fallback parameter in the job.
        return
    checkpoints = {item["id"]: item for item in document["checkpoints"]}
    selected = checkpoints.get(parameters["checkpoint_id"])
    if selected is None:
        deny("management_checkpoint_not_found", 404)
    if operation == "checkpoint_apply":
        if not selected["can_apply"]:
            deny("management_operation_unsupported")
        if (
            parameters["confirmation_vm_name"] != vm.name
            or parameters["confirmation_checkpoint_name"] != selected["name"]
        ):
            deny("management_confirmation_mismatch")
    elif operation == "checkpoint_delete":
        if not selected["can_delete"]:
            deny("management_operation_unsupported")
        affected = {selected["id"]}
        while True:
            descendants = {
                item["id"]
                for item in checkpoints.values()
                if item["parent_id"] in affected
            }
            if descendants.issubset(affected):
                break
            affected.update(descendants)
        if set(parameters["acknowledged_checkpoint_ids"]) != affected:
            deny("management_checkpoint_tree_changed")


def _job_document(job, *, mode=None):
    return {
        "schema": 1,
        "job_id": str(job.pk),
        "enrollment_id": str(job.enrollment_id),
        "vm_source_id": job.vm_source_id,
        "vm_name": job.vm_name,
        "operation": job.operation,
        "expected_revision": job.expected_revision,
        "parameters": job.parameters,
        "input_digest": job.input_digest,
        "status": job.status,
        "mode": mode or ("observe" if job.status in OBSERVABLE_STATUSES else "claim"),
    }


def job_payload(job):
    return {
        "id": str(job.pk),
        "request_id": str(job.request_id),
        "virtual_machine_id": (
            str(job.virtual_machine_id) if job.virtual_machine_id else None
        ),
        "operation": job.operation,
        "status": job.status,
        "phase": job.phase,
        "progress": job.progress,
        "result_code": job.result_code,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "can_cancel": False,
    }


def create_management_job(
    *,
    virtual_machine,
    actor,
    request_id,
    operation,
    expected_revision="",
    parameters=None,
):
    request_id = canonical_uuid(str(request_id))
    parameters = validate_parameters(
        operation, parameters if parameters is not None else {}
    )
    if operation == "inspect":
        if expected_revision != "":
            deny("invalid_request", 400)
    elif not isinstance(expected_revision, str) or not REVISION.fullmatch(
        expected_revision
    ):
        deny("invalid_request", 400)
    request_digest = document_digest(
        {
            "actor_id": str(actor.pk),
            "tenant_id": str(virtual_machine.tenant_id),
            "vm_id": str(virtual_machine.pk),
            "operation": operation,
            "expected_revision": expected_revision,
            "parameters": parameters,
        }
    )
    try:
        with transaction.atomic():
            tenant = _tenant(virtual_machine.tenant_id)
            actor = _fresh_actor(actor.pk, tenant, operation)
            prior = HyperVManagementJob.objects.filter(request_id=request_id).first()
            if prior is not None:
                if (
                    prior.request_digest != request_digest
                    or prior.actor_id != actor.pk
                    or prior.tenant_id != tenant.pk
                ):
                    deny("management_request_conflict")
                return prior
            vm, enrollment = _locked_vm(tenant.pk, virtual_machine.pk)
            _check_conflicts(vm, enrollment, operation)
            _check_snapshot(vm, enrollment, operation, expected_revision, parameters)
            input_digest = document_digest(
                {
                    "schema": 1,
                    "request_digest": request_digest,
                    "enrollment_id": str(enrollment.pk),
                    "vm_source_id": vm.source_id,
                    "vm_name": vm.name,
                    "operation": operation,
                    "expected_revision": expected_revision,
                    "parameters": parameters,
                }
            )
            job = HyperVManagementJob.objects.create(
                request_id=request_id,
                request_digest=request_digest,
                input_digest=input_digest,
                tenant=tenant,
                actor=actor,
                requested_by=actor.username,
                enrollment=enrollment,
                virtual_machine=vm,
                vm_source_id=vm.source_id,
                vm_name=vm.name,
                operation=operation,
                expected_revision=expected_revision,
                parameters=parameters,
            )
            _audit(job, "queue")
            return job
    except IntegrityError:
        # Cross-tenant duplicate request IDs are never returned to another actor.
        deny("management_request_conflict")


def _withdraw(job, code):
    now = timezone.now()
    job.authority_revoked_at = job.authority_revoked_at or now
    if job.status in ("queued", "delivered"):
        job.status = "cancelled"
        job.completed_at = now
        job.result_code = code
    job.save(
        update_fields=(
            "authority_revoked_at",
            "status",
            "completed_at",
            "result_code",
            "updated_at",
        )
    )
    _audit(job, "withdraw", outcome=AuditEvent.Outcome.DENIED)


def withdraw_management_jobs(*, tenant_id, actor_id=None, reason="authority_withdrawn"):
    """Caller holds the tenant transaction/lock; accepted jobs stay observable."""
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Management withdrawal requires the tenant transaction.")
    if not isinstance(reason, str) or not CODE.fullmatch(reason):
        deny("invalid_request", 400)
    jobs = active_management_jobs(tenant_id).filter(authority_revoked_at__isnull=True)
    if actor_id is not None:
        jobs = jobs.filter(actor_id=actor_id)
    count = 0
    for job in jobs.select_for_update().order_by("pk"):
        _withdraw(job, reason)
        count += 1
    return count


def _execution_checks(job, tenant):
    if job.authority_revoked_at is not None:
        deny("management_authority_withdrawn")
    _fresh_actor(job.actor_id, tenant, job.operation)
    validate_parameters(job.operation, job.parameters)
    if job.virtual_machine_id is None:
        deny("management_vm_not_found", 404)
    vm, enrollment = _locked_vm(tenant.pk, job.virtual_machine_id, job.enrollment_id)
    if vm.source_id != job.vm_source_id or vm.name != job.vm_name:
        deny("management_revision_changed")
    _check_conflicts(vm, enrollment, job.operation, exclude_job=job.pk)
    _check_snapshot(
        vm, enrollment, job.operation, job.expected_revision, job.parameters
    )


@transaction.atomic
def offer_management_job(enrollment):
    tenant = _tenant(enrollment.tenant_id, active=False)
    try:
        enrollment = _reporting_enrollment(enrollment)
    except PublicApiError:
        return None
    job = (
        active_management_jobs(tenant.pk, enrollment_id=enrollment.pk)
        .select_for_update()
        .order_by("created_at", "pk")
        .first()
    )
    if job is None:
        return None
    if job.status in OBSERVABLE_STATUSES:
        return _job_document(job, mode="observe")
    try:
        _execution_checks(job, tenant)
    except PublicApiError as exc:
        _withdraw(job, exc.public_code)
        return None
    if job.status == "queued":
        job.status = "delivered"
        job.delivered_at = timezone.now()
        job.save(update_fields=("status", "delivered_at", "updated_at"))
        _audit(job, "deliver")
    return _job_document(job, mode="claim")


@transaction.atomic
def management_job_status(enrollment, job_id):
    """Inspect an existing journal binding without offering or authorizing work."""
    job_id = canonical_uuid(str(job_id))
    tenant = _tenant(enrollment.tenant_id, active=False)
    enrollment = _reporting_enrollment(enrollment)
    job = HyperVManagementJob.objects.filter(
        pk=job_id, tenant=tenant, enrollment=enrollment
    ).first()
    if job is None:
        deny("management_job_not_found", 404)
    mode = "observe" if job.status in OBSERVABLE_STATUSES else job.status
    return _job_document(job, mode=mode)


@transaction.atomic
def claim_management_job(enrollment, job_id, input_digest):
    job_id = canonical_uuid(str(job_id))
    tenant = _tenant(enrollment.tenant_id, active=False)
    enrollment = _reporting_enrollment(enrollment)
    job = (
        HyperVManagementJob.objects.select_for_update()
        .filter(pk=job_id, tenant=tenant, enrollment=enrollment)
        .first()
    )
    if job is None:
        deny("management_job_not_found", 404)
    if not isinstance(input_digest, str) or input_digest != job.input_digest:
        deny("management_input_mismatch")
    if job.status in OBSERVABLE_STATUSES:
        return {
            "authorized": False,
            "mode": "observe",
            "job": _job_document(job, mode="observe"),
        }
    if job.status != "delivered":
        deny("management_job_not_claimable")
    try:
        _execution_checks(job, tenant)
    except PublicApiError as exc:
        _withdraw(job, exc.public_code)
        return {
            "authorized": False,
            "mode": "cancelled",
            "job": _job_document(job, mode="observe"),
        }
    now = timezone.now()
    job.status = "running"
    job.phase = "authorized"
    job.started_at = now
    job.execution_lease_expires_at = now + timedelta(seconds=EXECUTION_LEASE_SECONDS)
    job.save(
        update_fields=(
            "status",
            "phase",
            "started_at",
            "execution_lease_expires_at",
            "updated_at",
        )
    )
    _audit(job, "claim")
    return {
        "authorized": True,
        "mode": "execute",
        "expires_at": job.execution_lease_expires_at.isoformat(),
        "lease_seconds": EXECUTION_LEASE_SECONDS,
        "job": _job_document(job, mode="execute"),
    }


@transaction.atomic
def record_management_result(
    enrollment, *, job_id, status, phase, progress, result_code, snapshot=None
):
    job_id = canonical_uuid(str(job_id))
    tenant = _tenant(enrollment.tenant_id, active=False)
    enrollment = _reporting_enrollment(enrollment)
    if status not in (
        "running",
        "succeeded",
        "failed",
        "requires_reconciliation",
    ) or any(
        not isinstance(value, str) or not CODE.fullmatch(value)
        for value in (phase, result_code)
    ):
        deny("invalid_request", 400)
    integer(progress, 100, nullable=True)
    if snapshot is not None:
        validate_snapshot(snapshot)
    digest = document_digest(
        {
            "status": status,
            "phase": phase,
            "progress": progress,
            "result_code": result_code,
            "snapshot": snapshot,
        }
    )
    job = (
        HyperVManagementJob.objects.select_for_update()
        .filter(pk=job_id, tenant=tenant, enrollment=enrollment)
        .first()
    )
    if job is None:
        deny("management_job_not_found", 404)
    if job.status in TERMINAL_STATUSES:
        if job.result_digest == digest:
            return job
        deny("management_result_conflict")
    if job.status not in OBSERVABLE_STATUSES:
        deny("management_result_transition_invalid")
    if job.result_digest == digest:
        return job
    if job.status == "requires_reconciliation" and status == "running":
        deny("management_result_transition_invalid")
    expected_name = job.vm_name
    general_settings = (
        job.operation == "settings_update"
        and job.parameters.get("section") == "general"
    )
    if general_settings and status == "succeeded":
        expected_name = job.parameters["values"].get("name", job.vm_name)
    if snapshot is not None and (
        snapshot["vm_source_id"] != job.vm_source_id
        or snapshot["vm_name"] != expected_name
        or (general_settings and snapshot["settings"]["name"] != expected_name)
    ):
        deny("management_snapshot_identity_mismatch")
    if status == "succeeded" and snapshot is None:
        deny("management_snapshot_required")
    if status == "succeeded" and job.operation == "settings_update":
        section = job.parameters["section"]
        observed = (
            snapshot["settings"]
            if section == "general"
            else snapshot["settings"][section]
        )
        if (
            snapshot["collection_status"]["settings"] != "collected"
            or snapshot["state"] != job.parameters.get("expected_state", "stopped")
            or ("expected_state" in job.parameters and snapshot["schema_version"] != 2)
            or any(
                observed[key] != value
                for key, value in job.parameters["values"].items()
            )
        ):
            deny("management_snapshot_postcondition_mismatch")
    job.status = status
    job.phase = phase
    job.progress = progress
    job.result_code = result_code
    job.result_digest = digest
    if status in TERMINAL_STATUSES:
        job.completed_at = timezone.now()
    job.save(
        update_fields=(
            "status",
            "phase",
            "progress",
            "result_code",
            "result_digest",
            "completed_at",
            "updated_at",
        )
    )
    if (
        snapshot is not None
        and job.authority_revoked_at is None
        and tenant.status == "active"
        and job.virtual_machine_id
    ):
        vm = (
            HyperVVirtualMachine.objects.select_for_update()
            .select_related("host")
            .filter(
                pk=job.virtual_machine_id,
                tenant=tenant,
                host__source_id=enrollment.device_uri,
            )
            .first()
        )
        if vm is not None and vm.source_id == job.vm_source_id:
            if general_settings and status == "succeeded":
                vm.name = expected_name
                vm.save(update_fields=("name", "updated_at"))
            # Conservative observation start: a delayed or retried result never
            # turns an old inspection into a freshly observed configuration.
            HyperVManagementSnapshot.objects.update_or_create(
                virtual_machine=vm,
                defaults={
                    "tenant": tenant,
                    "enrollment": enrollment,
                    "job": job,
                    "revision": snapshot["revision"],
                    "document": snapshot,
                    "observed_at": job.started_at,
                },
            )
    _audit(
        job,
        "result",
        outcome=(
            AuditEvent.Outcome.FAILED
            if status in ("failed", "requires_reconciliation")
            else AuditEvent.Outcome.SUCCEEDED
        ),
    )
    return job


def management_payload(vm):
    snapshot = HyperVManagementSnapshot.objects.filter(
        virtual_machine=vm,
        tenant_id=vm.tenant_id,
        enrollment__device_uri=vm.host.source_id,
    ).first()
    active = (
        active_management_jobs(vm.tenant_id)
        .filter(virtual_machine=vm)
        .order_by("created_at")
        .first()
    )
    latest = (
        HyperVManagementJob.objects.filter(virtual_machine=vm, tenant_id=vm.tenant_id)
        .order_by("-created_at", "-pk")
        .first()
    )
    now = timezone.now()
    return {
        "virtual_machine_id": str(vm.pk),
        "vm_source_id": vm.source_id,
        "vm_name": vm.name,
        "collection_status": "collected" if snapshot else "not-reported",
        "snapshot": snapshot.document if snapshot else None,
        "observed_at": snapshot.observed_at.isoformat() if snapshot else None,
        "valid_until": (
            (snapshot.observed_at + timedelta(seconds=FRESH_SECONDS)).isoformat()
            if snapshot
            else None
        ),
        "fresh": bool(
            snapshot
            and now - timedelta(seconds=FRESH_SECONDS) <= snapshot.observed_at <= now
        ),
        "active_operation": job_payload(active) if active else None,
        "latest_operation": job_payload(latest) if latest else None,
    }
