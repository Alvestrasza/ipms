"""Live tenant policy and irreversible withdrawal of queued execution authority.

The caller of the suspension hook owns the Tenant NO KEY UPDATE lock. New
dispatchers use the same tenant-first order; no network work occurs under it.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from .models import Tenant
from .rbac import has_tenant_permission


def require_active_tenant(tenant_id, *, lock=False):
    query = Tenant.objects
    if lock:
        query = query.select_for_update(no_key=True)
    tenant = query.filter(pk=tenant_id, status=Tenant.Status.ACTIVE).first()
    if tenant is None:
        raise ValidationError("tenant_inactive")
    return tenant


def queued_actor_allowed(tenant_id, actor, permission):
    tenant = Tenant.objects.filter(pk=tenant_id, status=Tenant.Status.ACTIVE).first()
    if tenant is None or not isinstance(actor, str):
        return False
    user = get_user_model().objects.filter(username=actor, is_active=True).first()
    # A missing account is never an implicit system/scheduler identity.
    return bool(user and has_tenant_permission(user, tenant, permission))


def withdraw_agent_job(job, *, code="requester_permission_revoked"):
    """Do not replay an offer after authority returns; accept later settlement."""
    now = timezone.now()
    if job.authority_revoked_at is not None:
        return
    job.authority_revoked_at = now
    job.result_code = code
    fields = ["authority_revoked_at", "result_code"]
    if job.status == "queued":
        job.status = "cancelled"
        job.completed_at = now
        fields.extend(("status", "completed_at"))
    job.save(update_fields=fields)


@transaction.atomic
def apply_tenant_status_change(tenant, previous_status, actor):
    """Called after status persistence; activation never revives cancelled work."""
    from ipms.apps.agent_pki.models import (
        AgentEnrollment,
        AgentEnrollmentToken,
        AgentLifecycleJob,
        WindowsAgentDeployment,
        WindowsAgentDeploymentSecret,
    )
    from ipms.apps.audit.models import AuditEvent
    from ipms.apps.discovery.models import (
        DiscoveryJob,
        HyperVConsoleSession,
        HyperVVirtualMachineActionJob,
    )

    if tenant.status == Tenant.Status.ACTIVE or previous_status == tenant.status:
        return {}
    now = timezone.now()
    # All worker dispatchers take the tenant lock before their own job rows.
    # Ingestion also follows tenant-first ordering. Heartbeat uses a bounded
    # conditional update without taking this tenant lock.
    pending_ids = list(
        AgentEnrollment.objects.filter(tenant=tenant, status="pending").values_list(
            "id", flat=True
        )
    )
    counts = {
        "pending_enrollments": AgentEnrollment.objects.filter(
            id__in=pending_ids
        ).update(status="removed", updated_at=now),
        "enrollment_tokens": AgentEnrollmentToken.objects.filter(
            tenant=tenant, used_at__isnull=True
        ).update(used_at=now),
        "console_sessions": HyperVConsoleSession.objects.filter(
            tenant=tenant, status__in=("requested", "active")
        ).update(
            status="closed",
            failure_code="tenant_suspended",
            closed_at=now,
            frame_png=b"",
        ),
        "discovery_jobs": DiscoveryJob.objects.filter(
            tenant=tenant, status="queued"
        ).update(
            status="failed",
            error_code="tenant_suspended",
            completed_at=now,
        ),
    }
    deployments = WindowsAgentDeployment.objects.filter(tenant=tenant, status="queued")
    deployment_ids = list(deployments.values_list("id", flat=True))
    counts["deployments"] = deployments.update(
        status="failed", error_code="tenant_suspended", completed_at=now
    )
    WindowsAgentDeploymentSecret.objects.filter(
        deployment_id__in=deployment_ids
    ).delete()
    for model, label in (
        (AgentLifecycleJob, "lifecycle_jobs"),
        (HyperVVirtualMachineActionJob, "vm_actions"),
    ):
        jobs = model.objects.filter(
            tenant=tenant,
            status__in=("queued", "delivered", "running"),
            authority_revoked_at__isnull=True,
        )
        counts[label] = jobs.count()
        jobs.filter(status="queued").update(
            status="cancelled",
            authority_revoked_at=now,
            result_code="tenant_suspended",
            completed_at=now,
        )
        jobs.filter(status__in=("delivered", "running")).update(
            authority_revoked_at=now, result_code="tenant_suspended"
        )
    AuditEvent.objects.create(
        tenant=tenant,
        actor=actor,
        action="tenant.execution.suspend",
        object_type="tenant",
        object_id=str(tenant.id),
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details=counts,
    )
    return counts
