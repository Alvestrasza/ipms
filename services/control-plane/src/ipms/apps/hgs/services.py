# File Name: services.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Reviewed HGS plans with tenant-first locking, identity-bound steps and receipt reconciliation.
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from ipms.apps.agent_pki.models import AgentEnrollment, AgentLifecycleJob
from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from . import contract as c
from .models import HgsDeployment, HgsJob, HgsNode

PLAN_AGE = timedelta(hours=24)
READINESS_AGE = timedelta(minutes=30)
HEARTBEAT_AGE = timedelta(minutes=5)
PLAN_ACTIVE = ("draft", "inspecting", "ready", "blocked", "running", "waiting_for_reboot", "reconciliation_required")


def conflict(code):
    raise PublicApiError("hgs_" + code, status_code=409)


def audit(plan, action, *, details=None):
    AuditEvent.objects.create(tenant=plan.tenant, actor=str(plan.approved_by_id or plan.requested_by_id),
        action="hgs." + action, object_type="hgs_deployment", object_id=str(plan.id),
        outcome=AuditEvent.Outcome.SUCCEEDED, details={"plan_digest": plan.plan_digest, **(details or {})})


def live_identity(node, tenant):
    e = AgentEnrollment.objects.get(pk=node.enrollment_id)
    s = WindowsServer.objects.get(pk=node.system_id)
    return (tenant.purpose == "hgs" and tenant.status == "active" and e.status == "active"
            and e.tenant_id == tenant.id == s.tenant_id and e.platform == "windows"
            and e.device_uri == node.device_uri == s.source_id and s.inventory_source == "agent"
            and s.hostname.lower().split(".")[0] == node.hostname.lower().split(".")[0])


def eligible(system, enrollment):
    now = timezone.now()
    if not enrollment or enrollment.status != "active" or enrollment.platform != "windows" or enrollment.tenant_id != system.tenant_id:
        return "active_windows_agent_required"
    if system.inventory_source != "agent" or system.operating_system_role == "client" or system.os_build not in ("20348", "26100"):
        return "unsupported_windows_version"
    import re
    if not re.fullmatch(r"\d{1,5}\.\d{1,5}\.\d{1,5}", system.agent_version) or tuple(map(int, system.agent_version.split("."))) < (0, 2, 49):
        return "agent_update_required"
    if not enrollment.last_heartbeat_at or not now - HEARTBEAT_AGE < enrollment.last_heartbeat_at <= now:
        return "agent_unavailable"
    return ""


def configuration(plan, node):
    return {**plan.config, "profile": plan.profile, "attestation_mode": plan.attestation_mode,
            "domain_name": plan.domain_name, "service_name": plan.service_name,
            "node_role": node.role, "primary_server": plan.config["primary_server"] if node.role == "additional" else ""}


def plan_content(plan):
    return {"schema_version": 1, "tenant_id": str(plan.tenant_id), "name": plan.name,
            "profile": plan.profile, "attestation_mode": plan.attestation_mode,
            "domain_name": plan.domain_name, "service_name": plan.service_name, "config": plan.config,
            "nodes": [{"id": str(n.id), "system_id": str(n.system_id), "enrollment_id": str(n.enrollment_id),
                       "device_uri": n.device_uri, "hostname": n.hostname, "ordinal": n.ordinal, "role": n.role}
                      for n in plan.nodes.order_by("ordinal")]}


def create_plan(tenant, user, document):
    if tenant.purpose != "hgs" or not has_tenant_permission(user, tenant, Permission.HGS_MANAGE):
        conflict("dedicated_tenant_required")
    data = c.validate_plan(document)
    systems = {str(s.id): s for s in WindowsServer.objects.select_for_update().filter(tenant=tenant, pk__in=data["node_ids"])}
    if len(systems) != len(data["node_ids"]):
        conflict("node_selection_invalid")
    if HgsDeployment.objects.filter(tenant=tenant, domain_name=data["domain_name"]).exclude(status__in=("failed", "cancelled")).exists():
        conflict("domain_already_managed")
    enrollments = {e.device_uri: e for e in AgentEnrollment.objects.select_for_update().filter(tenant=tenant,
                    device_uri__in=[s.source_id for s in systems.values()])}
    if any(eligible(s, enrollments.get(s.source_id)) for s in systems.values()):
        conflict("node_unavailable")
    if HgsNode.objects.filter(enrollment__in=list(enrollments.values()), deployment__status__in=PLAN_ACTIVE).exists():
        conflict("node_already_reserved")
    plan = HgsDeployment.objects.create(tenant=tenant, requested_by=user, name=data["name"],
        profile=data["profile"], attestation_mode=data["attestation_mode"], domain_name=data["domain_name"],
        service_name=data["service_name"], config={key: data[key] for key in c.CONFIG_FIELDS}, plan_expires_at=timezone.now() + PLAN_AGE)
    for index, system_id in enumerate(data["node_ids"]):
        s = systems[system_id]
        HgsNode.objects.create(deployment=plan, system=s, enrollment=enrollments[s.source_id], device_uri=s.source_id,
            hostname=s.hostname, ordinal=index, role="primary" if index == 0 else "additional")
    plan.plan_digest = c.digest(plan_content(plan))
    plan.save(update_fields=("plan_digest", "updated_at"))
    audit(plan, "plan_created")
    return plan


def create_job(plan, node, operation, sequence=0, *, actor=None):
    job = HgsJob.objects.create(deployment=plan, node=node, operation=operation, sequence=sequence,
        requested_by=actor or plan.approved_by or plan.requested_by, expires_at=plan.approval_expires_at or plan.plan_expires_at)
    job.assignment = {"schema_version": 1, "job_id": str(job.id), "deployment_id": str(plan.id),
        "tenant_id": str(plan.tenant_id), "enrollment_id": str(node.enrollment_id), "device_uri": node.device_uri,
        "plan_digest": plan.plan_digest, "operation": operation, "config": configuration(plan, node),
        "expires_at": int(job.expires_at.timestamp())}
    job.save(update_fields=("assignment",))
    return job


def request_inspection(plan, *, actor=None, reconciliation=False):
    allowed = ("draft", "blocked", "ready", "failed", "cancelled", "reconciliation_required") if reconciliation else ("draft", "blocked", "ready")
    if plan.status not in allowed or plan.jobs.filter(status__in=c.ACTIVE).exists():
        conflict("inspection_unavailable")
    if plan.plan_expires_at <= timezone.now() and not reconciliation:
        conflict("plan_expired")
    # Reconciliation remains read-only even when a previous approval expired.
    for node in plan.nodes.select_for_update().all():
        if not live_identity(node, plan.tenant):
            conflict("node_identity_changed")
        job = create_job(plan, node, "inspect", actor=actor)
        if reconciliation:
            job.expires_at = timezone.now() + READINESS_AGE
            job.assignment["expires_at"] = int(job.expires_at.timestamp())
            job.save(update_fields=("expires_at", "assignment"))
        node.status = "inspecting"
        node.save(update_fields=("status",))
    if not reconciliation:
        plan.status = "inspecting"
    plan.save(update_fields=("status", "updated_at"))
    audit(plan, "reconciliation_requested" if reconciliation else "inspection_requested")


def authorize(plan, user, document):
    if not isinstance(document, dict) or set(document) != {"plan_digest", "confirm"} or document["confirm"] is not True:
        c.reject()
    if plan.status != "ready" or plan.authority_revoked_at or plan.approved_at:
        conflict("plan_not_ready")
    if document["plan_digest"] != plan.plan_digest or c.digest(plan_content(plan)) != plan.plan_digest:
        conflict("plan_changed")
    now = timezone.now()
    if plan.plan_expires_at <= now:
        conflict("plan_expired")
    for node in plan.nodes.select_for_update().all():
        if (not live_identity(node, plan.tenant) or not node.observed_at or not now - READINESS_AGE < node.observed_at <= now
                or not node.readiness or c.readiness_blockers(configuration(plan, node), node.readiness, hostname=node.hostname, role=node.role, initial=True)):
            conflict("readiness_expired_or_blocked")
    plan.approved_by = user
    plan.approved_at = now
    plan.approval_expires_at = plan.plan_expires_at
    plan.status = "running"
    plan.save()
    node = plan.nodes.order_by("ordinal").first()
    node.status = "running"
    node.save(update_fields=("status",))
    create_job(plan, node, "install_role")
    audit(plan, "plan_approved")


def fence(plan, code):
    now = timezone.now()
    plan.authority_revoked_at = plan.authority_revoked_at or now
    plan.blockers = sorted(set(plan.blockers + [code]))
    uncertain = plan.jobs.filter(Q(status__in=("running", "waiting_for_reboot"))
                                | Q(status="reconciliation_required", reconciliation_release__isnull=True)).exists()
    plan.jobs.filter(status__in=("queued", "offered")).update(status="cancelled", result_code=code, completed_at=now)
    plan.status = "reconciliation_required" if uncertain else "cancelled"
    plan.save(update_fields=("authority_revoked_at", "blockers", "status", "updated_at"))


def cancel(plan):
    if plan.status in ("succeeded", "cancelled"):
        conflict("already_complete")
    fence(plan, "cancelled_by_operator")
    audit(plan, "cancel_requested")


def authority_current(plan, job, tenant):
    if (tenant.purpose != "hgs" or tenant.status != "active"
            or job.expires_at <= timezone.now() or c.digest(plan_content(plan)) != plan.plan_digest
            or not job.requested_by or not has_tenant_permission(job.requested_by, tenant, Permission.HGS_MANAGE)):
        return False
    if job.operation == "inspect":
        return True
    return (not plan.authority_revoked_at and plan.status in ("running", "waiting_for_reboot") and plan.approved_at is not None
            and plan.approval_expires_at and plan.approval_expires_at > timezone.now()
            and plan.approved_by and has_tenant_permission(plan.approved_by, tenant, Permission.HGS_MANAGE))


def after_result(plan, node, job):
    if plan.authority_revoked_at and not plan.jobs.filter(
            Q(status__in=c.ACTIVE) | Q(status="reconciliation_required", reconciliation_release__isnull=True)).exists():
        plan.status = "cancelled"
        plan.save(update_fields=("status", "updated_at"))
        return
    if job.operation == "inspect":
        if plan.jobs.filter(operation="inspect", status__in=c.ACTIVE).exists():
            return
        # Inspection can explain a fenced/failed job; it cannot grant write authority.
        if plan.status not in ("inspecting", "draft", "blocked", "ready") or plan.authority_revoked_at:
            return
        blockers = sorted({item for n in plan.nodes.all() for item in n.blockers})
        plan.blockers = blockers
        plan.status = "blocked" if blockers else "ready"
        plan.save(update_fields=("blockers", "status", "updated_at"))
        return
    if plan.authority_revoked_at or plan.status in ("cancelled", "reconciliation_required"):
        return
    next_sequence = job.sequence + 1
    steps = c.node_steps(node)
    if next_sequence < len(steps):
        create_job(plan, node, steps[next_sequence], next_sequence)
        plan.status = "running"
    else:
        node.status = "succeeded"
        node.save(update_fields=("status",))
        following = plan.nodes.filter(ordinal__gt=node.ordinal).order_by("ordinal").first()
        if following:
            following.status = "running"
            following.save(update_fields=("status",))
            create_job(plan, following, "install_role")
            plan.status = "running"
        else:
            plan.status = "succeeded"
            audit(plan, "deployment_verified")
    plan.save(update_fields=("status", "updated_at"))


def accept_result(plan, node, job, document):
    if not isinstance(document, dict) or set(document) != {"status", "result_code", "observation"}:
        c.reject()
    status = document["status"]
    if status not in ("succeeded", "failed", "reconciliation_required", "reboot_required"):
        c.reject()
    if not isinstance(document["result_code"], str) or document["result_code"] not in c.RESULT_CODES:
        c.reject()
    observation = document["observation"]
    if status in ("succeeded", "reboot_required"):
        c.validate_observation(observation)
        if observation["computer_name"].lower().split(".")[0] != node.hostname.lower().split(".")[0]:
            c.reject()
        if status == "succeeded" and not c.postcondition(job.operation, configuration(plan, node), observation):
            c.reject()
        if status == "reboot_required" and job.operation not in ("install_role", "create_forest", "join_node", "reboot"):
            c.reject()
    elif observation:
        c.validate_observation(observation)
    elif not isinstance(observation, dict):
        c.reject()
    if job.status in c.TERMINAL:
        if job.status == "cancelled" and job.receipt is None and status == "failed" and document["result_code"] in c.UNCLAIMED_FAILURES:
            job.receipt = document
            job.save(update_fields=("receipt",))
            audit(plan, "cancelled_step_not_executed", details={"job_id": str(job.id), "result_code": document["result_code"]})
            return {"accepted": True}
        if job.receipt != document:
            c.reject()
        return {"accepted": True}
    unclaimed_failure = job.status in ("queued", "offered") and status == "failed" and document["result_code"] in c.UNCLAIMED_FAILURES
    if job.status not in ("running", "waiting_for_reboot") and not unclaimed_failure:
        c.reject()
    # A pre-reboot receipt is not proof of post-reboot completion.
    if job.operation == "reboot" and status == "succeeded" and job.preboot_id:
        if observation["boot_id"] == job.preboot_id:
            c.reject()
    if job.operation == "reboot" and status == "reboot_required" and not job.preboot_id:
        job.preboot_id = observation["boot_id"]
    now = timezone.now()
    job.receipt = document
    job.result_code = document["result_code"]
    if status == "reboot_required" and job.operation == "reboot":
        job.status = "waiting_for_reboot"
        plan.status = "reconciliation_required" if plan.authority_revoked_at else "waiting_for_reboot"
        plan.save(update_fields=("status", "updated_at"))
    else:
        job.status = "succeeded" if status == "reboot_required" else status
        job.completed_at = now
        # A valid late completion is evidence, not renewed authority to continue.
        # Keep its exact receipt and require a fresh observation plus explicit resolve.
        if job.status == "succeeded" and plan.authority_revoked_at and job.operation not in c.READ_ONLY:
            job.status = "reconciliation_required"
    job.save()
    if observation:
        node.readiness = observation
        node.observed_at = now
        node.blockers = c.readiness_blockers(configuration(plan, node), observation, hostname=node.hostname, role=node.role, initial=plan.approved_at is None)
    if job.operation == "inspect":
        node.status = "blocked" if status != "succeeded" or node.blockers else "ready"
        if status != "succeeded":
            node.blockers = sorted(set(node.blockers + [job.result_code]))
    node.save(update_fields=("readiness", "observed_at", "blockers", "status"))
    audit(plan, "step_reported", details={"job_id": str(job.id), "operation": job.operation, "status": status, "result_code": job.result_code})
    if job.operation == "inspect":
        after_result(plan, node, job)
    elif status in ("failed", "reconciliation_required"):
        plan.status = status
        plan.blockers = sorted(set(plan.blockers + [job.result_code]))
        plan.jobs.filter(status__in=("queued", "offered")).update(status="cancelled", result_code="prior_step_failed", completed_at=now)
        plan.save(update_fields=("status", "blockers", "updated_at"))
    elif job.status == "succeeded":
        after_result(plan, node, job)
    return {"accepted": True}


def reconciliation(plan):
    job = plan.jobs.filter(status="reconciliation_required", reconciliation_release__isnull=True).exclude(operation="inspect").order_by("-created_at").first()
    if not job:
        return None
    node = job.node
    latest = node.jobs.filter(operation="inspect", status="succeeded", created_at__gt=job.created_at).order_by("-created_at").first()
    observation = latest.receipt.get("observation") if latest and latest.receipt else None
    reason = "fresh_inspection_required"
    valid = False
    if latest and latest.completed_at and timezone.now() - READINESS_AGE < latest.completed_at <= timezone.now() and observation:
        valid = c.postcondition(job.operation, configuration(plan, node), observation)
        if job.operation == "reboot":
            previous_boot = job.preboot_id or (job.receipt or {}).get("observation", {}).get("boot_id")
            valid = bool(valid and previous_boot and observation["boot_id"] != previous_boot)
        reason = "" if valid else "interrupted_step_not_proven"
    return {"job_id": str(job.id), "observation_digest": c.digest(observation) if observation else "",
            "can_resolve": valid and plan.status == "reconciliation_required", "reason": reason}


def resolve(plan, user, document):
    if (not isinstance(document, dict) or set(document) != {"job_id", "plan_digest", "observation_digest", "confirm"}
            or document["confirm"] is not True):
        c.reject()
    state = reconciliation(plan)
    if (not state or not state["can_resolve"] or any(document[key] != state[key] for key in ("job_id", "observation_digest"))
            or document["plan_digest"] != plan.plan_digest or c.digest(plan_content(plan)) != plan.plan_digest):
        conflict("reconciliation_not_proven")
    job = plan.jobs.select_for_update().get(pk=state["job_id"])
    node = job.node
    if not live_identity(node, plan.tenant) or plan.jobs.filter(status__in=c.ACTIVE).exists():
        conflict("reconciliation_not_proven")
    now = timezone.now()
    job.reconciliation_release = {"job_id": str(job.id), "plan_digest": plan.plan_digest,
        "observation_digest": state["observation_digest"], "approved_by": str(user.id), "approved_at": now.isoformat()}
    # Original uncertain receipt is retained; the resolution is a separate proof.
    job.status = "succeeded"
    job.result_code = "hgs_state_reconciled"
    job.save(update_fields=("reconciliation_release", "status", "result_code"))
    plan.approved_by = user
    plan.approved_at = now
    plan.plan_expires_at = now + PLAN_AGE
    plan.approval_expires_at = plan.plan_expires_at
    plan.authority_revoked_at = None
    plan.blockers = []
    plan.status = "running"
    plan.save()
    audit(plan, "state_reconciled", details=job.reconciliation_release)
    after_result(plan, node, job)


def poll_response(enrollment, job=None):
    released = HgsJob.objects.filter(node__enrollment=enrollment, deployment__tenant_id=enrollment.tenant_id,
        reconciliation_release__isnull=False).order_by("-created_at").first()
    response = {"hgs_job": job}
    if released:
        response["hgs_reconciliation_release"] = {key: released.reconciliation_release[key] for key in ("job_id", "plan_digest")}
    return response


@transaction.atomic
def hgs_exchange(authenticated, document):
    if not isinstance(document, dict):
        c.reject()
    mode = document.get("mode")
    common = {"type", "device_uri", "mode"}
    required = common | ({"agent_version", "hgs_provider_version"} if mode == "poll" else
                         {"job_id", "plan_digest", "result"} if mode == "result" else {"job_id", "plan_digest"})
    if mode not in ("poll", "claim", "result") or set(document) != required or document["type"] != "hgs" or document["device_uri"] != authenticated.device_uri:
        c.reject()
    tenant = Tenant.objects.select_for_update().get(pk=authenticated.tenant_id)
    enrollment = AgentEnrollment.objects.select_for_update().get(pk=authenticated.id)
    if enrollment.platform != "windows" or enrollment.status != "active" or enrollment.device_uri != authenticated.device_uri or enrollment.tenant_id != tenant.id:
        c.reject()
    if mode == "poll":
        if type(document["hgs_provider_version"]) is not int or document["hgs_provider_version"] != 1 or not c.text(document["agent_version"], 1, 32):
            c.reject()
        if tenant.purpose != "hgs" or tenant.status != "active":
            return {"hgs_job": None}
        job = HgsJob.objects.select_for_update().filter(node__enrollment=enrollment, deployment__tenant=tenant, status__in=c.ACTIVE).order_by("created_at").first()
    else:
        if not c.identifier(document["job_id"]) or not isinstance(document["plan_digest"], str):
            c.reject()
        job = HgsJob.objects.select_for_update().filter(pk=document["job_id"], node__enrollment=enrollment, deployment__tenant=tenant).first()
    if not job:
        if mode == "poll":
            return poll_response(enrollment)
        c.reject()
    plan = HgsDeployment.objects.select_for_update().get(pk=job.deployment_id)
    plan.tenant = tenant
    node = HgsNode.objects.select_for_update().get(pk=job.node_id)
    if mode != "poll" and document["plan_digest"] != job.assignment.get("plan_digest"):
        c.reject()
    if mode == "result":
        if job.status in c.TERMINAL and job.receipt is not None:
            return accept_result(plan, node, job, document["result"])
        # Valid delayed receipts remain evidence after a cancellation or suspension.
        if not live_identity(node, Tenant(id=tenant.id, purpose="hgs", status="active")):
            c.reject()
        if not authority_current(plan, job, tenant) and not plan.authority_revoked_at and job.status in ("running", "waiting_for_reboot"):
            fence(plan, "authority_withdrawn")
        return accept_result(plan, node, job, document["result"])
    if not live_identity(node, tenant) or not authority_current(plan, job, tenant):
        fence(plan, "authority_withdrawn")
        return {"hgs_job": None}
    if job.assignment != {"schema_version": 1, "job_id": str(job.id), "deployment_id": str(plan.id),
        "tenant_id": str(tenant.id), "enrollment_id": str(node.enrollment_id), "device_uri": node.device_uri,
        "plan_digest": plan.plan_digest, "operation": job.operation, "config": configuration(plan, node),
        "expires_at": int(job.expires_at.timestamp())}:
        fence(plan, "assignment_changed")
        return {"hgs_job": None}
    if AgentLifecycleJob.objects.filter(enrollment=enrollment, status__in=("queued", "delivered", "running")).exists():
        return {"hgs_job": None}
    if mode == "poll":
        if job.status == "queued":
            job.status = "offered"
            job.offered_at = timezone.now()
            job.save(update_fields=("status", "offered_at"))
    elif job.status in ("queued", "offered"):
        job.status = "running"
        job.claimed_at = timezone.now()
        job.save(update_fields=("status", "claimed_at"))
        audit(plan, "step_claimed", details={"job_id": str(job.id), "operation": job.operation})
    elif job.status not in ("running", "waiting_for_reboot"):
        return {"hgs_job": None}
    return poll_response(enrollment, job.assignment) if mode == "poll" else {"hgs_job": job.assignment}


def withdraw_hgs_jobs(*, tenant_id=None, actor_id=None, enrollment_id=None, reason="authority_withdrawn"):
    query = HgsDeployment.objects.filter(status__in=PLAN_ACTIVE)
    if tenant_id:
        query = query.filter(tenant_id=tenant_id)
    if actor_id:
        query = query.filter(Q(requested_by_id=actor_id) | Q(approved_by_id=actor_id) | Q(jobs__requested_by_id=actor_id, jobs__status__in=c.ACTIVE))
    if enrollment_id:
        query = query.filter(nodes__enrollment_id=enrollment_id)
    count = 0
    for pk, owner in query.order_by("tenant_id", "id").values_list("id", "tenant_id").distinct():
        with transaction.atomic():
            Tenant.objects.select_for_update().get(pk=owner)
            plan = HgsDeployment.objects.select_for_update().get(pk=pk)
            fence(plan, reason)
            count += 1
    return count


def projection(plan):
    nodes = list(plan.nodes.all())
    jobs = list(plan.jobs.order_by("created_at", "id"))
    steps = []
    for node in nodes:
        for index, operation in enumerate(c.node_steps(node)):
            matches = [job for job in jobs if job.node_id == node.id and job.sequence == index and job.operation == operation]
            steps.append({"id": f"{node.id}:{index}", "operation": operation, "node_id": str(node.id),
                "hostname": node.hostname, "mutates": operation not in c.READ_ONLY, "requires_reboot": operation == "reboot",
                "status": matches[-1].status if matches else "pending"})
    return {"id": str(plan.id), "tenant_id": str(plan.tenant_id), "name": plan.name, "profile": plan.profile,
        "attestation_mode": plan.attestation_mode, "status": plan.status, "domain_name": plan.domain_name,
        "service_name": plan.service_name, "plan_digest": plan.plan_digest, "config": plan.config,
        "plan_expires_at": plan.plan_expires_at.isoformat(),
        "approval_expires_at": plan.approval_expires_at.isoformat() if plan.approval_expires_at else None,
        "created_at": plan.created_at.isoformat(), "updated_at": plan.updated_at.isoformat(), "blockers": plan.blockers,
        "nodes": [{"id": str(n.id), "system_id": str(n.system_id), "hostname": n.hostname, "role": n.role,
                   "status": n.status, "readiness": n.readiness, "blockers": n.blockers,
                   "observed_at": n.observed_at.isoformat() if n.observed_at else None} for n in nodes],
        "reconciliation": reconciliation(plan), "steps": steps, "jobs": [{"id": str(j.id), "node_id": str(j.node_id), "operation": j.operation,
            "status": j.status, "result_code": j.result_code, "created_at": j.created_at.isoformat(),
            "completed_at": j.completed_at.isoformat() if j.completed_at else None} for j in jobs]}
