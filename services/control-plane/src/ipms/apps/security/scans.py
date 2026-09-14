# File Name: scans.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Bounded tenant scan leases and authenticated native evidence ingestion.
import hashlib
import json
import re
import uuid
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .catalog import BY_ID, CATALOG_REVISION
from .content import CATALOG_SHA256, MANIFESTS
from .evaluator import evaluate
from .models import BaselineAssessment, BaselineScanJob

ACTIVE = ("queued", "running")
MIN_AGENT_VERSION = (0, 2, 31)
QUEUE_AGE = timedelta(hours=1)
LEASE_AGE = timedelta(minutes=20)
HEARTBEAT_AGE = timedelta(minutes=5)
READ_STATUSES = {"ok", "missing", "unsupported", "access_denied", "error", "limit"}
MAX_ACTIVE_JOBS = 1000


def version_supported(version):
    return bool(isinstance(version, str) and re.fullmatch(r"\d{1,5}\.\d{1,5}\.\d{1,5}", version)
                and tuple(map(int, version.split("."))) >= MIN_AGENT_VERSION)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def reject():
    raise ValidationError("The Security scan request or evidence is invalid.")


def job_projection(job):
    return {
        "id": str(job.id), "system_id": str(job.system_id), "hostname": job.system.hostname,
        "status": job.status, "requested_at": job.requested_at.isoformat(),
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "error_code": job.error_code,
    }


def finish_failed(job, code, *, expired=False):
    job.status = "expired" if expired else "failed"
    job.error_code = code
    job.completed_at = timezone.now()
    job.pages = {}
    if job.assessment_id:
        BaselineAssessment.objects.filter(pk=job.assessment_id).update(error_code="collection_failed", scope_verified=False)
    job.save()


def expire_jobs(tenant):
    now = timezone.now()
    for job in BaselineScanJob.objects.select_for_update().filter(tenant=tenant, status__in=ACTIVE).filter(
        Q(expires_at__lte=now) | Q(status="running", lease_expires_at__lte=now)
    ):
        finish_failed(job, "expired", expired=True)


def eligible(enrollment, system, now):
    return bool(enrollment and enrollment.status == "active" and enrollment.platform == "windows"
                and enrollment.tenant_id == system.tenant_id and system.inventory_source == "agent"
                and system.source_id == enrollment.device_uri and version_supported(system.agent_version)
                and enrollment.last_heartbeat_at and now - HEARTBEAT_AGE < enrollment.last_heartbeat_at <= now)


def queue_scans(tenant, user, baseline, systems):
    """Caller holds the tenant lock and has freshly checked session authority."""
    expire_jobs(tenant)
    result = {"queued": 0, "existing": 0, "unavailable": 0, "results": []}
    enrollments = {row.device_uri: row for row in AgentEnrollment.objects.select_for_update().filter(
        tenant=tenant, device_uri__in=[system.source_id for system in systems],
    ).order_by("id")}
    now = timezone.now()
    pending = []
    for system in systems:
        enrollment = enrollments.get(system.source_id)
        manifest = MANIFESTS.get((baseline.id, system.operating_system_role))
        existing = BaselineScanJob.objects.filter(system=system, baseline_id=baseline.id, status__in=ACTIVE).first()
        if existing:
            result["existing"] += 1
            result["results"].append(job_projection(existing))
        elif not eligible(enrollment, system, now) or not manifest:
            result["unavailable"] += 1
        else:
            pending.append((system, enrollment, manifest))
    if BaselineScanJob.objects.filter(tenant=tenant, status__in=ACTIVE).count() + len(pending) > MAX_ACTIVE_JOBS:
        raise PublicApiError("security_scan_queue_full", status_code=409)
    for system, enrollment, manifest in pending:
        job = BaselineScanJob.objects.create(
            tenant=tenant, system=system, enrollment=enrollment, requested_by=user,
            baseline_id=baseline.id, baseline_revision=baseline.revision, catalog_revision=CATALOG_REVISION,
            manifest_sha256=manifest["manifest_sha256"], profile=system.operating_system_role,
            os_build=system.os_build, operating_system=system.operating_system, expires_at=now + QUEUE_AGE,
        )
        result["queued"] += 1
        result["results"].append(job_projection(job))
    if result["queued"]:
        AuditEvent.objects.create(
            tenant=tenant, actor=str(user.pk), action="security.scan_requested", object_type="security_baseline",
            object_id=baseline.id, outcome=AuditEvent.Outcome.SUCCEEDED,
            details={key: result[key] for key in ("queued", "existing", "unavailable")},
        )
    return result


def scope_current(job, enrollment, tenant):
    manifest = MANIFESTS.get((job.baseline_id, job.profile))
    baseline = BY_ID.get(job.baseline_id)
    system = WindowsServer.objects.select_for_update().get(pk=job.system_id)
    job.system = system
    return bool(manifest and baseline and manifest["manifest_sha256"] == job.manifest_sha256
                and job.catalog_revision == CATALOG_REVISION and job.baseline_revision == baseline.revision
                and system.tenant_id == tenant.id and job.tenant_id == tenant.id
                and job.enrollment_id == enrollment.id and system.source_id == enrollment.device_uri
                and system.inventory_source == "agent" and baseline.matches(system)
                and system.operating_system_role == job.profile and system.os_build == job.os_build
                and system.operating_system == job.operating_system
                and job.requested_by and has_tenant_permission(job.requested_by, tenant, Permission.SECURITY_SCANS_RUN))


def uuid_field(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            reject()
        return uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        reject()


def valid_value(value):
    if value is None or (type(value) is int and 0 <= value <= 0xFFFFFFFF):
        return True
    if isinstance(value, str):
        return len(value) <= 4096 and "\x00" not in value
    if isinstance(value, list):
        return len(value) <= 256 and all(isinstance(item, str) and len(item) <= 512 and "\x00" not in item for item in value)
    return False


def validate_page(job, manifest, document):
    index, count = document["page_index"], document["page_count"]
    total = len(manifest["controls"])
    if (type(index) is not int or type(count) is not int or not 0 <= index < count <= min(64, total)
            or count < (total + 31) // 32 or (job.page_count and job.page_count != count)):
        reject()
    system = document["system"]
    if not isinstance(system, dict) or set(system) != {"os_build", "product_type", "operating_system", "join_state"}:
        reject()
    if (system["os_build"] != manifest["os_build"] or system["operating_system"] != job.operating_system
            or type(system["product_type"]) is not int
            or system["product_type"] != {"client": 1, "domain-controller": 2, "server": 3}[job.profile]
            or system["join_state"] not in ("domain", "workgroup", "unknown")
            or (job.evidence_system and job.evidence_system != system)):
        reject()
    controls = document["controls"]
    if not isinstance(controls, list) or not 1 <= len(controls) <= 32:
        reject()
    known_ids = {control["id"] for control in manifest["controls"]}
    seen = set()
    for control in controls:
        if not isinstance(control, dict) or set(control) != {"control_id", "read_status", "value"}:
            reject()
        key = control["control_id"]
        if (not isinstance(key, str) or key not in known_ids or key in seen
                or not isinstance(control["read_status"], str) or control["read_status"] not in READ_STATUSES
                or not valid_value(control["value"])
                or (control["read_status"] != "ok" and control["value"] is not None)):
            reject()
        seen.add(key)
    digest = hashlib.sha256(canonical({"controls": controls, "system": system, "page_count": count})).hexdigest()
    return str(index), digest


@transaction.atomic
def security_exchange(enrollment, document):
    """Only called after Gateway mTLS validation. Recheck current DB authority."""
    common = {"type", "device_uri", "correlation_id", "schema_version", "action"}
    actions = {
        "poll": {"agent_version", "catalog_sha256"},
        "result": {"job_id", "attempt_id", "manifest_sha256", "page_index", "page_count", "system", "controls"},
        "failed": {"job_id", "attempt_id", "manifest_sha256", "error_code"},
    }
    action = document.get("action")
    if (not isinstance(action, str) or action not in actions or set(document) != common | actions[action]
            or document["type"] != "security_scan" or document["schema_version"] != "1"
            or document["device_uri"] != enrollment.device_uri
            or not isinstance(document["correlation_id"], str) or not 1 <= len(document["correlation_id"]) <= 128):
        reject()
    tenant = Tenant.objects.select_for_update().get(pk=enrollment.tenant_id)
    authenticated = enrollment
    enrollment = AgentEnrollment.objects.select_for_update().get(pk=enrollment.pk)
    now = timezone.now()
    if (tenant.status != "active" or enrollment.status != "active" or enrollment.platform != "windows"
            or enrollment.tenant_id != tenant.id or enrollment.device_uri != authenticated.device_uri
            or not enrollment.certificate_fingerprint_sha256
            or enrollment.certificate_fingerprint_sha256 != authenticated.certificate_fingerprint_sha256
            or not enrollment.certificate_not_before or not enrollment.certificate_not_after
            or not enrollment.certificate_not_before <= now < enrollment.certificate_not_after):
        reject()
    expire_jobs(tenant)
    if action == "poll":
        if not version_supported(document["agent_version"]) or document["catalog_sha256"] != CATALOG_SHA256:
            return {"status": "accepted", "security_scan": None}
        for job in BaselineScanJob.objects.select_for_update(of=("self",)).filter(enrollment=enrollment, tenant=tenant, status__in=ACTIVE).select_related(
            "system", "requested_by",
        ).order_by("requested_at", "id"):
            if not scope_current(job, enrollment, tenant) or job.attempt_count >= 3:
                finish_failed(job, "scope_changed" if job.attempt_count < 3 else "attempt_limit")
                continue
            manifest = MANIFESTS[(job.baseline_id, job.profile)]
            now = timezone.now()
            job.status = "running"
            job.attempt_id = uuid.uuid4()
            job.attempt_count += 1
            job.lease_expires_at = min(now + LEASE_AGE, job.expires_at)
            job.pages, job.page_hashes, job.evidence_system, job.page_count = {}, {}, {}, 0
            job.assessment = BaselineAssessment.objects.create(
                system=job.system, enrollment=enrollment, baseline_id=job.baseline_id,
                baseline_revision=job.baseline_revision, catalog_revision=job.catalog_revision,
                content_sha256=job.manifest_sha256, profile=job.profile, os_build=job.os_build,
                operating_system=job.operating_system, total_controls=len(manifest["controls"]),
                unknown_controls=len(manifest["controls"]), observed_at=now,
            )
            job.save()
            return {"status": "accepted", "security_scan": {
                "job_id": str(job.id), "attempt_id": str(job.attempt_id), "baseline_id": job.baseline_id,
                "profile": job.profile, "manifest_sha256": job.manifest_sha256,
                "total_controls": len(manifest["controls"]), "expires_at": job.lease_expires_at.isoformat(),
            }}
        return {"status": "accepted", "security_scan": None}

    job = BaselineScanJob.objects.select_for_update(of=("self",)).filter(
        pk=uuid_field(document["job_id"]), tenant=tenant, enrollment=enrollment,
    ).select_related("system", "requested_by", "assessment").first()
    if (not job or job.attempt_id != uuid_field(document["attempt_id"])
            or document["manifest_sha256"] != job.manifest_sha256):
        reject()
    if not scope_current(job, enrollment, tenant):
        if job.status in ACTIVE:
            finish_failed(job, "scope_changed")
        return {"status": "accepted", "complete": True}
    if action == "failed":
        if document["error_code"] not in ("collection_failed", "unsupported_manifest", "cancelled", "scope_changed"):
            reject()
        if job.status == "running":
            finish_failed(job, document["error_code"])
        elif job.status != "failed" or job.error_code != document["error_code"]:
            reject()
        return {"status": "accepted", "complete": True}
    manifest = MANIFESTS[(job.baseline_id, job.profile)]
    key, digest = validate_page(job, manifest, document)
    if key in job.page_hashes:
        if job.page_hashes[key] != digest:
            reject()
        return {"status": "accepted", "complete": job.status == "completed"}
    if job.status != "running":
        reject()
    other_ids = {control["control_id"] for page in job.pages.values() for control in page}
    if other_ids.intersection(control["control_id"] for control in document["controls"]):
        reject()
    job.pages[key] = document["controls"]
    if len(canonical(job.pages)) > 2 * 1024 * 1024:
        reject()
    job.page_hashes[key] = digest
    job.page_count = document["page_count"]
    job.evidence_system = document["system"]
    complete = len(job.pages) == job.page_count
    if complete:
        observations = {control["control_id"]: control for page in job.pages.values() for control in page}
        if set(observations) != {control["id"] for control in manifest["controls"]}:
            reject()
        result = evaluate(manifest, observations, job.evidence_system)
        for field, value in result.items():
            setattr(job.assessment, field, value)
        job.assessment.observed_at = timezone.now()
        job.assessment.save()
        job.status, job.completed_at, job.pages = "completed", timezone.now(), {}
        AuditEvent.objects.create(
            tenant=tenant, actor=str(enrollment.id), action="security.scan_completed", object_type="security_scan",
            object_id=str(job.id), outcome=AuditEvent.Outcome.SUCCEEDED,
            details={key: result[key] for key in ("total_controls", "passed_controls", "failed_controls", "unknown_controls")},
        )
    job.save()
    return {"status": "accepted", "complete": complete}
