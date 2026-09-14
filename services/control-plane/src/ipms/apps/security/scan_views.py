# File Name: scan_views.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant-authorized read-only scan requests, job progress and paginated findings.
import uuid

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import NotFound, ParseError, PermissionDenied
from rest_framework.response import Response

from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .administration import SmallJSONParser
from .catalog import BY_ID
from .models import BaselineAssessment, BaselinePreference, BaselineScanJob
from .scans import ACTIVE, expire_jobs, job_projection, queue_scans
from .services import BaselineOverview
from .views import SecurityReadView, query


def visible_baseline(tenant, baseline_id):
    baseline = BY_ID.get(baseline_id)
    if not baseline or BaselinePreference.objects.filter(tenant=tenant, baseline_id=baseline_id, hidden=True).exists():
        raise NotFound("Baseline not found.")
    return baseline


class ScanJSONParser(SmallJSONParser):
    # Up to 250 UUIDs; inherited duplicate/type checking remains strict.
    maximum_bytes = 16384


class BaselineScansView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    parser_classes = (ScanJSONParser,)
    http_method_names = ("get", "post", "head", "options")

    @transaction.atomic
    def get(self, request, baseline_id):
        query(request, set())
        tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        request.tenant = tenant
        self.check_permissions(request)
        visible_baseline(tenant, baseline_id)
        expire_jobs(tenant)
        jobs = BaselineScanJob.objects.filter(tenant=tenant, baseline_id=baseline_id).select_related("system")
        return Response({"count": jobs.count(), "active": jobs.filter(status__in=ACTIVE).count(),
                         "results": [job_projection(job) for job in jobs[:25]]})

    @transaction.atomic
    def post(self, request, baseline_id):
        query(request, set())
        tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        request.tenant = tenant
        self.check_permissions(request)
        if not has_tenant_permission(request.user, tenant, Permission.SECURITY_SCANS_RUN):
            raise PermissionDenied()
        baseline = visible_baseline(tenant, baseline_id)
        data = request.data
        if not isinstance(data, dict) or set(data) - {"system_ids"}:
            raise ParseError("Only an optional system_ids selection is accepted.")
        systems = WindowsServer.objects.select_for_update().filter(tenant=tenant).order_by("id")
        if "system_ids" in data:
            ids = data["system_ids"]
            if not isinstance(ids, list) or not 1 <= len(ids) <= 250:
                raise ParseError("Select between one and 250 systems.")
            try:
                if any(not isinstance(item, str) or str(uuid.UUID(item)) != item for item in ids) or len(set(ids)) != len(ids):
                    raise ValueError()
            except (ValueError, TypeError, AttributeError) as exc:
                raise ParseError("Invalid system selection.") from exc
            systems = list(systems.filter(pk__in=ids))
            if len(systems) != len(ids) or any(not baseline.matches(system) for system in systems):
                raise NotFound("System selection not found.")
        else:
            systems = [system for system in systems if baseline.matches(system)]
        if len(systems) > 250:
            raise PublicApiError("security_scan_scope_too_large", status_code=409)
        return Response(queue_scans(tenant, request.user, baseline, systems), status=202)


class BaselineFindingsView(SecurityReadView):
    def get(self, request, baseline_id, system_id):
        query(request, {"page"})
        baseline = visible_baseline(request.tenant, baseline_id)
        system = get_object_or_404(WindowsServer, pk=system_id, tenant=request.tenant)
        if not baseline.matches(system):
            raise NotFound("System not found.")
        raw = request.query_params.get("page", "1")
        if not raw.isascii() or not raw.isdecimal() or not 1 <= len(raw) <= 7 or int(raw) < 1:
            raise ParseError("A positive page number is required.")
        page = int(raw)
        record = BaselineAssessment.objects.filter(
            system=system, enrollment__tenant=request.tenant, baseline_id=baseline_id,
        ).first()
        current = BaselineOverview(request.tenant).result(baseline, system)
        findings = record.findings if record else []
        return Response({
            "assessment_id": str(record.id) if record else None,
            "assessed_at": record.observed_at.isoformat() if record else None,
            "scope_verified": bool(record and record.scope_verified and current["reason"] == "complete"),
            "status": current["status"], "reason": current["reason"],
            **{key: getattr(record, key) if record else 0 for key in (
                "total_controls", "passed_controls", "failed_controls", "unknown_controls",
            )},
            "page": page, "page_size": 50, "count": len(findings),
            "results": findings[(page - 1) * 50:page * 50],
        })
