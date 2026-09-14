# File Name: services.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant-bound baseline applicability, evidence freshness and compliance calculations.
from collections import Counter
from datetime import timedelta

from django.db.models import OuterRef, Subquery
from django.utils import timezone

from ipms.apps.discovery.models import WindowsServer
from .catalog import BASELINES, CATALOG_REVISION
from .models import BaselineAssessment, BaselinePreference

MAX_AGE = timedelta(hours=24)
STATUSES = ("compliant", "non_compliant", "unknown", "error", "stale")


class BaselineOverview:
    def __init__(self, tenant):
        self.now = timezone.now()
        self.preferences = {row.baseline_id: row for row in BaselinePreference.objects.filter(tenant=tenant)}
        self.systems = list(WindowsServer.objects.filter(tenant=tenant).only(
            "id", "hostname", "fqdn", "operating_system", "os_build", "operating_system_role",
            "server_type", "source_id", "inventory_source", "tenant_id",
        ).order_by("hostname", "id"))
        # Select latest *attempt*, including incomplete/old-revision attempts.
        # Selecting only successful results would conceal a later failed scan.
        latest = BaselineAssessment.objects.filter(
            system_id=OuterRef("system_id"), baseline_id=OuterRef("baseline_id"),
        ).order_by("-observed_at", "-created_at", "-id").values("pk")[:1]
        records = BaselineAssessment.objects.filter(
            system__tenant=tenant, enrollment__tenant=tenant, pk=Subquery(latest),
        ).select_related("enrollment").defer("findings")
        self.records = {(record.system_id, record.baseline_id): record for record in records}

    def result(self, baseline, system):
        record = self.records.get((system.id, baseline.id))
        status, reason = "unknown", "not_assessed"
        observed_at = record.observed_at if record else None
        if record:
            identity = record.enrollment
            if (identity.status != "active" or identity.platform != "windows"
                or system.inventory_source != "agent" or system.source_id != identity.device_uri):
                reason = "agent_unavailable"
            elif record.baseline_revision != baseline.revision or record.catalog_revision != CATALOG_REVISION:
                reason = "baseline_changed"
            elif not self.content_current(record):
                reason = "baseline_changed"
            elif (record.profile != system.operating_system_role or record.os_build != system.os_build
                  or record.operating_system != system.operating_system):
                reason = "system_changed"
            elif record.observed_at > self.now:
                reason = "partial"
            elif record.observed_at <= self.now - MAX_AGE:
                status, reason = "stale", "expired"
            elif record.error_code:
                status, reason = "error", "assessment_error"
            elif (
                not record.scope_verified or record.total_controls <= 0 or record.unknown_controls
                or record.passed_controls + record.failed_controls <= 0
                or record.total_controls != record.passed_controls + record.failed_controls + record.unknown_controls + record.not_applicable_controls
            ):
                reason = "partial"
                # A proven deviation already disproves full compliance even
                # when other controls remain unknown. Coverage stays incomplete.
                if record.failed_controls:
                    status = "non_compliant"
            else:
                status = "non_compliant" if record.failed_controls else "compliant"
                reason = "complete"
        return {
            "id": str(system.id), "hostname": system.hostname, "fqdn": system.fqdn,
            "operating_system": system.operating_system, "os_build": system.os_build,
            "operating_system_role": system.operating_system_role, "server_type": system.server_type,
            "status": status, "reason": reason,
            "assessed_at": observed_at.isoformat() if observed_at else None,
            "assessment_id": str(record.id) if record else None,
            "controls": {"total": record.total_controls, "passed": record.passed_controls,
                         "failed": record.failed_controls, "unknown": record.unknown_controls} if record else None,
        }

    @staticmethod
    def content_current(record):
        from .content import MANIFESTS
        manifest = MANIFESTS.get((record.baseline_id, record.profile))
        return bool(manifest and manifest["manifest_sha256"] == record.content_sha256
                    and len(manifest["controls"]) == record.total_controls)

    def systems_for(self, baseline):
        return [self.result(baseline, system) for system in self.systems if baseline.matches(system)]

    def baseline(self, baseline, rows=None):
        rows = self.systems_for(baseline) if rows is None else rows
        counts = Counter(row["status"] for row in rows)
        assessed = sum(row["reason"] == "complete" for row in rows)
        classified = counts["compliant"] + counts["non_compliant"]
        total = len(rows)
        complete_times = [row["assessed_at"] for row in rows if row["reason"] == "complete"]
        return {
            **baseline.projection(),
            "summary": {
                "applicable": total, **{key: counts[key] for key in STATUSES}, "assessed": assessed,
                "compliance_percent": round(100 * counts["compliant"] / total, 1) if classified else None,
                "coverage_percent": round(100 * assessed / total, 1) if total else None,
                "last_assessed_at": max(complete_times, default=None),
            },
        }

    def catalog(self, target="all", *, include_hidden=False):
        roles = Counter(system.operating_system_role for system in self.systems)
        selected = [baseline for baseline in BASELINES if target == "all" or baseline.target == target]
        hidden = {key for key, value in self.preferences.items() if value.hidden}
        return {
            "catalog_revision": CATALOG_REVISION, "generated_at": self.now.isoformat(),
            "hidden_count": sum(baseline.id in hidden for baseline in selected),
            "capabilities": {"assessment": True, "deployment": False, "collections": False},
            "inventory": {
                "total": len(self.systems), "servers": roles["server"] + roles["domain-controller"],
                "clients": roles["client"], "unclassified": sum(value for key, value in roles.items() if key not in ("server", "domain-controller", "client")),
                "unmatched": sum(not any(baseline.matches(system) for baseline in BASELINES) for system in self.systems),
            },
            "results": [self.baseline(baseline) for baseline in selected if include_hidden or baseline.id not in hidden],
        }
