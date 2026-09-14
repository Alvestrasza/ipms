# File Name: services.py
# Version: v0.2.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Atomic WSUS ingestion and conservative comparison with tenant inventory.
import hashlib
import hmac
import json
from collections import Counter, defaultdict
from datetime import timedelta

from django.core.serializers.json import DjangoJSONEncoder
from django.db import transaction
from django.db.models import OuterRef, Subquery
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import AuthenticationFailed

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import SoftwareInventorySnapshot, WindowsServer
from ipms.apps.tenancy.models import Tenant
from .contract import STATES, normalized_fqdn, update_key
from .models import UpdateSource, WsusComputerReport, WsusSnapshot


def audit(source, actor, action, **details):
    AuditEvent.objects.create(tenant=source.tenant, actor=actor, action=action,
                             object_type="update_source", object_id=str(source.id),
                             outcome="succeeded", details=details)


@transaction.atomic
def ingest(auth_source, data):
    # Lock tenant before source, consistently with configuration/revocation.
    tenant = Tenant.objects.select_for_update().get(id=auth_source.tenant_id)
    source = UpdateSource.objects.select_for_update().get(id=auth_source.id)
    if tenant.status != "active" or not source.enabled or not hmac.compare_digest(source.token_hash, auth_source.token_hash):
        raise AuthenticationFailed("Source authority was withdrawn.")
    if data["scope"] != source.scope:
        raise PublicApiError("wsus_scope_mismatch")
    canonical = json.dumps(data, cls=DjangoJSONEncoder, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    prior = source.snapshots.filter(snapshot_id=data["snapshot_id"]).first()
    if prior:
        if prior.digest != digest:
            raise PublicApiError("wsus_snapshot_conflict", status_code=409)
        return prior, False
    if source.wsus_changed_at and data["observed_at"] <= source.wsus_changed_at:
        raise PublicApiError("wsus_snapshot_predates_configuration", status_code=409)
    latest = source.current_snapshot if source.current_snapshot_id else source.snapshots.order_by("-observed_at").first()
    if latest and data["observed_at"] <= latest.observed_at:
        raise PublicApiError("wsus_snapshot_out_of_order", status_code=409)
    if source.snapshots.count() >= 10000:
        raise PublicApiError("wsus_receipt_limit", status_code=409)
    # Re-serialize only validated metadata; never store raw provider responses.
    document = json.loads(canonical)
    snapshot = WsusSnapshot.objects.create(
        source=source, snapshot_id=data["snapshot_id"], digest=digest,
        observed_at=data["observed_at"], updates=document["updates"],
        update_count=len(data["updates"]),
        computer_count=len(data["computers"]),
    )
    WsusComputerReport.objects.bulk_create([
        WsusComputerReport(snapshot=snapshot, computer_id=c["computer_id"], fqdn=c["fqdn"],
                           reported_at=c["reported_at"], updates=doc["updates"])
        for c, doc in zip(data["computers"], document["computers"], strict=True)
    ])
    source.current_snapshot = snapshot
    source.save(update_fields=("current_snapshot",))
    audit(source, f"wsus-source:{source.id}", "updates.wsus.snapshot_received",
          snapshot_id=str(snapshot.snapshot_id), update_count=len(snapshot.updates),
          computer_count=snapshot.computer_count)
    # Retain recent evidence, with a hard per-source storage bound.
    keep = list(source.snapshots.order_by("-observed_at").values_list("id", flat=True)[:3])
    # Keep compact identity/digest receipts so a pruned snapshot ID cannot be reused.
    pruned = source.snapshots.exclude(id__in=keep)
    WsusComputerReport.objects.filter(snapshot__in=pruned).delete()
    pruned.exclude(updates=[]).update(updates=[])
    return snapshot, True


def snapshot_projection(snapshot):
    if not snapshot:
        return None
    return {"id": str(snapshot.snapshot_id), "observed_at": snapshot.observed_at,
            "received_at": snapshot.received_at, "update_count": snapshot.update_count,
            "computer_count": snapshot.computer_count}


def source_projection(source):
    snap = source.current_snapshot
    return {"id": str(source.id), "name": source.name, "scope": source.scope,
            "wsus_host": source.wsus_host, "wsus_port": source.wsus_port,
            "wsus_use_ssl": source.wsus_use_ssl,
            "enabled": source.enabled, "created_at": source.created_at,
            "last_received_at": snap.received_at if snap else None,
            "last_observed_at": snap.observed_at if snap else None}


def stale(value):
    return value is None or value < timezone.now() - timedelta(hours=24)


class Comparison:
    def __init__(self, source):
        self.source = source
        self.snapshot = source.current_snapshot
        self.servers = list(WindowsServer.objects.filter(
            tenant=source.tenant, operating_system_role__in=("server", "domain-controller")
        ).only("id", "hostname", "fqdn", "discovered_at", "source_id", "inventory_source").order_by("hostname", "id"))
        self.server_counts = Counter(normalized_fqdn(s.fqdn) for s in self.servers)
        self.reports = defaultdict(list)
        if self.snapshot:
            for report in self.snapshot.computers.all():
                self.reports[report.fqdn].append(report)
        self.catalog = self.snapshot.updates if self.snapshot else []
        self.agent_by_uri = {}
        latest = SoftwareInventorySnapshot.objects.filter(
            tenant=source.tenant, enrollment_id=OuterRef("enrollment_id"),
            platform="windows", status="completed"
        ).order_by("-completed_at", "-created_at", "-id").values("pk")[:1]
        snapshots = SoftwareInventorySnapshot.objects.filter(
            pk=Subquery(latest),
            tenant=source.tenant, platform="windows", status="completed",
            enrollment__status="active", enrollment__tenant=source.tenant,
            enrollment__device_uri__in=[s.source_id for s in self.servers if s.inventory_source == "agent"],
        ).select_related("enrollment").order_by("-completed_at", "-created_at")
        for snapshot in snapshots:
            self.agent_by_uri.setdefault(snapshot.enrollment.device_uri, snapshot)

    def match(self, server):
        if not self.snapshot:
            return "no-data", None
        fqdn = normalized_fqdn(server.fqdn)
        reports = self.reports.get(fqdn, [])
        if not fqdn or not reports:
            return "unmatched", None
        if self.server_counts[fqdn] != 1 or len(reports) != 1:
            return "ambiguous", None
        return "matched", reports[0]

    def agent_evidence(self, server):
        snapshot = self.agent_by_uri.get(server.source_id) if server.inventory_source == "agent" else None
        return snapshot.windows_update_evidence if snapshot else {}

    def details(self, report, evidence=None):
        states = {update_key(u): u["state"] for u in report.updates} if report else {}
        evidence = evidence or {}
        installed = {update_key(u) for u in evidence.get("updates", [])} if evidence.get("status") == "collected" else set()
        known_ids = {key[0] for key in installed}
        return [{**u, "state": states.get(update_key(u), "unknown"),
                 "agent_state": ("installed" if update_key(u) in installed else
                                 "revision-mismatch" if str(u["update_id"]) in known_ids else "unknown"),
                 "agent_observed_at": evidence.get("observed_at")} for u in self.catalog]

    def row(self, server):
        match, report = self.match(server)
        counts = dict.fromkeys(STATES, 0)
        for update in self.details(report):
            counts[update["state"]] += 1
        status = "unknown"
        if not self.snapshot:
            status = "no-data"
        elif match != "matched":
            status = "unknown"
        elif not self.source.enabled or stale(self.snapshot.observed_at) or stale(report.reported_at):
            status = "stale"
        elif counts["failed"]:
            status = "failed"
        elif counts["installed_pending_reboot"]:
            status = "reboot-required"
        elif counts["not_installed"] or counts["downloaded"]:
            status = "missing"
        elif self.catalog and not counts["unknown"]:
            status = "current"
        agent = self.agent_by_uri.get(server.source_id) if server.inventory_source == "agent" else None
        evidence = self.agent_evidence(server)
        details = self.details(report, evidence)
        local_counts = Counter(u["agent_state"] for u in details)
        return {"server_id": str(server.id), "hostname": server.hostname, "fqdn": server.fqdn,
                "inventory_at": server.discovered_at, "inventory_stale": stale(server.discovered_at),
                "match_status": match, "wsus_status": status,
                "reported_at": report.reported_at if report else None, "counts": counts,
                "agent_evidence": {"status": evidence.get("status", "not-reported"),
                                   "observed_at": evidence.get("observed_at"),
                                   "stale": stale(parse_datetime(evidence["observed_at"])) if evidence.get("observed_at") else True,
                                   "installed_matches": local_counts["installed"],
                                   "revision_mismatches": local_counts["revision-mismatch"],
                                   "unknown": local_counts["unknown"]},
                "agent": {"scan_status": agent.update_scan_status,
                          "last_scan_at": agent.last_update_scan_at,
                          "reboot_required": agent.reboot_required,
                          "updates_available": agent.updates_available} if agent else None}
