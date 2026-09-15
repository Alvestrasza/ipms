# File Name: applications.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant-bound computer GPO application by active baseline family, independent of compliance.
from collections import Counter, defaultdict
from datetime import timedelta

from django.core.exceptions import ValidationError

from ipms.apps.agent_pki.group_policy import (
    GROUP_POLICY_CLOCK_SKEW, canonical_domain, canonical_guid, utc_timestamp, validate_group_policy,
    watermark_matches_report,
)
from ipms.apps.agent_pki.models import AgentEnrollment
from .gpo_content import COMPONENTS, PROFILE_COMPONENTS
from .models import GpoImportJob

MAX_APPLICATION_AGE = timedelta(hours=24)
APPLICATION_STATUSES = ("applied", "not_applied", "partial", "unknown")
_CONTEXT_FIELDS = {"enrollment_id", "domain_name", "operating_system_role", "os_build", "operating_system", "received_at"}
_ASSIGNMENT_FIELDS = {
    "schema", "job_id", "operation", "domain_dns_name", "domain_guid", "forest_dns_name",
    "executor_dc_fqdn", "scope_id", "scope_revision", "target_tier", "baseline_id", "profile",
    "backup_id", "artifact_sha256", "pilot_display_name", "expires_at", "input_digest",
}


class BaselineApplications:
    def __init__(self, tenant, systems, now):
        self.tenant_id, self.systems, self.now = tenant.id, systems, now
        self.enrollments = {row.device_uri: row for row in AgentEnrollment.objects.filter(
            tenant=tenant, platform="windows", status="active",
        ).only("id", "device_uri")}
        self.reports = {system.id: self._report(system) for system in systems}
        self.bindings = self._bindings(tenant)

    def _fresh(self, observed):
        return self.now - MAX_APPLICATION_AGE < observed <= self.now + GROUP_POLICY_CLOCK_SKEW

    def _report(self, system):
        snapshot = system.detail_snapshot
        enrollment = self.enrollments.get(system.source_id)
        if system.inventory_source != "agent" or not enrollment or not isinstance(snapshot, dict):
            return None
        context = snapshot.get("group_policy_context")
        if not isinstance(context, dict) or set(context) != _CONTEXT_FIELDS or any((
            context["enrollment_id"] != str(enrollment.id),
            context["domain_name"] != system.domain_name,
            context["operating_system_role"] != system.operating_system_role,
            context["os_build"] != system.os_build,
            context["operating_system"] != system.operating_system,
        )):
            return None
        try:
            report = validate_group_policy(snapshot.get("group_policy"), inventory_domain=system.domain_name, now=self.now)
            if not watermark_matches_report(snapshot, report, context):
                return None
            observed, received = utc_timestamp(report["observed_at"]), utc_timestamp(context["received_at"])
            if (report["status"] != "collected" or not self._fresh(observed)
                    or received > self.now + GROUP_POLICY_CLOCK_SKEW
                    or observed > received + GROUP_POLICY_CLOCK_SKEW):
                return None
            return {**report, "observed": observed, "by_guid": {row["guid"]: row for row in report["gpos"]}}
        except (ValidationError, ValueError, TypeError):
            return None

    def _trusted_component(self, job):
        # A staged receipt binds an exact imported component to an AD GUID.
        # It is not application evidence: these GPOs start disabled/unlinked.
        from .gpo_jobs import DEFAULT_GPO_IDS, digest
        try:
            assigned = job.assignment
            if (job.status != "staged" or job.error_code or not job.claimed_at or not job.completed_at
                    or not job.requested_at <= job.claimed_at <= job.completed_at <= self.now
                    or job.gpo_guid in DEFAULT_GPO_IDS or canonical_guid(job.gpo_guid) != job.gpo_guid
                    or canonical_guid(job.domain_guid) != job.domain_guid
                    or job.domain.tenant_id != self.tenant_id or job.enrollment.tenant_id != self.tenant_id
                    or job.system.tenant_id != self.tenant_id or job.enrollment.platform != "windows"
                    or job.system.inventory_source != "agent" or job.system.source_id != job.enrollment.device_uri
                    or not isinstance(assigned, dict) or set(assigned) != _ASSIGNMENT_FIELDS
                    or type(assigned["schema"]) is not int or assigned["schema"] != 1
                    or assigned["operation"] != "create_unlinked_pilot"
                    or assigned["job_id"] != str(job.id) or assigned["scope_id"] != str(job.domain_id)
                    or type(assigned["scope_revision"]) is not int or assigned["scope_revision"] < 1
                    or type(assigned["target_tier"]) is not int or assigned["target_tier"] not in (0, 1, 2)
                    or assigned["domain_guid"] != job.domain_guid
                    or canonical_domain(assigned["domain_dns_name"]) != job.domain.domain_name
                    or assigned["pilot_display_name"] != job.pilot_display_name
                    or assigned["input_digest"] != job.input_digest
                    or digest({key: value for key, value in assigned.items() if key != "input_digest"}) != job.input_digest
                    or utc_timestamp(assigned["expires_at"]) <= job.claimed_at):
                return None
            canonical_domain(assigned["forest_dns_name"])
            canonical_domain(assigned["executor_dc_fqdn"])
            component = COMPONENTS.get((assigned["baseline_id"], assigned["backup_id"]))
            if (not component or component["scope"] != "machine"
                    or component["artifact_sha256"] != assigned["artifact_sha256"]
                    or assigned["backup_id"] not in PROFILE_COMPONENTS.get((assigned["baseline_id"], assigned["profile"]), ())):
                return None
            expected = {
                "computer_enabled": False, "user_enabled": False, "unlinked": True,
                "domain_dns_name": assigned["domain_dns_name"], "domain_guid": job.domain_guid,
                "dc_fqdn": assigned["executor_dc_fqdn"],
            }
            evidence = job.result_evidence
            if (not isinstance(evidence, dict) or evidence != expected or set(evidence) != set(expected)
                    or any(type(evidence[key]) is not bool for key in ("computer_enabled", "user_enabled", "unlinked"))
                    or digest({"status": "staged", "result_code": "gpo_staged_unlinked",
                               "gpo_guid": job.gpo_guid, "evidence": evidence}) != job.result_digest):
                return None
            return (job.domain_guid, assigned["domain_dns_name"], assigned["baseline_id"], assigned["backup_id"])
        except (ValueError, TypeError, AttributeError, KeyError, UnicodeError):
            return None

    def _bindings(self, tenant):
        candidates = defaultdict(list)
        for job in GpoImportJob.objects.filter(tenant=tenant).exclude(gpo_guid="").select_related(
            "domain", "enrollment", "system",
        ).only(
            "id", "domain_id", "enrollment_id", "system_id", "domain_guid", "status", "error_code",
            "requested_at", "claimed_at", "completed_at", "gpo_guid", "assignment", "input_digest",
            "result_digest", "result_evidence", "pilot_display_name",
            "domain__tenant_id", "domain__domain_name", "enrollment__tenant_id",
            "enrollment__platform", "enrollment__device_uri", "system__tenant_id",
            "system__inventory_source", "system__source_id",
        ).order_by("-requested_at", "-id"):
            candidates[(job.domain_guid, job.gpo_guid)].append(job)
        bindings = defaultdict(list)
        for jobs in candidates.values():
            latest = jobs[0]
            identity = self._trusted_component(latest)
            if identity is None:
                continue
            # Never select only successful jobs: a newer failed/ambiguous write
            # must not resurrect an older association for the same AD identity.
            # Conflicting component associations or later writes are ambiguous.
            ambiguous = any(
                self._trusted_component(older) != identity
                or not isinstance(older.assignment, dict)
                or any(older.assignment.get(key) != latest.assignment[key]
                       for key in ("domain_dns_name", "baseline_id", "backup_id", "artifact_sha256"))
                or (older.claimed_at is not None and older.claimed_at > latest.completed_at)
                or (older.completed_at is not None and older.completed_at > latest.completed_at)
                for older in jobs[1:]
            )
            if not ambiguous:
                bindings[identity].append((latest.gpo_guid, latest.completed_at))
        return bindings

    def _component_state(self, report, baseline_id, backup_id):
        bindings = self.bindings.get((report["domain_guid"], report["domain_dns"], baseline_id, backup_id), ())
        if not bindings:
            return "unknown"
        states = []
        for guid, imported_at in bindings:
            row = report["by_guid"].get(guid)
            if report["observed"] < imported_at:
                states.append("unknown")
            elif row is None or row["status"] == "excluded":
                states.append("not_applied")
            elif row["status"] == "applied":
                processed = utc_timestamp(row["processed_at"])
                states.append("applied" if self._fresh(processed) and processed >= imported_at else "unknown")
            else:
                states.append("unknown")
        if "applied" in states:
            return "applied"
        return "not_applied" if all(state == "not_applied" for state in states) else "unknown"

    def _baseline_state(self, system, baseline):
        report = self.reports[system.id]
        if report is None:
            return "unknown"
        expected = [backup_id for backup_id in PROFILE_COMPONENTS.get((baseline.id, system.operating_system_role), ())
                    if COMPONENTS.get((baseline.id, backup_id), {}).get("scope") == "machine"]
        if not expected:
            return "unknown"
        states = [self._component_state(report, baseline.id, backup_id) for backup_id in expected]
        if all(state == "applied" for state in states):
            return "applied"
        if "applied" in states:
            return "partial"
        return "not_applied" if all(state == "not_applied" for state in states) else "unknown"

    def groups(self, baselines):
        families = defaultdict(list)
        for baseline in baselines:
            projection = baseline.projection()
            families[(projection["provider"], projection["platform"], baseline.target)].append(baseline)
        groups = []
        for (provider, platform, target), members in families.items():
            roles = ("server", "domain-controller") if target == "server" else ("client",)
            population = [system for system in self.systems if platform == "windows" and system.operating_system_role in roles]
            counts = Counter()
            for system in population:
                states = [self._baseline_state(system, baseline) for baseline in members if baseline.matches(system)]
                if "applied" in states:
                    status = "applied"
                elif "partial" in states:
                    status = "partial"
                elif states and all(state == "not_applied" for state in states):
                    status = "not_applied"
                else:
                    status = "unknown"
                counts[status] += 1
            total = len(population)
            known = total - counts["unknown"]
            groups.append({
                "id": f"{provider}:{platform}:{target}", "provider": provider,
                "platform": platform, "target": target, "baseline_ids": [item.id for item in members],
                "summary": {"applicable": total, **{status: counts[status] for status in APPLICATION_STATUSES},
                            "application_percent": round(100 * counts["applied"] / total, 1) if known else None},
            })
        return groups
