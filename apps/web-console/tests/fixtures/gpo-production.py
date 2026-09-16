# File Name: gpo-production.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Synthetic native GPO observations in the explicit isolated browser database; never contacts AD.
import copy
import json
import os
import sys
import uuid
from datetime import timedelta
from pathlib import Path

if (os.environ.get("DJANGO_SETTINGS_MODULE") != "ipms_control_plane.settings.e2e"
        or not os.environ.get("IPMS_E2E_DATABASE")
        or Path(os.environ["IPMS_E2E_DATABASE"]).name != "fixture.sqlite3"):
    raise RuntimeError("Explicit isolated browser fixture settings and database are required.")
import django
django.setup()

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.security.catalog import BASELINES
from ipms.apps.security.gpo_jobs import security_gpo_exchange, digest
from ipms.apps.security.models import DomainSecuritySettings, GpoDomainAuthorization, GpoExecutorReport, GpoImportJob, GpoReconciliation, ManagedGpoPolicy
from ipms.apps.tenancy.models import Tenant

tenant = Tenant.objects.get(slug="console-e2e")
mode = sys.argv[1]


def exchange(job, action, **fields):
    return security_gpo_exchange(job.enrollment, {
        "type": "security_gpo", "schema_version": "1", "device_uri": job.enrollment.device_uri,
        "correlation_id": "isolated-production-gpo", "action": action,
        "job_id": str(job.pk), "input_digest": job.input_digest, **fields,
    })


def observe(job):
    assignment = job.assignment
    policy = ManagedGpoPolicy.objects.get(pk=assignment["managed_id"], tenant=tenant)
    history = list(GpoImportJob.objects.filter(tenant=tenant, assignment__managed_id=str(policy.pk),
        status__in=("staged", "linked", "activated", "deactivated")).order_by("-completed_at"))
    prior = copy.deepcopy(history[0].result_evidence["state"]) if history else None
    state = {"schema": 1, "gpo": prior["gpo"] if prior else None, "ous": [], "name_available": True}
    for dn in assignment["target_ous"]:
        old = next((copy.deepcopy(ou) for row in history for ou in row.result_evidence["state"]["ous"]
                    if ou["dn"] == dn), None)
        state["ous"].append(old or {"dn": dn, "guid": assignment["domain_guid"] if dn.startswith("DC=") else str(uuid.uuid5(uuid.NAMESPACE_DNS, dn)),
            "usn": "100", "blocked": False, "links": [], "inherited_links": []})
    return state


with transaction.atomic():
    if mode == "setup":
        suffix = uuid.uuid4().hex[:12]
        domain_name = f"production-{suffix}.example.invalid"
        # Reuse an unclassified fixture DC so baseline fleet denominators remain unchanged.
        system = WindowsServer.objects.get(tenant=tenant, hostname="gpo-ui-dc")
        system.domain_name, system.fqdn, system.agent_version = domain_name, f"gpo-ui-dc.{domain_name}", "0.2.37"
        system.save(update_fields=("domain_name", "fqdn", "agent_version"))
        enrollment = AgentEnrollment.objects.get(tenant=tenant, device_uri=system.source_id)
        enrollment.last_heartbeat_at = timezone.now()
        enrollment.certificate_not_before = timezone.now() - timedelta(days=1)
        enrollment.certificate_not_after = timezone.now() + timedelta(days=1)
        enrollment.save()
        GpoExecutorReport.objects.update_or_create(enrollment=enrollment, defaults={
            "agent_version": "0.2.37", "domain_dns_name": domain_name, "domain_guid": str(uuid.uuid4()),
            "forest_dns_name": domain_name, "dc_fqdn": system.fqdn, "role": "writable-domain-controller",
            "gpmc_available": True, "result_code": "ready_for_approval", "observed_at": timezone.now()})
        suffix_dn = ",".join("DC=" + part for part in domain_name.split("."))
        domain = DomainSecuritySettings.objects.create(tenant=tenant, domain_name=domain_name,
            tier_ous={str(tier): [f"OU=Tier{tier},{suffix_dn}"] for tier in range(3)},
            gpo_name_template="{tier}-{scope}-{target}-{purpose}_V{version}", baseline_order=[item.id for item in BASELINES])
        actor = get_user_model().objects.get(username="e2e-admin")
        GpoDomainAuthorization.objects.create(domain=domain, grants=[{"user_id": str(actor.pk), "tiers": ["0", "1", "2"]}])
        result = {"domain_id": str(domain.pk), "domain_name": domain_name, "system_id": str(system.pk)}
    elif mode in ("agent-035", "agent-037", "agent-043"):
        domain = DomainSecuritySettings.objects.get(pk=uuid.UUID(sys.argv[2]), tenant=tenant,
            domain_name__startswith="production-", domain_name__endswith=".example.invalid")
        system = WindowsServer.objects.get(tenant=tenant, domain_name=domain.domain_name, hostname="gpo-ui-dc")
        system.agent_version = {"agent-035": "0.2.35", "agent-037": "0.2.37", "agent-043": "0.2.43"}[mode]
        system.save(update_fields=("agent_version",))
        GpoExecutorReport.objects.filter(enrollment__device_uri=system.source_id).update(agent_version=system.agent_version)
        result = {"version": system.agent_version}
    elif mode in ("fail", "reconcile"):
        job = GpoImportJob.objects.get(pk=uuid.UUID(sys.argv[2]), tenant=tenant,
            domain__domain_name__startswith="production-", domain__domain_name__endswith=".example.invalid")
        if mode == "fail":
            if job.assignment.get("operation") != "inspect_managed_gpo" or job.claimed_at:
                raise RuntimeError("Only an unclaimed synthetic inspection may fail here.")
        else:
            if not job.approved_at or job.status != "queued":
                raise RuntimeError("Synthetic write failure requires explicit Portal approval.")
            claim = exchange(job, "claim")["gpo_claim"]
            if not claim["authorized"] or claim["mode"] != "execute":
                raise RuntimeError("Synthetic write claim was not authorized.")
        exchange(job, "result", status="failed", result_code="gpo_provider_failed",
            gpo_guid=str(uuid.uuid5(uuid.NAMESPACE_DNS, "synthetic-partial-" + str(job.pk))) if mode == "reconcile" else None, evidence=None)
        job.refresh_from_db()
        result = {"job_id": str(job.pk), "status": job.status}
    elif mode in ("observe-reconciliation", "observe-unverifiable", "ack-reconciliation", "drift-reconciliation"):
        job = GpoImportJob.objects.get(pk=uuid.UUID(sys.argv[2]), tenant=tenant,
            domain__domain_name__startswith="production-", domain__domain_name__endswith=".example.invalid")
        record = GpoReconciliation.objects.get(job=job)
        a = job.assignment
        report = GpoExecutorReport.objects.get(enrollment=job.enrollment)
        executor = {"schema": 1, **{key: getattr(report, key) for key in
            ("domain_dns_name", "domain_guid", "forest_dns_name", "dc_fqdn", "role", "gpmc_available", "result_code")}}
        control = exchange(job, "reconciliation_poll", journal_sha256="d" * 64, agent_version="0.2.37", executor=executor)["reconciliation"]
        if not control or control["id"] != str(record.pk):
            raise RuntimeError("The real backend did not request this synthetic observation.")
        if mode == "ack-reconciliation":
            if control["mode"] != "accept":
                raise RuntimeError("Only explicitly accepted observations may be acknowledged.")
            value = record.observation
        elif mode == "drift-reconciliation":
            value = copy.deepcopy(record.observation)
            value["state"]["gpo"]["computer_ds"] += 1
            value["state"]["gpo"]["computer_sysvol"] += 1
        else:
            state = copy.deepcopy(a["expected_state"])
            state["gpo"] = {"guid": job.gpo_guid, "name": a["pilot_display_name"],
                "description": "IPMS managed GPO; id=" + a["managed_id"], "computer_enabled": False,
                "user_enabled": False, "computer_ds": 0, "computer_sysvol": 0, "user_ds": 0,
                "user_sysvol": 0, "security_digest": "b" * 64, "wmi_filter": "", "links": []}
            value = {"schema": 1, "state": state, "forest_links": [], "forest_complete": mode != "observe-unverifiable",
                "acl_consistent": True, "gpo_presence": "present", "issues": [], "gpo_guid": job.gpo_guid, "quiescent": True}
        observed_digest = digest(value)
        exchange(job, "reconciliation_result", journal_sha256="d" * 64, reconciliation_id=str(record.pk),
            observation_digest=observed_digest, observation=value)
        if mode == "ack-reconciliation":
            exchange(job, "reconciliation_ack", journal_sha256="d" * 64, reconciliation_id=str(record.pk), observation_digest=observed_digest)
        record.refresh_from_db()
        job.refresh_from_db()
        policy = ManagedGpoPolicy.objects.get(pk=a["managed_id"])
        result = {"id": str(record.pk), "status": record.status, "job_status": job.status,
            "error_code": job.error_code, "observation": record.observation, "observation_digest": record.observation_digest,
            "staged_job_id": str(policy.staged_job_id) if policy.staged_job_id else None,
            "active_job_id": str(policy.active_job_id) if policy.active_job_id else None}
    elif mode in ("inspect", "complete"):
        job = GpoImportJob.objects.get(pk=uuid.UUID(sys.argv[2]), tenant=tenant,
            domain__domain_name__startswith="production-", domain__domain_name__endswith=".example.invalid")
        assignment = job.assignment
        if assignment.get("schema") not in (3, 4):
            raise RuntimeError("Only schema 3/4 synthetic fixture requests are supported.")
        if mode == "inspect":
            if assignment["operation"] != "inspect_managed_gpo" or job.approved_at or job.claimed_at:
                raise RuntimeError("Inspection must be read-only and unapproved.")
            state = observe(job)
            status, code = "inspected", "gpo_inspected"
        else:
            if not job.approved_at or job.status != "queued":
                raise RuntimeError("The test must explicitly approve the exact fixture request first.")
            claim = exchange(job, "claim")["gpo_claim"]
            if not claim["authorized"] or claim["mode"] != "execute":
                raise RuntimeError("The real backend did not authorize the synthetic claim.")
            state = copy.deepcopy(assignment["expected_state"])
            if assignment["operation"] in ("import_managed_gpo", "import_and_link_managed_gpo"):
                if state["gpo"] is None:
                    state["gpo"] = {"guid": str(uuid.uuid4()), "name": assignment["pilot_display_name"],
                        "description": ("IPMS managed override; id=" + assignment["managed_id"] + "; definition=" + assignment["override_id"]
                            if assignment["schema"] == 4 else "IPMS managed GPO; id=" + assignment["managed_id"]),
                        "computer_enabled": False, "user_enabled": False, "computer_ds": 1, "computer_sysvol": 1,
                        "user_ds": 1, "user_sysvol": 1, "security_digest": "b" * 64, "wmi_filter": "", "links": []}
                status, code = "staged", "gpo_prepared"
            if assignment["operation"] in ("link_managed_gpo", "activate_managed_gpo", "import_and_link_managed_gpo"):
                activating = assignment["operation"] == "activate_managed_gpo"
                if activating:
                    # Synthetic native boundary only: no AD or real backup is created.
                    # The test must have explicitly reviewed and approved this fixture action.
                    state["gpo"]["name"] = assignment["pilot_display_name"]
                    state["gpo"]["computer_enabled"] = True
                    state["gpo"]["user_enabled"] = False
                state["gpo"]["links"] = []
                for index, ou in enumerate(state["ous"]):
                    link = {"guid": state["gpo"]["guid"], "domain": assignment["domain_dns_name"], "dn": ou["dn"],
                        "kind": "domain" if ou["dn"].startswith("DC=") else "ou", "enabled": activating, "enforced": False, "order": assignment["link_orders"][index]}
                    ou["links"] = [item for item in ou["links"] if item["guid"] != state["gpo"]["guid"]]
                    ou["links"].insert(link["order"] - 1, link)
                    for order, item in enumerate(ou["links"], 1):
                        item["order"] = order
                    state["gpo"]["links"].append(copy.deepcopy(link))
                    ou["usn"] = str(int(ou["usn"]) + 1)
                status, code = ("activated", "gpo_activated") if activating else ("linked", "gpo_linked")
            elif assignment["operation"] != "import_managed_gpo":
                raise RuntimeError("Unsupported synthetic fixture operation.")
        evidence = {"schema": assignment["schema"], "operation": assignment["operation"], "managed_id": assignment["managed_id"],
            "state": state, "prepared_artifact_sha256": assignment["artifact_sha256"] if mode == "complete"
                and assignment["operation"] in ("import_managed_gpo", "activate_managed_gpo", "import_and_link_managed_gpo") else "", "backup_id": "", "backup_manifest_sha256": ""}
        if assignment["schema"] == 4:
            evidence["override_sha256"] = assignment["override_sha256"]
        if mode == "complete" and assignment["operation"] == "activate_managed_gpo":
            # Placeholder receipt represents the fake provider, never a backup of real directory data.
            evidence["backup_id"] = str(uuid.uuid5(uuid.NAMESPACE_DNS, "synthetic-backup-" + str(job.pk)))
            evidence["backup_manifest_sha256"] = "c" * 64
        exchange(job, "result", status=status, result_code=code,
            gpo_guid=state["gpo"]["guid"] if state["gpo"] else None, evidence=evidence)
        job.refresh_from_db()
        result = {"job_id": str(job.pk), "status": job.status, "approved_at": job.approved_at.isoformat() if job.approved_at else None,
            "claimed_at": job.claimed_at.isoformat() if job.claimed_at else None, "managed_id": assignment["managed_id"],
            "gpo_guid": job.gpo_guid or None, "state": state}
    else:
        raise RuntimeError("Unknown isolated fixture mode.")
print(json.dumps(result))
