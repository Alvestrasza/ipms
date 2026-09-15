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
from ipms.apps.security.gpo_jobs import security_gpo_exchange
from ipms.apps.security.models import DomainSecuritySettings, GpoDomainAuthorization, GpoExecutorReport, GpoImportJob, ManagedGpoPolicy
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
        system.domain_name, system.fqdn, system.agent_version = domain_name, f"gpo-ui-dc.{domain_name}", "0.2.35"
        system.save(update_fields=("domain_name", "fqdn", "agent_version"))
        enrollment = AgentEnrollment.objects.get(tenant=tenant, device_uri=system.source_id)
        enrollment.last_heartbeat_at = timezone.now()
        enrollment.certificate_not_before = timezone.now() - timedelta(days=1)
        enrollment.certificate_not_after = timezone.now() + timedelta(days=1)
        enrollment.save()
        GpoExecutorReport.objects.update_or_create(enrollment=enrollment, defaults={
            "agent_version": "0.2.35", "domain_dns_name": domain_name, "domain_guid": str(uuid.uuid4()),
            "forest_dns_name": domain_name, "dc_fqdn": system.fqdn, "role": "writable-domain-controller",
            "gpmc_available": True, "result_code": "ready_for_approval", "observed_at": timezone.now()})
        suffix_dn = ",".join("DC=" + part for part in domain_name.split("."))
        domain = DomainSecuritySettings.objects.create(tenant=tenant, domain_name=domain_name,
            tier_ous={str(tier): [f"OU=Tier{tier},{suffix_dn}"] for tier in range(3)},
            gpo_name_template="{tier}-{scope}-{target}-{purpose}_V{version}", baseline_order=[item.id for item in BASELINES])
        actor = get_user_model().objects.get(username="e2e-admin")
        GpoDomainAuthorization.objects.create(domain=domain, grants=[{"user_id": str(actor.pk), "tiers": ["0", "1", "2"]}])
        result = {"domain_id": str(domain.pk), "domain_name": domain_name, "system_id": str(system.pk)}
    elif mode in ("inspect", "complete"):
        job = GpoImportJob.objects.get(pk=uuid.UUID(sys.argv[2]), tenant=tenant,
            domain__domain_name__startswith="production-", domain__domain_name__endswith=".example.invalid")
        assignment = job.assignment
        if assignment.get("schema") != 3:
            raise RuntimeError("Only schema 3 synthetic fixture requests are supported.")
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
            if assignment["operation"] == "import_managed_gpo":
                if state["gpo"] is None:
                    state["gpo"] = {"guid": str(uuid.uuid4()), "name": assignment["pilot_display_name"],
                        "description": "IPMS managed GPO; id=" + assignment["managed_id"],
                        "computer_enabled": False, "user_enabled": False, "computer_ds": 1, "computer_sysvol": 1,
                        "user_ds": 1, "user_sysvol": 1, "security_digest": "b" * 64, "wmi_filter": "", "links": []}
                status, code = "staged", "gpo_prepared"
            elif assignment["operation"] in ("link_managed_gpo", "activate_managed_gpo"):
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
            else:
                raise RuntimeError("Unsupported synthetic fixture operation.")
        evidence = {"schema": 3, "operation": assignment["operation"], "managed_id": assignment["managed_id"],
            "state": state, "prepared_artifact_sha256": assignment["artifact_sha256"] if mode == "complete"
                and assignment["operation"] in ("import_managed_gpo", "activate_managed_gpo") else "", "backup_id": "", "backup_manifest_sha256": ""}
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
