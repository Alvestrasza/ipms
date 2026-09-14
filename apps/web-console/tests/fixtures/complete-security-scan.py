# File Name: complete-security-scan.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Explicit synthetic native observations for isolated full browser/API/DB acceptance.
import json
import os

if os.environ.get("DJANGO_SETTINGS_MODULE") != "ipms_control_plane.settings.e2e" or not os.environ.get("IPMS_E2E_DATABASE"):
    raise RuntimeError("Explicit isolated Security fixture settings are required.")
import django
django.setup()

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.security.content import CATALOG_SHA256, MANIFESTS
from ipms.apps.security.models import BaselineScanJob
from ipms.apps.security.scans import security_exchange

agent = AgentEnrollment.objects.get(tenant__slug="console-e2e", display_name="baseline-unknown")
base = {"type": "security_scan", "schema_version": "1", "device_uri": agent.device_uri,
        "correlation_id": "isolated-e2e-synthetic"}
assignment = security_exchange(agent, {**base, "action": "poll", "agent_version": "0.2.31", "catalog_sha256": CATALOG_SHA256})["security_scan"]
if not assignment:
    raise RuntimeError("The browser must request the synthetic job first.")
job = BaselineScanJob.objects.get(pk=assignment["job_id"])
manifest = MANIFESTS[(assignment["baseline_id"], assignment["profile"])]
controls = []
failed = False
for control in manifest["controls"]:
    status, value = "unsupported", None
    if control["scope"] == "machine" and control["kind"] != "unsupported" and control["comparison"] == "equals":
        status, value = "ok", control["expected"]
        if not failed and control["value_type"] == "dword":
            value = 0 if value else 1
            failed = True
    controls.append({"control_id": control["id"], "read_status": status, "value": value})
for offset in range(0, len(controls), 32):
    security_exchange(agent, {
        **base, "action": "result", **{key: assignment[key] for key in ("job_id", "attempt_id", "manifest_sha256")},
        "page_index": offset // 32, "page_count": (len(controls) + 31) // 32,
        "system": {"os_build": "26100", "product_type": 3, "operating_system": job.operating_system, "join_state": "domain"},
        "controls": controls[offset:offset + 32],
    })
job.refresh_from_db()
print(json.dumps({"status": job.status, "controls": job.assessment.total_controls,
                  "failed": job.assessment.failed_controls, "unknown": job.assessment.unknown_controls}))
