# File Name: seed-wsus.py
# Version: v0.1.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Seed isolated Agent update evidence for catalog-only WSUS browser acceptance.
import os
import runpy
import uuid
from pathlib import Path

if os.environ.get("DJANGO_SETTINGS_MODULE") != "ipms_control_plane.settings.e2e":
    raise RuntimeError("WSUS fixtures require explicit isolated E2E settings.")
if not os.environ.get("IPMS_E2E_DATABASE"):
    raise RuntimeError("WSUS fixtures require an explicit isolated database path.")

runpy.run_path(str(Path(__file__).with_name("seed-console.py")), run_name="__main__")

from django.utils import timezone  # noqa: E402
from ipms.apps.agent_pki.models import AgentEnrollment  # noqa: E402
from ipms.apps.agent_pki.services import confirm_software_inventory  # noqa: E402

enrollment = AgentEnrollment.objects.get(
    tenant__slug="console-e2e",
    device_uri="urn:ipms:agent:31111111-1111-1111-1111-111111111111",
    status="active",
)
confirm_software_inventory(enrollment, document={
    "schema_version": "2", "platform": "windows", "snapshot_id": str(uuid.uuid4()),
    "page_index": 0, "page_count": 1, "reboot_required": None,
    "update_scan_status": "unknown", "last_update_scan_at": None,
    "last_update_install_at": None, "packages": [],
    "windows_update_evidence": {
        "source": "wua-local-cache", "status": "collected",
        "observed_at": timezone.now().isoformat(),
        "updates": [
            {"update_id": "61111111-1111-1111-1111-111111111111", "revision": 1},
            {"update_id": "62222222-2222-2222-2222-222222222222", "revision": 1},
        ],
    },
}, agent_version="0.2.43")
print("Isolated WSUS Agent evidence fixture ready.")
