# File Name: seed-security.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Synthetic baseline results in an explicitly isolated browser-test database.
import os
import runpy
import uuid
from datetime import timedelta
from pathlib import Path

if os.environ.get("DJANGO_SETTINGS_MODULE") != "ipms_control_plane.settings.e2e" or not os.environ.get("IPMS_E2E_DATABASE"):
    raise RuntimeError("Security fixtures require explicit isolated E2E settings and database.")
runpy.run_path(str(Path(__file__).with_name("seed-console.py")), run_name="__main__")

from django.utils import timezone
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.security.catalog import CATALOG_REVISION
from ipms.apps.security.models import BaselineAssessment
from ipms.apps.tenancy.models import Tenant

tenant = Tenant.objects.get(slug="console-e2e")
if BaselineAssessment.objects.exists():
    raise RuntimeError("Use a fresh isolated database for the security fixture.")
host = WindowsServer.objects.get(tenant=tenant, hostname="console-host")
host.operating_system = "Microsoft Windows Server 2025 Standard"
host.os_build = "26100"
host.save()


def system(name, *, role="server", build="26100", os_name="Microsoft Windows Server 2025 Standard", owner=tenant):
    enrollment = AgentEnrollment.objects.create(
        tenant=owner, device_uri=f"urn:ipms:agent:{uuid.uuid4()}",
        display_name=name, platform="windows", status="active",
    )
    return WindowsServer.objects.create(
        tenant=owner, source_id=enrollment.device_uri, inventory_source="agent",
        hostname=name, fqdn=f"{name}.example.invalid", server_type="virtual",
        operating_system=os_name, os_build=build, operating_system_role=role,
        discovered_at=timezone.now(),
    )


def result(target, **changes):
    fields = dict(
        system=target, enrollment=AgentEnrollment.objects.get(device_uri=target.source_id),
        baseline_id="microsoft-windows-server-2025", baseline_revision="2602",
        catalog_revision=CATALOG_REVISION, profile=target.operating_system_role,
        os_build=target.os_build, operating_system=target.operating_system,
        scope_verified=True, total_controls=10, passed_controls=10,
        observed_at=timezone.now() - timedelta(minutes=5),
    )
    fields.update(changes)
    BaselineAssessment.objects.create(**fields)


result(host)
result(system("baseline-failed", role="domain-controller"), passed_controls=8, failed_controls=2)
system("baseline-unknown")
result(system("baseline-stale"), observed_at=timezone.now() - timedelta(hours=25))
for index in range(26):
    system(f"baseline-2022-{index:02}", build="20348", os_name="Microsoft Windows Server 2022 Datacenter")
system("baseline-client", role="client", build="26200", os_name="Microsoft Windows 11 Enterprise")
system("baseline-unmatched", role="client", build="28000", os_name="Microsoft Windows 11 Enterprise")
system("baseline-unclassified", role="unknown", build="", os_name="")
other = Tenant.objects.get(slug="service-accounts-e2e")
result(system("hidden-other-tenant", owner=other))
print("Synthetic security fixture ready: 25% compliance / 50% coverage for Server 2025.")
