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
from django.contrib.auth import get_user_model
from ipms.apps.agent_pki.models import AgentEnrollment, AgentLifecycleJob, WindowsAgentDeployment
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.security.catalog import CATALOG_REVISION
from ipms.apps.security.content import MANIFESTS
from ipms.apps.security.models import BaselineAssessment, BaselineScanJob, DomainSecuritySettings, GpoExecutorReport, GpoImportJob
from ipms.apps.security.catalog import BASELINES
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
    manifest = MANIFESTS[("microsoft-windows-server-2025", target.operating_system_role)]
    fields = dict(
        system=target, enrollment=AgentEnrollment.objects.get(device_uri=target.source_id),
        baseline_id="microsoft-windows-server-2025", baseline_revision="2602",
        catalog_revision=CATALOG_REVISION, profile=target.operating_system_role,
        content_sha256=manifest["manifest_sha256"],
        os_build=target.os_build, operating_system=target.operating_system,
        scope_verified=True, total_controls=10, passed_controls=10,
        observed_at=timezone.now() - timedelta(minutes=5),
    )
    fields.update(changes)
    fields["passed_controls"] += len(manifest["controls"]) - fields["total_controls"]
    fields["total_controls"] = len(manifest["controls"])
    BaselineAssessment.objects.create(**fields)


result(host)
result(system("baseline-failed", role="domain-controller"), passed_controls=8, failed_controls=2)
scan_host = system("baseline-unknown")
scan_host.agent_version = "0.2.31"
scan_host.save()
AgentEnrollment.objects.filter(device_uri=scan_host.source_id).update(
    last_heartbeat_at=timezone.now(), certificate_fingerprint_sha256="a" * 64,
    certificate_not_before=timezone.now() - timedelta(days=1),
    certificate_not_after=timezone.now() + timedelta(days=1),
)
result(system("baseline-stale"), observed_at=timezone.now() - timedelta(hours=25))
for index in range(26):
    system(f"baseline-2022-{index:02}", build="20348", os_name="Microsoft Windows Server 2022 Datacenter")
system("baseline-client", role="client", build="26200", os_name="Microsoft Windows 11 Enterprise")
system("baseline-unmatched", role="client", build="28000", os_name="Microsoft Windows 11 Enterprise")
system("baseline-unclassified", role="unknown", build="", os_name="")
other = Tenant.objects.get(slug="service-accounts-e2e")
result(system("hidden-other-tenant", owner=other))
# This synthetic executor reports no known OS/build, keeping the existing
# baseline coverage fixture unchanged. No real Agent or AD operation runs.
gpo_dc = system("gpo-ui-dc", role="domain-controller", build="", os_name="")
gpo_dc.domain_name = "gpo-ui.example.invalid"
gpo_dc.fqdn = "gpo-ui-dc.gpo-ui.example.invalid"
gpo_dc.agent_version = "0.2.32"
gpo_dc.save()
gpo_agent = AgentEnrollment.objects.get(device_uri=gpo_dc.source_id)
gpo_agent.last_heartbeat_at = timezone.now()
gpo_agent.certificate_fingerprint_sha256 = "a" * 64
gpo_agent.certificate_not_before = timezone.now() - timedelta(days=1)
gpo_agent.certificate_not_after = timezone.now() + timedelta(days=1)
gpo_agent.save()
GpoExecutorReport.objects.create(
    enrollment=gpo_agent, agent_version="0.2.32", domain_dns_name=gpo_dc.domain_name,
    domain_guid="e99d4445-1d3b-4a30-92ca-77c04e725eab", forest_dns_name=gpo_dc.domain_name,
    dc_fqdn=gpo_dc.fqdn, role="writable-domain-controller", gpmc_available=True,
    result_code="ready_for_approval", observed_at=timezone.now(),
)
# History fixtures never change assessment coverage and are never delivered to an Agent.
log_actor = get_user_model().objects.get(username="e2e-admin")
host_agent = AgentEnrollment.objects.get(device_uri=host.source_id)
for index in range(30):
    logged_at = timezone.now() - timedelta(days=2, minutes=index)
    BaselineScanJob.objects.create(
        tenant=tenant, enrollment=host_agent, system=host, requested_by=log_actor,
        baseline_id="microsoft-windows-server-2025", status="completed", requested_at=logged_at,
        expires_at=logged_at + timedelta(minutes=10), completed_at=logged_at + timedelta(minutes=1),
        error_code="logs-fixture-complete",
    )
AgentLifecycleJob.objects.create(
    tenant=tenant, enrollment=host_agent, action="update", status="succeeded", target_version="0.2.32",
    requested_by="logs-fixture-admin", completed_at=timezone.now(), result_code="logs-fixture-updated",
)
WindowsAgentDeployment.objects.create(
    tenant=tenant, enrollment=host_agent, display_name="logs-fixture-deployment", target_address="logs.example.invalid",
    requested_by="logs-fixture-admin", status="succeeded", completed_at=timezone.now(),
)
logs_domain = DomainSecuritySettings.objects.create(
    tenant=tenant, domain_name="logs.example.invalid", tier_ous={"0": [], "1": [], "2": []},
    gpo_name_template="{tier}-{scope}-{target}-{purpose}_V{version}", baseline_order=[item.id for item in BASELINES],
)
GpoImportJob.objects.create(
    id=uuid.UUID("75555555-5555-4555-8555-555555555555"), tenant=tenant, enrollment=gpo_agent, system=gpo_dc,
    domain=logs_domain, requested_by=log_actor, domain_guid="76666666-6666-4666-8666-666666666666",
    pilot_display_name="0-C-ALL-LogsFixture_V1.0.0-Pilot", pilot_name_key="logs-fixture-pilot",
    status="awaiting_approval", expires_at=timezone.now() + timedelta(hours=1),
    assignment={"baseline_id": "microsoft-windows-server-2025", "backup_id": "fixture-backup", "target_tier": "0",
                "approval_test_marker": "logs-fixture-approval"},
)
print("Synthetic security fixture ready: 25% compliance / 50% coverage for Server 2025.")
