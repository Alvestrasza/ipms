"""Isolated loopback-only console browser acceptance fixture."""
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ipms_control_plane.settings.e2e")
if os.environ["DJANGO_SETTINGS_MODULE"] != "ipms_control_plane.settings.e2e" or not os.environ.get("IPMS_E2E_DATABASE"):
    raise RuntimeError("Console fixtures require explicit isolated E2E settings and database.")
import django
django.setup()
from django.core.management import call_command
from django.contrib.auth import get_user_model
from django.utils import timezone
from ipms.apps.tenancy.models import Tenant, TenantMembership
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.discovery.models import WindowsServer, HyperVVirtualMachine

call_command("migrate", interactive=False, verbosity=0)
user, _ = get_user_model().objects.get_or_create(username="e2e-admin")
user.set_password("test-only-password")
user.save()
tenant, _ = Tenant.objects.get_or_create(slug="console-e2e", defaults={"display_name": "Console E2E"})
TenantMembership.objects.get_or_create(tenant=tenant, user=user, defaults={"role": "tenant_admin"})
enrollment, _ = AgentEnrollment.objects.get_or_create(tenant=tenant, device_uri="urn:ipms:agent:31111111-1111-1111-1111-111111111111", defaults={"display_name": "Console E2E host", "platform": "windows", "status": "active", "last_seen_at": timezone.now()})
host, _ = WindowsServer.objects.get_or_create(tenant=tenant, source_id=enrollment.device_uri, defaults={"inventory_source": "agent", "server_type": "physical", "hostname": "console-host", "fqdn": "console-host.example.invalid", "operating_system": "Microsoft Windows Server", "hyperv_inventory_status": "collected", "agent_version": "0.2.22", "agent_state": "online", "health": "healthy", "discovered_at": timezone.now(), "last_seen_at": timezone.now()})
vm, _ = HyperVVirtualMachine.objects.get_or_create(tenant=tenant, host=host, source_id="32222222-2222-2222-2222-222222222222", defaults={"name": "Console acceptance VM", "state": "running", "observed_at": timezone.now()})
print("Isolated console fixture ready.")
