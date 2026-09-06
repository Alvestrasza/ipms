"""Isolated loopback-only console browser acceptance fixture."""
import os
from pathlib import Path
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ipms_control_plane.settings.e2e")
if os.environ["DJANGO_SETTINGS_MODULE"] != "ipms_control_plane.settings.e2e" or not os.environ.get("IPMS_E2E_DATABASE"):
    raise RuntimeError("Console fixtures require explicit isolated E2E settings and database.")
if key_path := os.environ.get("IPMS_NATIVE_CONSOLE_KEY_FILE"):
    fixture_directory = Path(os.environ["IPMS_E2E_DATABASE"]).resolve().parent
    fixture_key = Path(key_path).resolve()
    if fixture_key.parent != fixture_directory or fixture_key.name != "fixture.key":
        raise RuntimeError("The fixture key must be named fixture.key beside the isolated database.")
    if not fixture_key.exists():
        fixture_key.write_bytes(os.urandom(32))
import django
django.setup()
from django.core.management import call_command
from django.contrib.auth import get_user_model
from django.utils import timezone
from ipms.apps.tenancy.models import Tenant, TenantMembership, PlatformAdministrator, ExternalIdentity
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.discovery.models import WindowsServer, HyperVVirtualMachine

call_command("migrate", interactive=False, verbosity=0)
user, _ = get_user_model().objects.get_or_create(username="e2e-admin")
user.set_password("test-only-password")
user.save()
tenant, _ = Tenant.objects.get_or_create(slug="console-e2e", defaults={"display_name": "Console E2E"})
TenantMembership.objects.get_or_create(tenant=tenant, user=user, defaults={"role": "tenant_admin"})
operator, _ = get_user_model().objects.get_or_create(username="e2e-operator")
operator.set_password("test-only-password")
operator.save()
TenantMembership.objects.get_or_create(tenant=tenant, user=operator, defaults={"role": "operator"})
second_tenant, _ = Tenant.objects.get_or_create(slug="service-accounts-e2e", defaults={"display_name": "Service Accounts E2E"})
TenantMembership.objects.get_or_create(tenant=second_tenant, user=user, defaults={"role": "tenant_admin"})
platform, _ = get_user_model().objects.get_or_create(username="e2e-platform")
platform.set_password("test-only-password")
platform.is_staff = platform.is_superuser = False
platform.save()
PlatformAdministrator.objects.get_or_create(user=platform)
Tenant.objects.get_or_create(slug="decommissioned-e2e", defaults={"display_name": "Archived E2E tenant", "status": "decommissioned"})
unassigned, _ = get_user_model().objects.get_or_create(username="e2e-unassigned")
unassigned.set_password("test-only-password")
unassigned.save()

# Disposable identity-security accounts: never reuse the ordinary suite logins.
for account_name in ("e2e-self-tenant", "e2e-self-platform", "e2e-self-unassigned", "e2e-self-suspended", "e2e-reset-target", "e2e-shared-target", "e2e-external-target"):
    identity, _ = get_user_model().objects.get_or_create(username=account_name)
    identity.set_password("test-only-password")
    identity.save()
    if account_name == "e2e-self-platform":
        PlatformAdministrator.objects.get_or_create(user=identity)
    elif account_name == "e2e-self-suspended":
        suspended, _ = Tenant.objects.get_or_create(slug="suspended-account-e2e", defaults={"display_name": "Suspended account E2E", "status": "suspended"})
        TenantMembership.objects.get_or_create(tenant=suspended, user=identity, defaults={"role": "reader"})
    elif account_name != "e2e-self-unassigned":
        TenantMembership.objects.get_or_create(tenant=tenant, user=identity, defaults={"role": "reader"})
    if account_name == "e2e-shared-target":
        TenantMembership.objects.get_or_create(tenant=second_tenant, user=identity, defaults={"role": "reader", "is_active": False})
    if account_name == "e2e-external-target":
        ExternalIdentity.objects.get_or_create(user=identity, issuer="https://identity.example.invalid", defaults={"subject": "fixture-external-subject"})
enrollment, _ = AgentEnrollment.objects.get_or_create(tenant=tenant, device_uri="urn:ipms:agent:31111111-1111-1111-1111-111111111111", defaults={"display_name": "Console E2E host", "platform": "windows", "status": "active", "last_seen_at": timezone.now()})
host, _ = WindowsServer.objects.get_or_create(tenant=tenant, source_id=enrollment.device_uri, defaults={"inventory_source": "agent", "server_type": "physical", "hostname": "console-host", "fqdn": "console-host.example.invalid", "operating_system": "Microsoft Windows Server", "hyperv_inventory_status": "collected", "agent_version": "0.2.22", "agent_state": "online", "health": "healthy", "discovered_at": timezone.now(), "last_seen_at": timezone.now()})
vm, _ = HyperVVirtualMachine.objects.get_or_create(tenant=tenant, host=host, source_id="32222222-2222-2222-2222-222222222222", defaults={"name": "Console acceptance VM", "state": "running", "observed_at": timezone.now()})
print("Isolated console fixture ready.")
