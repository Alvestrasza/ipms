import uuid
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, close_old_connections, connection, transaction
from django.test import Client, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import HyperVVirtualMachine, WindowsServer, WindowsServerRole
from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership
from .hyperv_console import create_console_session
from .models import AgentEnrollment, AgentRevocation, NativeConsoleCredential, ServiceAccount
from .native_console import authorize_browser, load_credential, store_credential
from .service_accounts import decrypt_service_account

from .test_native_console import NativeFixture


class ServiceAccountFixture(NativeFixture):
    endpoint = "/api/v1/service-accounts/"

    def setUp(self):
        super().setUp()
        self.host.hyperv_inventory_status = "collected"
        self.host.fqdn = "native-host.example.invalid"
        self.host.save(update_fields=("hyperv_inventory_status", "fqdn"))

    def create_account(self, **changes):
        document = {"name": "Console account", "kind": "hyperv_console", **self.credential, **changes}
        response = self.client.post(self.endpoint, document, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 201, response.content)
        return response.json()

    def host_endpoint(self, enrollment=None):
        return self.endpoint + f"hosts/{(enrollment or self.enrollment).id}/"

    def assign(self, account, enrollment=None):
        response = self.client.put(self.host_endpoint(enrollment), {"service_account_id": account["id"]}, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def patch_account(self, account, document):
        return self.client.patch(self.endpoint + account["id"] + "/", document, content_type="application/json", **self.headers)

    def second_host(self):
        enrollment = AgentEnrollment.objects.create(tenant=self.tenant, display_name="Second host", device_uri="urn:ipms:agent:" + str(uuid.uuid4()), status="active")
        host = WindowsServer.objects.create(tenant=self.tenant, inventory_source="agent", source_id=enrollment.device_uri,
                                           hostname="second-host", agent_version="0.2.26", hyperv_inventory_status="collected", discovered_at=timezone.now())
        vm = HyperVVirtualMachine.objects.create(tenant=self.tenant, host=host, source_id=str(uuid.uuid4()), name="Second VM", state="running", observed_at=timezone.now())
        return enrollment, host, vm


class ServiceAccountTests(ServiceAccountFixture, TestCase):
    def test_create_returns_metadata_without_secrets(self):
        result = self.create_account()
        self.assertEqual(result["username"], self.credential["username"])
        self.assertEqual(result["host_count"], 0)
        self.assertNotIn("password", result)
        self.assertEqual(self.client.get(self.endpoint, **self.headers).json()["results"], [result])
        account = ServiceAccount.objects.get(pk=result["id"])
        for secret in self.credential.values():
            self.assertNotIn(secret.encode(), bytes(account.ciphertext))
        self.assertEqual(decrypt_service_account(account, tenant_id=self.tenant.id), self.credential)
        audit = str(list(AuditEvent.objects.values()))
        for secret in self.credential.values():
            self.assertNotIn(secret, audit)

    def test_account_domain_is_optional_and_empty_means_local_account(self):
        document = {"name": "Local console", "kind": "hyperv_console", "username": "local-console", "password": "test-secret"}
        response = self.client.post(self.endpoint, document, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["domain"], "")

    def test_operator_and_reader_cannot_read_or_write_accounts_or_legacy_configuration(self):
        account = self.create_account()
        operator = get_user_model().objects.create_user("operator")
        TenantMembership.objects.create(tenant=self.tenant, user=operator, role="operator")
        for user in (operator, self.reader):
            self.client.force_login(user)
            for method, url, data in (
                ("get", self.endpoint, None), ("post", self.endpoint, self.credential),
                ("patch", self.endpoint + account["id"] + "/", {"name": "Changed"}),
                ("delete", self.endpoint + account["id"] + "/", None),
                ("get", self.endpoint + "hosts/", None),
                ("put", self.host_endpoint(), {"service_account_id": account["id"]}),
                ("delete", self.host_endpoint(), None),
            ):
                response = getattr(self.client, method)(url, data, content_type="application/json", **self.headers)
                self.assertEqual(response.status_code, 403, (method, url, response.content))
            with self.assertRaises(ValidationError):
                store_credential(self.enrollment, user=user, document=self.credential)
        self.client.force_login(operator)
        config = self.client.get(f"/api/v1/hyper-v/virtual-machines/{self.vm.id}/console-configuration/", **self.headers)
        self.assertEqual(config.json(), {"configured": True, "can_manage": False, "native_supported": True})

    def test_console_configuration_post_is_removed_even_for_administrator(self):
        response = self.client.post(f"/api/v1/hyper-v/virtual-machines/{self.vm.id}/console-configuration/", self.credential, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 405)

    def test_platform_credentials_denied_even_with_malformed_membership(self):
        account = self.create_account()
        self.assign(account)
        platform = get_user_model().objects.create_user("platform-admin")
        PlatformAdministrator.objects.create(user=platform)
        legacy_staff = get_user_model().objects.create_user("legacy-staff", is_staff=True)
        for user in (platform, legacy_staff):
            # Bypass model validation to exercise authorization against invalid
            # historical rows, not merely against a well-formed database.
            TenantMembership.objects.bulk_create([
                TenantMembership(tenant=self.tenant, user=user, role="tenant_admin"),
            ])
            self.client.force_login(user)
            for method, url, data in (
                ("get", self.endpoint, None),
                ("post", self.endpoint, {"name": "Forbidden", "kind": "hyperv_console", **self.credential}),
                ("patch", self.endpoint + account["id"] + "/", {"password": "forbidden-change"}),
                ("delete", self.endpoint + account["id"] + "/", None),
                ("get", self.endpoint + "hosts/", None),
                ("put", self.host_endpoint(), {"service_account_id": account["id"]}),
                ("delete", self.host_endpoint(), None),
                ("get", f"/api/v1/hyper-v/virtual-machines/{self.vm.id}/console-configuration/", None),
            ):
                response = getattr(self.client, method)(
                    url, data, content_type="application/json", **self.headers,
                )
                self.assertEqual(response.status_code, 404, (user.username, method, url))
                self.assertNotIn(self.credential["username"], response.content.decode())
            with self.assertRaises(ValidationError):
                store_credential(self.enrollment, user=user, document=self.credential)
        self.assertEqual(ServiceAccount.objects.count(), 1)
        retained = ServiceAccount.objects.get(pk=account["id"])
        self.assertEqual(decrypt_service_account(retained, tenant_id=self.tenant.id), self.credential)
        binding = NativeConsoleCredential.objects.get(enrollment=self.enrollment)
        self.assertEqual(binding.service_account_id, retained.id)

    def test_cross_tenant_accounts_hosts_and_ciphertext_fail_closed(self):
        account = self.create_account()
        foreign = Tenant.objects.create(slug="foreign", display_name="Foreign")
        TenantMembership.objects.create(tenant=foreign, user=self.user, role="tenant_admin")
        own_headers = self.headers
        self.headers = {"HTTP_X_IPMS_TENANT_ID": str(foreign.id)}
        foreign_account = self.create_account(name="Foreign account")
        for method, endpoint, data in (
            ("patch", self.endpoint + account["id"] + "/", {"name": "No"}),
            ("delete", self.endpoint + account["id"] + "/", None),
            ("put", self.host_endpoint(), {"service_account_id": foreign_account["id"]}),
            ("delete", self.host_endpoint(), None),
        ):
            response = getattr(self.client, method)(endpoint, data, content_type="application/json", **self.headers)
            self.assertEqual(response.status_code, 404)
        self.headers = own_headers
        response = self.client.put(self.host_endpoint(), {"service_account_id": foreign_account["id"]}, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 404)
        self.assign(account)
        session = self.native_session()
        NativeConsoleCredential.objects.filter(enrollment=self.enrollment).update(service_account_id=foreign_account["id"])
        with self.assertRaises(ValidationError):
            load_credential(session)
        own = ServiceAccount.objects.get(pk=account["id"])
        other = ServiceAccount.objects.get(pk=foreign_account["id"])
        own.nonce, own.ciphertext = other.nonce, other.ciphertext
        with self.assertRaises(ValidationError):
            decrypt_service_account(own, tenant_id=self.tenant.id)
        with self.assertRaises(ValidationError):
            decrypt_service_account(other, tenant_id=self.tenant.id)

    def test_account_uuid_is_cryptographically_bound_within_same_tenant(self):
        first, second = self.create_account(), self.create_account(name="Second")
        one, two = ServiceAccount.objects.get(pk=first["id"]), ServiceAccount.objects.get(pk=second["id"])
        one.nonce, one.ciphertext = two.nonce, two.ciphertext
        with self.assertRaises(ValidationError):
            decrypt_service_account(one, tenant_id=self.tenant.id)

    def test_legacy_preserved_until_explicit_assignment_and_downlevel_writes_blocked(self):
        before = NativeConsoleCredential.objects.get(enrollment=self.enrollment)
        account = self.create_account()
        before.refresh_from_db()
        self.assertIsNone(before.service_account_id)
        self.assertTrue(before.ciphertext)
        hosts = self.client.get(self.endpoint + "hosts/", **self.headers).json()["results"]
        self.assertTrue(hosts[0]["legacy_configured"])
        assigned = self.assign(account)
        self.assertFalse(assigned["legacy_configured"])
        before.refresh_from_db()
        self.assertEqual(bytes(before.nonce), b"")
        self.assertEqual(bytes(before.ciphertext), b"")
        with self.assertRaises(IntegrityError), transaction.atomic():
            NativeConsoleCredential.objects.filter(pk=before.pk).update(nonce=b"old-nonce", ciphertext=b"old-ciphertext")
        self.assertEqual(self.client.delete(self.host_endpoint(), **self.headers).status_code, 204)
        self.assertFalse(NativeConsoleCredential.objects.filter(enrollment=self.enrollment).exists())

    def test_reuse_and_rotate_once_close_all_sessions_even_with_clock_rollback(self):
        account = self.create_account()
        enrollment, host, vm = self.second_host()
        self.assign(account)
        self.assign(account, enrollment)
        first = self.native_session()
        second, occupied = create_console_session(virtual_machine=vm, actor=self.user.username, owner=self.user, transport="vmconnect", external_session_acknowledged=True)
        self.assertIsNone(occupied)
        self.assertEqual(load_credential(first), self.credential)
        self.assertEqual(load_credential(second), self.credential)
        attached = authorize_browser(str(first.id), self.cookie, attach=True)
        with patch("ipms.apps.agent_pki.service_accounts.timezone.now", return_value=first.created_at - timedelta(days=1)):
            response = self.patch_account(account, {"password": "rotated-private-password"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["host_count"], 2)
        for old in (first, second):
            old.refresh_from_db()
            self.assertEqual(old.status, "closed")
            self.assertEqual(old.failure_code, "native_configuration_changed")
            with self.assertRaises(ValidationError):
                load_credential(old)
        with self.assertRaises(ValidationError):
            authorize_browser(str(first.id), self.cookie, claim=attached.browser_claim)
        fresh = self.native_session()
        self.assertEqual(load_credential(fresh)["password"], "rotated-private-password")

    def test_reassignment_and_unassignment_close_session_and_deny_stale_load(self):
        one, two = self.create_account(), self.create_account(name="Replacement", password="replacement-password")
        self.assign(one)
        old = self.native_session()
        self.assign(two)
        with self.assertRaises(ValidationError):
            load_credential(old)
        current = self.native_session()
        self.assertEqual(load_credential(current)["password"], "replacement-password")
        self.assertEqual(self.client.delete(self.host_endpoint(), **self.headers).status_code, 204)
        with self.assertRaises((ValidationError, NativeConsoleCredential.DoesNotExist)):
            load_credential(current)
        current.refresh_from_db()
        self.assertEqual(current.status, "closed")
        with self.assertRaises(ValidationError):
            self.native_session()

    def test_name_only_update_keeps_password_and_active_session(self):
        account = self.create_account()
        self.assign(account)
        session = self.native_session()
        response = self.patch_account(account, {"name": "Renamed"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], "Renamed")
        self.assertEqual(load_credential(session), self.credential)
        self.assertEqual(self.patch_account(account, {"username": "renamed-user"}).status_code, 200)
        fresh = self.native_session()
        self.assertEqual(load_credential(fresh), {**self.credential, "username": "renamed-user"})

    def test_delete_bound_returns_conflict_then_explicit_unassign_allows_delete(self):
        account = self.create_account()
        self.assign(account)
        endpoint = self.endpoint + account["id"] + "/"
        response = self.client.delete(endpoint, **self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["error"]["code"], "service_account_in_use")
        self.assertEqual(self.client.delete(self.host_endpoint(), **self.headers).status_code, 204)
        self.assertEqual(self.client.delete(endpoint, **self.headers).status_code, 204)
        self.assertFalse(ServiceAccount.objects.filter(pk=account["id"]).exists())

    def test_bound_inactive_host_remains_visible_and_can_be_unassigned_not_assigned(self):
        account = self.create_account()
        self.assign(account)
        AgentEnrollment.objects.filter(pk=self.enrollment.pk).update(status="revoked")
        hosts = self.client.get(self.endpoint + "hosts/", **self.headers).json()["results"]
        self.assertEqual(len(hosts), 1)
        self.assertFalse(hosts[0]["eligible"])
        self.assertEqual(hosts[0]["status"], "revoked")
        response = self.client.put(self.host_endpoint(), {"service_account_id": account["id"]}, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.client.delete(self.host_endpoint(), **self.headers).status_code, 204)
        self.assertEqual(self.client.get(self.endpoint + "hosts/", **self.headers).json(), {"results": []})

    def test_only_agent_windows_hyperv_hosts_are_eligible_and_revocation_wins(self):
        account = self.create_account()
        enrollment, host, vm = self.second_host()
        for changes in ({"hyperv_inventory_status": "not-reported"}, {"inventory_source": "hyper-v"}):
            original = {key: getattr(host, key) for key in changes}
            WindowsServer.objects.filter(pk=host.pk).update(**changes)
            response = self.client.put(self.host_endpoint(enrollment), {"service_account_id": account["id"]}, content_type="application/json", **self.headers)
            self.assertEqual(response.status_code, 400)
            WindowsServer.objects.filter(pk=host.pk).update(**original)
        AgentEnrollment.objects.filter(pk=enrollment.pk).update(platform="linux")
        self.assertEqual(self.client.put(self.host_endpoint(enrollment), {"service_account_id": account["id"]}, content_type="application/json", **self.headers).status_code, 400)
        AgentEnrollment.objects.filter(pk=enrollment.pk).update(platform="windows")
        AgentRevocation.objects.create(enrollment=enrollment, tenant=self.tenant, reason="test", revoked_by="test-admin")
        self.assertEqual(self.client.put(self.host_endpoint(enrollment), {"service_account_id": account["id"]}, content_type="application/json", **self.headers).status_code, 400)

    def test_hyperv_role_without_collected_vm_inventory_is_eligible(self):
        account = self.create_account()
        self.host.hyperv_inventory_status = "not-reported"
        self.host.save(update_fields=("hyperv_inventory_status",))
        WindowsServerRole.objects.create(server=self.host, name="Hyper-V", display_name="Hyper-V")
        self.assign(account)

    def test_validation_rejects_blank_password_unknown_fields_and_wrong_kind(self):
        account = self.create_account()
        for document in ({"password": ""}, {"password": None}, {"username": ""}, {"password": "a\x00b"}, {"password": "x" * 1025}, {"kind": "shell"}, {"command": "ignored?"}, {"domain": []}):
            response = self.patch_account(account, document)
            self.assertEqual(response.status_code, 400, document)
            self.assertEqual(response.json()["error"]["code"], "service_account_invalid")
        self.assertEqual(decrypt_service_account(ServiceAccount.objects.get(pk=account["id"]), tenant_id=self.tenant.id), self.credential)

    def test_csrf_is_required_for_authenticated_mutation(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        response = client.post(self.endpoint, {"name": "Blocked", "kind": "hyperv_console", **self.credential}, content_type="application/json", **self.headers)
        self.assertEqual(response.status_code, 403)
        self.assertFalse(ServiceAccount.objects.exists())

    def test_missing_key_and_corrupt_ciphertext_return_sanitized_unavailable(self):
        account = self.create_account()
        with override_settings(NATIVE_CONSOLE_KEY_FILE=""):
            response = self.client.get(self.endpoint, **self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "service_account_unavailable")
        ServiceAccount.objects.filter(pk=account["id"]).update(ciphertext=b"broken")
        response = self.client.get(self.endpoint, **self.headers)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"]["code"], "service_account_unavailable")


@skipUnless(connection.vendor == "postgresql", "Requires real PostgreSQL row locks")
class ServiceAccountConcurrencyTests(ServiceAccountFixture, TransactionTestCase):
    def test_rotation_serializes_with_new_console_creation(self):
        from rest_framework.test import APIRequestFactory, force_authenticate
        from . import service_account_views

        account = self.create_account()
        self.assign(account)
        previous = self.native_session()
        locked, release = threading.Event(), threading.Event()
        application_name = "ipms-service-account-race-" + uuid.uuid4().hex
        original_close = service_account_views.close_credential_sessions

        def paused_close(*args, **kwargs):
            locked.set()
            if not release.wait(10):
                raise AssertionError("Credential mutation test gate timed out")
            return original_close(*args, **kwargs)

        def rotate():
            close_old_connections()
            try:
                request = APIRequestFactory().patch(self.endpoint + account["id"] + "/", {"password": "concurrent-rotation"}, format="json", **self.headers)
                force_authenticate(request, user=self.user)
                return service_account_views.ServiceAccountDetailView.as_view()(request, pk=uuid.UUID(account["id"])).status_code
            finally:
                connection.close()

        def create():
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT set_config('application_name', %s, false)", [application_name])
                session, occupied = create_console_session(virtual_machine=self.vm, actor=self.user.username, owner=self.user,
                                                          transport="vmconnect", external_session_acknowledged=True)
                return session, occupied
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor, patch.object(service_account_views, "close_credential_sessions", side_effect=paused_close):
            rotation = executor.submit(rotate)
            try:
                self.assertTrue(locked.wait(10))
                creation = executor.submit(create)
                waiting = False
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE application_name=%s AND wait_event_type='Lock')", [application_name])
                        waiting = cursor.fetchone()[0]
                    if waiting:
                        break
                    time.sleep(0.02)
                self.assertTrue(waiting, "Console creation must wait on the rotating enrollment lock")
            finally:
                release.set()
            self.assertEqual(rotation.result(timeout=10), 200)
            session, occupied = creation.result(timeout=10)
        self.assertIsNone(occupied)
        self.assertNotEqual(session.id, previous.id)
        previous.refresh_from_db()
        self.assertEqual(previous.status, "closed")
        self.assertEqual(load_credential(session)["password"], "concurrent-rotation")
