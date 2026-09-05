"""Tenant-bound encrypted service accounts and explicit host assignments."""
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import HyperVConsoleSession, WindowsServer
from ipms.apps.tenancy.models import Tenant
from .models import AgentEnrollment, NativeConsoleCredential, ServiceAccount
from .native_console import _key


def _account_aad(tenant_id, account_id):
    return f"ipms:service-account:v1:{tenant_id}:{account_id}".encode("ascii")


@sensitive_variables()
def decrypt_service_account(account, *, tenant_id):
    # A foreign-key association alone is never a tenant authorization boundary.
    if account.tenant_id != tenant_id or account.kind != ServiceAccount.Kind.HYPERV_CONSOLE:
        raise ValidationError("service_account_unavailable")
    try:
        document = json.loads(AESGCM(_key()).decrypt(
            bytes(account.nonce), bytes(account.ciphertext), _account_aad(tenant_id, account.id),
        ))
        if not isinstance(document, dict) or set(document) != {"username", "password", "domain"}:
            raise ValueError()
        for name, limit in (("username", 256), ("password", 1024), ("domain", 256)):
            value = document[name]
            if not isinstance(value, str) or len(value) > limit or "\x00" in value or (name != "domain" and not value):
                raise ValueError()
        return document
    except (InvalidTag, OSError, ValueError, TypeError, UnicodeError):
        raise ValidationError("service_account_unavailable") from None


@sensitive_variables()
def encrypt_service_account(account, document):
    nonce = os.urandom(12)
    try:
        ciphertext = AESGCM(_key()).encrypt(nonce, json.dumps(document).encode(), _account_aad(account.tenant_id, account.id))
    except (OSError, ValueError, TypeError):
        raise ValidationError("service_account_unavailable") from None
    account.nonce, account.ciphertext = nonce, ciphertext


@sensitive_variables()
def account_state(account):
    document = decrypt_service_account(account, tenant_id=account.tenant_id)
    return {
        "id": str(account.id), "name": account.name, "kind": account.kind,
        "username": document["username"], "domain": document["domain"],
        "host_count": account.bindings.filter(tenant_id=account.tenant_id).count(),
        "updated_at": account.updated_at.isoformat(),
    }


def eligible_hosts(tenant):
    return WindowsServer.objects.filter(tenant=tenant, inventory_source="agent").filter(
        Q(hyperv_inventory_status="collected") | Q(installed_roles__name="Hyper-V"),
    ).distinct()


def host_state(enrollment):
    host = WindowsServer.objects.filter(
        tenant_id=enrollment.tenant_id, inventory_source="agent", source_id=enrollment.device_uri,
    ).first()
    binding = NativeConsoleCredential.objects.filter(enrollment=enrollment, tenant_id=enrollment.tenant_id).first()
    eligible = bool(
        enrollment.platform == AgentEnrollment.Platform.WINDOWS
        and enrollment.status == AgentEnrollment.Status.ACTIVE
        and not hasattr(enrollment, "revocation")
        and host and eligible_hosts(enrollment.tenant).filter(pk=host.pk).exists()
    )
    return {
        "id": str(enrollment.id), "fqdn": (host.fqdn or host.hostname) if host else enrollment.display_name,
        "agent_version": host.agent_version if host else "",
        "service_account_id": str(binding.service_account_id) if binding and binding.service_account_id else None,
        "legacy_configured": bool(binding and binding.service_account_id is None and binding.nonce and binding.ciphertext),
        "eligible": eligible, "status": "revoked" if hasattr(enrollment, "revocation") else enrollment.status,
    }


def list_host_states(tenant):
    eligible_devices = eligible_hosts(tenant).values("source_id")
    enrollments = AgentEnrollment.objects.filter(tenant=tenant).filter(
        Q(platform="windows", status="active", revocation__isnull=True, device_uri__in=eligible_devices)
        | Q(native_console_credential__tenant=tenant),
    ).select_related("tenant", "revocation").order_by("display_name", "id")
    return [host_state(enrollment) for enrollment in enrollments]


def lock_tenant(tenant):
    # Low-frequency credential mutations serialize per tenant. Then acquire
    # enrollment(s, sorted) -> account -> binding -> session locks. Session
    # creation/removal already acquires enrollment first, avoiding both a
    # rotate/create race and an account/enrollment lock-order inversion.
    # NO KEY UPDATE still serializes these mutations, but allows the FK KEY
    # SHARE locks of concurrent audit inserts/session creation. A full tenant
    # FOR UPDATE lock would invert those existing enrollment-first workflows.
    return Tenant.objects.select_for_update(no_key=True).get(pk=tenant.pk, status=Tenant.Status.ACTIVE)


def lock_account_enrollments(account):
    return list(AgentEnrollment.objects.select_for_update(of=("self",)).filter(
        tenant_id=account.tenant_id, native_console_credential__service_account=account,
    ).order_by("id"))


def close_credential_sessions(tenant, enrollment_ids):
    return HyperVConsoleSession.objects.filter(
        tenant=tenant, enrollment_id__in=enrollment_ids, transport="vmconnect", status__in=("requested", "active"),
    ).update(status="closed", failure_code="native_configuration_changed", closed_at=timezone.now(), frame_png=b"")


def audit_account(tenant, user, action, object_id, **details):
    AuditEvent.objects.create(
        tenant=tenant, actor=user.get_username(), action=f"service_account.{action}",
        object_type="service_account", object_id=str(object_id), outcome=AuditEvent.Outcome.SUCCEEDED,
        details=details,
    )
