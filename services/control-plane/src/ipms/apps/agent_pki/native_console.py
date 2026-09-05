"""Authorization and encrypted configuration for the fixed native console capability."""
import json
import os
import uuid
from datetime import timedelta
from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.contrib.auth import get_user
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import HyperVConsoleSession, HyperVVirtualMachine
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .models import AgentEnrollment, AgentRevocation, NativeConsoleCredential

NATIVE_MIN_VERSION = (0, 2, 26)


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValidationError("native_identity_invalid")
    return value


def _key():
    path = getattr(settings, "NATIVE_CONSOLE_KEY_FILE", "")
    if not path:
        raise ValidationError("native_configuration_unavailable")
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValidationError("native_configuration_unavailable")
    return key


def _aad(tenant_id, enrollment_id):
    return f"ipms:native-console:v1:{tenant_id}:{enrollment_id}".encode("ascii")


def store_credential(enrollment, *, user, document):
    if not has_tenant_permission(user, enrollment.tenant, Permission.AGENTS_MANAGE):
        raise ValidationError("native_configuration_forbidden")
    if not isinstance(document, dict) or set(document) != {"username", "password", "domain"}:
        raise ValidationError("native_configuration_invalid")
    for name, limit in (("username", 256), ("password", 1024), ("domain", 256)):
        value = document[name]
        if not isinstance(value, str) or len(value) > limit or "\x00" in value or (name != "domain" and not value):
            raise ValidationError("native_configuration_invalid")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, json.dumps(document).encode(), _aad(enrollment.tenant_id, enrollment.id))
    with transaction.atomic():
        locked = AgentEnrollment.objects.select_for_update().get(
            id=enrollment.id, tenant=enrollment.tenant, status=AgentEnrollment.Status.ACTIVE,
        )
        NativeConsoleCredential.objects.update_or_create(
            enrollment=locked, defaults={"tenant": locked.tenant, "nonce": nonce, "ciphertext": ciphertext},
        )
        AuditEvent.objects.create(
            tenant=locked.tenant, actor=user.get_username(), action="hyperv.console.credential.configure",
            object_type="agent_enrollment", object_id=str(locked.id), outcome=AuditEvent.Outcome.SUCCEEDED, details={},
        )


def load_credential(session):
    secret = NativeConsoleCredential.objects.get(enrollment=session.enrollment, tenant=session.tenant)
    document = json.loads(AESGCM(_key()).decrypt(
        bytes(secret.nonce), bytes(secret.ciphertext), _aad(session.tenant_id, session.enrollment_id),
    ))
    if set(document) != {"username", "password", "domain"} or any(not isinstance(v, str) for v in document.values()):
        raise ValidationError("native_configuration_invalid")
    return document


def configuration_state(vm, user):
    enrollment = AgentEnrollment.objects.filter(
        tenant=vm.tenant, device_uri=vm.host.source_id, status=AgentEnrollment.Status.ACTIVE,
        platform=AgentEnrollment.Platform.WINDOWS,
    ).first()
    from .hyperv_console import _version_tuple
    version = _version_tuple(vm.host.agent_version)
    return {
        "configured": bool(enrollment and NativeConsoleCredential.objects.filter(enrollment=enrollment, tenant=vm.tenant).exists()),
        "can_manage": has_tenant_permission(user, vm.tenant, Permission.AGENTS_MANAGE),
        "native_supported": bool(enrollment and version and version >= NATIVE_MIN_VERSION),
    }


def _validate_session(session):
    now = timezone.now()
    enrollment = session.enrollment
    if (session.transport != "vmconnect" or session.status not in ("requested", "active")
            or session.lease_expires_at <= now or session.owner_id is None or session.stream_generation is None
            or session.tenant.status != Tenant.Status.ACTIVE or enrollment.tenant_id != session.tenant_id
            or enrollment.status != AgentEnrollment.Status.ACTIVE
            or enrollment.platform != AgentEnrollment.Platform.WINDOWS
            or AgentRevocation.objects.filter(enrollment=enrollment).exists()
            or not session.owner.is_active
            or not has_tenant_permission(session.owner, session.tenant, Permission.VIRTUAL_MACHINES_CONSOLE_CONTROL)):
        raise ValidationError("native_session_unavailable")
    canonical_uuid(session.vm_source_id)
    if not HyperVVirtualMachine.objects.filter(
        id=session.virtual_machine_id, tenant=session.tenant, source_id=session.vm_source_id,
        host__tenant=session.tenant, host__source_id=enrollment.device_uri, state="running",
    ).exists():
        raise ValidationError("native_vm_binding_changed")


def _session_queryset():
    return HyperVConsoleSession.objects.select_related("owner", "tenant", "enrollment")


@transaction.atomic
def authorize_browser(session_id, cookie, *, claim=None, attach=False, renew=False, peek=False):
    canonical_uuid(session_id)
    if not cookie or len(cookie) > 128:
        raise ValidationError("native_authentication_required")
    # Authentication remains Django's own session/hash validation, but a
    # broker has no authority to delete or rotate application login sessions.
    # Do not subclass SessionStore: its class name is part of the signing salt.
    session_store = import_module(settings.SESSION_ENGINE).SessionStore(session_key=cookie)

    def deny_session_mutation():
        raise ValidationError("native_authentication_required")

    session_store.flush = deny_session_mutation
    session_store.cycle_key = deny_session_mutation
    user = get_user(SimpleNamespace(session=session_store))
    if not user.is_authenticated or not user.is_active:
        raise ValidationError("native_authentication_required")
    session = _session_queryset().select_for_update(of=("self",)).get(id=session_id, owner_id=user.pk)
    _validate_session(session)
    if peek:
        return session
    if attach:
        if session.browser_claim is not None:
            raise ValidationError("native_browser_already_attached")
        session.browser_claim = uuid.uuid4()
        session.save(update_fields=("browser_claim",))
    elif claim is None or session.browser_claim != claim:
        raise ValidationError("native_browser_claim_invalid")
    if renew:
        now = timezone.now()
        session.last_activity_at = now
        session.lease_expires_at = now + timedelta(seconds=30)
        session.save(update_fields=("last_activity_at", "lease_expires_at"))
    return session


def authorize_agent(enrollment, session_id, generation):
    canonical_uuid(session_id)
    canonical_uuid(generation)
    session = _session_queryset().get(id=session_id, enrollment=enrollment, stream_generation=generation)
    _validate_session(session)
    if session.browser_claim is None:
        raise ValidationError("native_browser_not_attached")
    return session


def record_native_contact(session_id, generation):
    now = timezone.now()
    HyperVConsoleSession.objects.filter(
        id=session_id, stream_generation=generation, transport="vmconnect",
        status__in=("requested", "active"), lease_expires_at__gt=now,
    ).update(last_agent_contact_at=now)


def mark_native_ready(session_id, claim):
    now = timezone.now()
    updated = HyperVConsoleSession.objects.filter(
        id=session_id, browser_claim=claim, transport="vmconnect",
        status__in=("requested", "active"), lease_expires_at__gt=now,
    ).update(status="active", connected_at=now)
    if updated != 1:
        raise ValidationError("native_session_unavailable")


def audit_native(session, action, details=None):
    AuditEvent.objects.create(
        tenant=session.tenant, actor=session.requested_by, action=f"hyperv.console.native.{action}",
        object_type="hyperv_console_session", object_id=str(session.id),
        outcome=AuditEvent.Outcome.SUCCEEDED, details=details or {},
    )


def close_native(session_id, claim, *, failure=""):
    with transaction.atomic():
        session = HyperVConsoleSession.objects.select_for_update().get(id=session_id, browser_claim=claim)
        if session.status in ("requested", "active"):
            session.status = "failed" if failure else "closed"
            session.failure_code = failure
            session.closed_at = timezone.now()
            session.frame_png = b""
            session.save(update_fields=("status", "failure_code", "closed_at", "frame_png"))
            audit_native(session, "close", {"code": failure or "closed"})
