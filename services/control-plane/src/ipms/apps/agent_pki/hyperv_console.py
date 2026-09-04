import base64
import binascii
import re
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import (
    HyperVConsoleInputEvent,
    HyperVConsoleSession,
    HyperVVirtualMachine,
)

from .models import AgentEnrollment


ACTIVE_STATUSES = (
    HyperVConsoleSession.Status.REQUESTED,
    HyperVConsoleSession.Status.ACTIVE,
)
FIRST_CAPABLE_AGENT_VERSION = (0, 2, 17)
LEASE_SECONDS = 30
MAX_FRAME_BYTES = 1_500_000
MAX_INPUT_EVENTS = 256
MAX_INPUT_BATCH = 64
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
FAILURE_CODE_PATTERN = re.compile(r"^[a-z0-9_]{1,64}$")


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _expire_stale_sessions(now=None) -> int:
    observed_at = now or timezone.now()
    return HyperVConsoleSession.objects.filter(
        status__in=ACTIVE_STATUSES,
        lease_expires_at__lt=observed_at,
    ).update(
        status=HyperVConsoleSession.Status.EXPIRED,
        failure_code="browser_lease_expired",
        closed_at=observed_at,
        frame_png=b"",
    )


@transaction.atomic
def create_console_session(*, virtual_machine, actor: str):
    now = timezone.now()
    _expire_stale_sessions(now)
    virtual_machine = (
        HyperVVirtualMachine.objects.select_for_update()
        .select_related("host")
        .get(id=virtual_machine.id, tenant=virtual_machine.tenant)
    )
    if virtual_machine.state != HyperVVirtualMachine.State.RUNNING:
        raise ValidationError("The virtual machine must be running to open its console.")
    agent_version = _version_tuple(virtual_machine.host.agent_version)
    if agent_version is None or agent_version < FIRST_CAPABLE_AGENT_VERSION:
        raise ValidationError(
            "The Hyper-V host Agent must be updated before it can provide a console."
        )
    enrollment = AgentEnrollment.objects.filter(
        tenant=virtual_machine.tenant,
        device_uri=virtual_machine.host.source_id,
        platform=AgentEnrollment.Platform.WINDOWS,
        status=AgentEnrollment.Status.ACTIVE,
    ).first()
    if enrollment is None:
        raise ValidationError("The Hyper-V host Agent is unavailable.")
    occupied = HyperVConsoleSession.objects.filter(
        tenant=virtual_machine.tenant,
        vm_source_id=virtual_machine.source_id,
        status__in=ACTIVE_STATUSES,
    ).first()
    if occupied:
        return None, occupied
    try:
        # Keep the uniqueness race inside a savepoint so the outer transaction
        # can safely read and return the winning session after a conflict.
        with transaction.atomic():
            session = HyperVConsoleSession.objects.create(
                tenant=virtual_machine.tenant,
                enrollment=enrollment,
                virtual_machine=virtual_machine,
                vm_source_id=virtual_machine.source_id,
                vm_name=virtual_machine.name,
                requested_by=actor,
                lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
                last_activity_at=now,
            )
    except IntegrityError:
        occupied = HyperVConsoleSession.objects.filter(
            tenant=virtual_machine.tenant,
            vm_source_id=virtual_machine.source_id,
            status__in=ACTIVE_STATUSES,
        ).first()
        return None, occupied
    AuditEvent.objects.create(
        tenant=virtual_machine.tenant,
        actor=actor,
        action="hyperv.virtual_machine.console.open",
        object_type="hyperv_console_session",
        object_id=str(session.id),
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={"virtual_machine_id": str(virtual_machine.id)},
    )
    return session, None


@transaction.atomic
def renew_console_session(*, session, actor: str):
    now = timezone.now()
    session = HyperVConsoleSession.objects.select_for_update().get(
        id=session.id,
        tenant=session.tenant,
    )
    if session.status not in ACTIVE_STATUSES:
        return session
    if session.requested_by != actor:
        raise ValidationError("The console session is owned by another user.")
    if session.lease_expires_at < now:
        session.status = HyperVConsoleSession.Status.EXPIRED
        session.failure_code = "browser_lease_expired"
        session.closed_at = now
        session.frame_png = b""
        session.save(
            update_fields=("status", "failure_code", "closed_at", "frame_png")
        )
        return session
    session.last_activity_at = now
    session.lease_expires_at = now + timedelta(seconds=LEASE_SECONDS)
    session.save(update_fields=("last_activity_at", "lease_expires_at"))
    return session


@transaction.atomic
def close_console_session(*, session, actor: str):
    session = HyperVConsoleSession.objects.select_for_update().get(
        id=session.id,
        tenant=session.tenant,
    )
    if session.status not in ACTIVE_STATUSES:
        return session
    if session.requested_by != actor:
        raise ValidationError("The console session is owned by another user.")
    session.status = HyperVConsoleSession.Status.CLOSED
    session.closed_at = timezone.now()
    session.frame_png = b""
    session.save(update_fields=("status", "closed_at", "frame_png"))
    AuditEvent.objects.create(
        tenant=session.tenant,
        actor=actor,
        action="hyperv.virtual_machine.console.close",
        object_type="hyperv_console_session",
        object_id=str(session.id),
        outcome=AuditEvent.Outcome.SUCCEEDED,
        details={},
    )
    return session


def _validated_input(event_type: str, payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValidationError("The console input payload is invalid.")
    if event_type == HyperVConsoleInputEvent.EventType.KEY:
        if set(payload) != {"key_code", "is_down"}:
            raise ValidationError("The console key input is invalid.")
        key_code = payload["key_code"]
        is_down = payload["is_down"]
        if type(key_code) is not int or not 8 <= key_code <= 255 or type(is_down) is not bool:
            raise ValidationError("The console key input is invalid.")
        return {"key_code": key_code, "is_down": is_down}
    if event_type == HyperVConsoleInputEvent.EventType.MOUSE_MOVE:
        if set(payload) != {"x", "y"}:
            raise ValidationError("The console mouse position is invalid.")
        x, y = payload["x"], payload["y"]
        if type(x) is not int or type(y) is not int or not 0 <= x <= 4095 or not 0 <= y <= 4095:
            raise ValidationError("The console mouse position is invalid.")
        return {"x": x, "y": y}
    if event_type == HyperVConsoleInputEvent.EventType.MOUSE_BUTTON:
        if set(payload) != {"button", "is_down"}:
            raise ValidationError("The console mouse button input is invalid.")
        button, is_down = payload["button"], payload["is_down"]
        if type(button) is not int or button not in (1, 2, 3) or type(is_down) is not bool:
            raise ValidationError("The console mouse button input is invalid.")
        return {"button": button, "is_down": is_down}
    if event_type == HyperVConsoleInputEvent.EventType.MOUSE_WHEEL:
        if set(payload) != {"delta"} or type(payload["delta"]) is not int:
            raise ValidationError("The console mouse wheel input is invalid.")
        delta = max(-1200, min(1200, payload["delta"]))
        return {"delta": delta}
    if event_type == HyperVConsoleInputEvent.EventType.SECURE_ATTENTION:
        if payload:
            raise ValidationError("The secure attention request is invalid.")
        return {}
    raise ValidationError("The console input type is invalid.")


@transaction.atomic
def queue_console_input(*, session, actor: str, event_type: str, payload: object):
    session = HyperVConsoleSession.objects.select_for_update().get(
        id=session.id,
        tenant=session.tenant,
    )
    if session.status not in ACTIVE_STATUSES or session.lease_expires_at < timezone.now():
        raise ValidationError("The console session is no longer active.")
    if session.requested_by != actor:
        raise ValidationError("The console session is owned by another user.")
    validated = _validated_input(event_type, payload)
    if event_type == HyperVConsoleInputEvent.EventType.MOUSE_MOVE:
        pending_move = session.input_events.filter(
            event_type=event_type,
            delivered_at__isnull=True,
        ).order_by("-created_at").first()
        if pending_move:
            pending_move.payload = validated
            pending_move.save(update_fields=("payload",))
            return pending_move
    if session.input_events.count() >= MAX_INPUT_EVENTS:
        raise ValidationError("The console input queue is full.")
    event = HyperVConsoleInputEvent.objects.create(
        session=session,
        event_type=event_type,
        payload=validated,
    )
    if event_type == HyperVConsoleInputEvent.EventType.SECURE_ATTENTION:
        AuditEvent.objects.create(
            tenant=session.tenant,
            actor=actor,
            action="hyperv.virtual_machine.console.secure_attention",
            object_type="hyperv_console_session",
            object_id=str(session.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            details={},
        )
    return event


def _decode_frame(value: object) -> bytes:
    if not isinstance(value, str) or len(value) > (MAX_FRAME_BYTES * 4 // 3) + 8:
        raise ValidationError("The console frame is invalid.")
    try:
        frame = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("The console frame is invalid.") from exc
    if not 0 < len(frame) <= MAX_FRAME_BYTES or not frame.startswith(PNG_SIGNATURE):
        raise ValidationError("The console frame is invalid.")
    return frame


@transaction.atomic
def process_console_cycle(
    enrollment,
    *,
    session_id: str,
    frame_png_base64: object,
    frame_width: object,
    frame_height: object,
    acknowledged_input_ids: object,
    failure_code: str,
):
    now = timezone.now()
    _expire_stale_sessions(now)
    reported_session = None
    if session_id:
        reported_session = HyperVConsoleSession.objects.select_for_update().filter(
            id=session_id,
            enrollment=enrollment,
            tenant=enrollment.tenant,
        ).first()
        if reported_session is None:
            raise ValidationError("The console session identity is invalid.")
        if not isinstance(acknowledged_input_ids, list) or len(acknowledged_input_ids) > MAX_INPUT_BATCH:
            raise ValidationError("The console input acknowledgement is invalid.")
        acknowledgement_ids = []
        for value in acknowledged_input_ids:
            if not isinstance(value, str) or len(value) != 36:
                raise ValidationError("The console input acknowledgement is invalid.")
            acknowledgement_ids.append(value)
        reported_session.input_events.filter(id__in=acknowledgement_ids).delete()
        if reported_session.status in ACTIVE_STATUSES:
            reported_session.last_agent_contact_at = now
            update_fields = ["last_agent_contact_at"]
            if failure_code:
                if not FAILURE_CODE_PATTERN.fullmatch(failure_code):
                    raise ValidationError("The console failure code is invalid.")
                reported_session.status = HyperVConsoleSession.Status.FAILED
                reported_session.failure_code = failure_code
                reported_session.closed_at = now
                reported_session.frame_png = b""
                update_fields.extend(("status", "failure_code", "closed_at", "frame_png"))
            elif frame_png_base64:
                if (
                    type(frame_width) is not int
                    or type(frame_height) is not int
                    or not 160 <= frame_width <= 1920
                    or not 120 <= frame_height <= 1200
                ):
                    raise ValidationError("The console frame dimensions are invalid.")
                reported_session.frame_png = _decode_frame(frame_png_base64)
                reported_session.frame_width = frame_width
                reported_session.frame_height = frame_height
                reported_session.frame_sequence += 1
                if reported_session.status == HyperVConsoleSession.Status.REQUESTED:
                    reported_session.status = HyperVConsoleSession.Status.ACTIVE
                    reported_session.connected_at = now
                    update_fields.extend(("status", "connected_at"))
                update_fields.extend(
                    ("frame_png", "frame_width", "frame_height", "frame_sequence")
                )
            reported_session.save(update_fields=tuple(dict.fromkeys(update_fields)))

    session = (
        HyperVConsoleSession.objects.select_for_update()
        .filter(enrollment=enrollment, status__in=ACTIVE_STATUSES)
        .order_by(F("last_agent_contact_at").asc(nulls_first=True), "created_at")
        .first()
    )
    if session is None:
        return None
    events = list(session.input_events.order_by("created_at")[:MAX_INPUT_BATCH])
    session.input_events.filter(id__in=[event.id for event in events]).update(
        delivered_at=now
    )
    return {
        "session_id": str(session.id),
        "vm_source_id": session.vm_source_id,
        "vm_name": session.vm_name,
        "width": 1024,
        "height": 768,
        "inputs": [
            {
                "id": str(event.id),
                "type": event.event_type,
                **event.payload,
            }
            for event in events
        ],
    }
