"""Local identity changes with permanent names and freshly revalidated authority."""

from contextlib import contextmanager
from ipaddress import ip_address

from django.contrib.auth import HASH_SESSION_KEY, get_user_model
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils.crypto import constant_time_compare
from django.views.decorators.debug import sensitive_variables

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from .models import ExternalIdentity, Tenant, TenantMembership, UsernameReservation
from .rbac import (
    Permission,
    has_tenant_permission,
    is_platform_administrator,
    is_tenant_principal,
)


def normalize_username(username):
    return get_user_model().normalize_username(username).casefold()


def validate_username(username):
    model = get_user_model()
    username = model.normalize_username(username)
    try:
        for validator in model._meta.get_field(model.USERNAME_FIELD).validators:
            validator(username)
    except ValidationError:
        raise PublicApiError("invalid_request") from None
    return username


def reserve_username(username, *, user=None, current=False):
    """Caller holds the relevant user lock, or is creating a new principal."""
    normalized = normalize_username(username)
    # Migration seeds every existing identity. This check also fails closed for
    # externally created or fixture accounts which bypass the supported helpers.
    for existing_id, existing_name in (
        get_user_model().objects.values_list("pk", "username").iterator()
    ):
        if normalize_username(existing_name) == normalized and (
            user is None or existing_id != user.pk
        ):
            raise PublicApiError("username_unavailable", status_code=409)
    existing = UsernameReservation.objects.filter(pk=normalized).first()
    if existing is not None:
        if current and user is not None and existing.user_id == user.pk:
            return existing
        raise PublicApiError("username_unavailable", status_code=409)
    try:
        with transaction.atomic():
            return UsernameReservation.objects.create(
                normalized_username=normalized, user=user
            )
    except IntegrityError:
        raise PublicApiError("username_unavailable", status_code=409) from None


@sensitive_variables()
@transaction.atomic
def create_local_user(*, username, password, **attributes):
    username = validate_username(username)
    reservation = reserve_username(username)
    user = get_user_model().objects.create_user(
        username=username, password=password, **attributes
    )
    reservation.user = user
    reservation.save(update_fields=("user",))
    return user


def authentication_source(user):
    external = any(
        identity.is_active for identity in user.ipms_external_identities.all()
    )
    return (
        "hybrid"
        if external and user.has_usable_password()
        else "oidc" if external else "local"
    )


def can_manage_own_identity(user):
    return bool(
        user.is_authenticated
        and user.is_active
        and not user.is_staff
        and not user.is_superuser
        and (is_tenant_principal(user) or is_platform_administrator(user))
    )


def is_local_identity(user):
    return (
        user.has_usable_password()
        and not ExternalIdentity.objects.filter(user=user, is_active=True).exists()
    )


def tenant_identity_capabilities(membership, actor):
    allowed = bool(
        actor is not None
        and is_local_identity(actor)
        and has_tenant_permission(actor, membership.tenant, Permission.USERS_MANAGE)
        and is_tenant_principal(membership.user)
        and is_local_identity(membership.user)
        and not TenantMembership.objects.filter(user_id=membership.user_id)
        .exclude(tenant_id=membership.tenant_id)
        .exists()
    )
    return {
        "can_rename": allowed,
        "can_reset_password": allowed and actor.pk != membership.user_id,
    }


@contextmanager
def locked_identities(actor_id, target_id, selected_tenant_id=None):
    """Tenant-before-user ordering also serializes membership and queue mutation."""
    user_ids = sorted({actor_id, target_id})
    with transaction.atomic():
        tenant_ids = set(
            TenantMembership.objects.filter(user_id__in=user_ids).values_list(
                "tenant_id", flat=True
            )
        )
        if selected_tenant_id is not None:
            tenant_ids.add(selected_tenant_id)
        tenants = {
            tenant.pk: tenant
            for tenant in Tenant.objects.select_for_update(no_key=True)
            .filter(pk__in=tenant_ids)
            .order_by("pk")
        }
        users = {
            user.pk: user
            for user in get_user_model()
            .objects.select_for_update(no_key=True)
            .filter(pk__in=user_ids)
            .order_by("pk")
        }
        # If a membership committed between the snapshot and locks, retry from a
        # fresh request rather than acquiring a late tenant lock below a user.
        current_tenants = set(
            TenantMembership.objects.filter(user_id__in=user_ids).values_list(
                "tenant_id", flat=True
            )
        )
        if not current_tenants.issubset(tenant_ids):
            raise PublicApiError("forbidden", status_code=403)
        if actor_id not in users or target_id not in users:
            raise PublicApiError("user_not_found", status_code=404)
        yield users[actor_id], users[target_id], tenants


@sensitive_variables()
def reauthenticate(request, actor, current_password):
    session_hash = request.session.get(HASH_SESSION_KEY, "")
    if (
        not can_manage_own_identity(actor)
        or not is_local_identity(actor)
        or not session_hash
        or not constant_time_compare(session_hash, actor.get_session_auth_hash())
        # Reauthentication only verifies. User.check_password() may upgrade a
        # legacy hash and invalidate the otherwise retained administrator session.
        or not check_password(current_password, actor.password)
    ):
        raise PublicApiError("current_password_invalid", status_code=403)


def check_target(target, *, tenant_id=None, actor=None, password=False):
    if not target.is_active:
        raise PublicApiError("user_inactive", status_code=409)
    if tenant_id is not None:
        if not is_tenant_principal(target):
            raise PublicApiError("user_not_found", status_code=404)
        if (
            TenantMembership.objects.filter(user=target)
            .exclude(tenant_id=tenant_id)
            .exists()
        ):
            raise PublicApiError("shared_identity_protected", status_code=409)
        if password and target.pk == actor.pk:
            raise PublicApiError("self_password_reset_denied", status_code=409)
    elif not can_manage_own_identity(target):
        raise PublicApiError("forbidden", status_code=403)
    if not is_local_identity(target):
        raise PublicApiError("external_identity_managed", status_code=409)


def audit_identity(
    request, *, actor, target_id, action, outcome, tenant=None, **details
):
    try:
        source_ip = str(ip_address(request.META.get("REMOTE_ADDR", "")))
    except ValueError:
        source_ip = None
    AuditEvent.objects.create(
        tenant=tenant,
        actor=actor.get_username()[:255],
        action=f"identity.account.{action}",
        object_type="user",
        object_id=str(target_id),
        outcome=outcome,
        correlation_id=getattr(request, "correlation_id", None),
        source_ip=source_ip,
        details={
            "actor_user_id": str(actor.pk),
            "target_user_id": str(target_id),
            **details,
        },
    )


@sensitive_variables()
def change_identity(request, *, data, action, membership_id=None):
    """Return a fresh target; denied reauthentication is audited after rollback."""
    target_id = request.user.pk
    selected_tenant_id = None
    if membership_id is not None:
        selected_tenant_id = request.tenant.pk
        target_id = (
            TenantMembership.objects.filter(
                pk=membership_id,
                tenant_id=selected_tenant_id,
                user__is_staff=False,
                user__is_superuser=False,
                user__ipms_platform_administrator__isnull=True,
            )
            .values_list("user_id", flat=True)
            .first()
        )
        if target_id is None:
            raise PublicApiError("user_not_found", status_code=404)
    actor_for_audit = request.user
    try:
        with locked_identities(request.user.pk, target_id, selected_tenant_id) as (
            actor,
            target,
            tenants,
        ):
            actor_for_audit = actor
            tenant = tenants.get(selected_tenant_id)
            if membership_id is not None:
                if tenant is None or not has_tenant_permission(
                    actor, tenant, Permission.USERS_MANAGE
                ):
                    raise PublicApiError("forbidden", status_code=403)
                if not TenantMembership.objects.filter(
                    pk=membership_id, tenant=tenant, user=target
                ).exists():
                    raise PublicApiError("user_not_found", status_code=404)
            check_target(
                target,
                tenant_id=selected_tenant_id,
                actor=actor,
                password=action != "rename",
            )
            reauthenticate(request, actor, data["current_password"])
            before = target.username
            from .operations import withdraw_identity_operations

            if action == "rename":
                username = data["username"]
                reserve_username(before, user=target, current=True)
                if normalize_username(username) != normalize_username(before):
                    reserve_username(username, user=target)
                counts = withdraw_identity_operations(target, reason="username_changed")
                target.username = username
                target.save(update_fields=("username",))
            else:
                try:
                    validate_password(data["new_password"], target)
                    if target.check_password(data["new_password"]):
                        raise ValidationError("The password must change.")
                except ValidationError:
                    raise PublicApiError("weak_password") from None
                counts = withdraw_identity_operations(
                    target,
                    reason="password_reset" if membership_id else "password_changed",
                )
                target.set_password(data["new_password"])
                target.save(update_fields=("password",))
            audit_identity(
                request,
                actor=actor,
                target_id=target.pk,
                tenant=tenant,
                action=action,
                outcome=AuditEvent.Outcome.SUCCEEDED,
                previous_username=before,
                current_username=target.username,
                withdrawn=counts,
            )
            return target
    except PublicApiError as exc:
        if exc.public_code == "current_password_invalid":
            audit_identity(
                request,
                actor=actor_for_audit,
                target_id=target_id,
                action=action,
                outcome=AuditEvent.Outcome.DENIED,
                reason="current_password_invalid",
                tenant=getattr(request, "tenant", None),
            )
        raise
    except IntegrityError:
        raise PublicApiError("username_unavailable", status_code=409) from None
