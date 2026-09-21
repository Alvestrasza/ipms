# File Name: onboarding.py
# Version: v0.2.76 | Created: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Platform-visible tenant Agent PKI, Gateway and package readiness.
"""Bounded readiness checks for first-Agent tenant onboarding."""

import hashlib
import socket
import ssl
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ipms.apps.tenancy.models import Tenant, TenantMembership

from .models import AgentPkiPolicy, AgentPkiRecoveryMaterial


MINIMUM_HGS_AGENT_VERSION = (0, 2, 49)


def _administrator_ready(tenant: Tenant) -> bool:
    if tenant.initial_administrator_created_at is not None:
        return True
    return (
        TenantMembership.objects.filter(
            tenant=tenant,
            role=TenantMembership.Role.TENANT_ADMIN,
            user__is_active=True,
        )
        .exclude(user__is_staff=True)
        .exclude(user__is_superuser=True)
        .filter(user__ipms_platform_administrator__isnull=True)
        .exists()
    )


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except ValueError:
        return None
    return parts if len(parts) == 3 else None


def agent_package_status(*, tenant: Tenant) -> dict:
    path = Path(settings.AGENT_WINDOWS_PACKAGE_PATH)
    configured_digest = settings.AGENT_WINDOWS_PACKAGE_SHA256.lower()
    version = settings.AGENT_WINDOWS_VERSION
    reason = ""
    observed_digest = ""
    try:
        if not path.is_file():
            reason = "package_missing"
        else:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            observed_digest = digest.hexdigest()
            if observed_digest != configured_digest:
                reason = "package_digest_mismatch"
    except OSError:
        reason = "package_unreadable"
    parsed_version = _version_tuple(version)
    if not reason and parsed_version is None:
        reason = "package_version_invalid"
    if (
        not reason
        and tenant.purpose == Tenant.Purpose.HGS
        and parsed_version < MINIMUM_HGS_AGENT_VERSION
    ):
        reason = "package_hgs_version_too_old"
    return {
        "ready": not reason,
        "reason": reason,
        "version": version,
        "sha256": configured_digest,
        "observed_sha256": observed_digest,
        "filename": path.name,
        "minimum_hgs_version": ".".join(str(part) for part in MINIMUM_HGS_AGENT_VERSION),
    }


def tenant_agent_onboarding_status(*, tenant: Tenant) -> dict:
    administrator_ready = _administrator_ready(tenant)
    try:
        policy = AgentPkiPolicy.objects.select_related("gateway_identity").get(tenant=tenant)
    except AgentPkiPolicy.DoesNotExist:
        policy = None
    recovery = None
    if policy is not None:
        recovery = AgentPkiRecoveryMaterial.objects.filter(policy=policy).first()
    recovery_ready = bool(
        policy
        and (
            policy.trust_mode != AgentPkiPolicy.TrustMode.IPMS_MANAGED
            or policy.root_recovery_exported_at is not None
        )
    )
    gateway_ready = bool(
        policy
        and policy.gateway_last_verified_at
        and not policy.gateway_last_verification_error
        and policy.gateway_last_verified_fingerprint_sha256
        == policy.gateway_identity.fingerprint_sha256
    )
    package = agent_package_status(tenant=tenant)
    if policy is None:
        state = "missing"
    elif recovery is not None:
        state = "recovery_pending"
    elif recovery_ready:
        state = "ready"
    else:
        state = "incomplete"
    return {
        "tenant_id": str(tenant.id),
        "tenant_slug": tenant.slug,
        "tenant_purpose": tenant.purpose,
        "administrator_ready": administrator_ready,
        "pki": {
            "state": state,
            "trust_mode": policy.trust_mode if policy else "",
            "gateway_dns_name": policy.gateway_dns_name if policy else "",
            "gateway_port": policy.gateway_port if policy else settings.AGENT_GATEWAY_PORT,
            "root_fingerprint_sha256": policy.root_fingerprint_sha256 if policy else "",
            "gateway_fingerprint_sha256": (
                policy.gateway_identity.fingerprint_sha256 if policy else ""
            ),
            "recovery_bundle_sha256": recovery.bundle_sha256 if recovery else "",
            "recovery_downloaded": bool(recovery and recovery.downloaded_at),
            "recovery_confirmed_at": (
                policy.root_recovery_exported_at.isoformat()
                if policy and policy.root_recovery_exported_at
                else None
            ),
        },
        "gateway": {
            "ready": gateway_ready,
            "last_verified_at": (
                policy.gateway_last_verified_at.isoformat()
                if policy and policy.gateway_last_verified_at
                else None
            ),
            "error": policy.gateway_last_verification_error if policy else "not_configured",
        },
        "package": package,
        "ready_for_enrollment": bool(
            tenant.status == Tenant.Status.ACTIVE
            and administrator_ready
            and recovery_ready
            and gateway_ready
            and package["ready"]
        ),
    }


def _probe_gateway(policy: AgentPkiPolicy) -> str:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cadata=policy.root_certificate_pem)
    context.set_alpn_protocols(["http/1.1"])
    probe_host = settings.AGENT_GATEWAY_PROBE_HOST or policy.gateway_dns_name
    with socket.create_connection(
        (probe_host, policy.gateway_port), timeout=3
    ) as connection:
        with context.wrap_socket(
            connection,
            server_hostname=policy.gateway_dns_name,
        ) as tls_connection:
            certificate = tls_connection.getpeercert(binary_form=True)
    if not certificate:
        raise ssl.SSLError("Gateway certificate unavailable")
    return hashlib.sha256(certificate).hexdigest()


def _probe_error_code(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "gateway_timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "gateway_connection_refused"
    if isinstance(exc, ssl.SSLError):
        return "gateway_tls_rejected"
    if isinstance(exc, OSError):
        return "gateway_unreachable"
    return "gateway_probe_failed"


def verify_gateway_isolation(*, requested_tenant: Tenant) -> dict:
    policies = list(
        AgentPkiPolicy.objects.select_related("tenant", "gateway_identity")
        .filter(tenant__status__in=(Tenant.Status.ACTIVE, Tenant.Status.SUSPENDED))
        .order_by("tenant__slug")
    )
    results: dict[str, dict] = {}
    for policy in policies:
        error = ""
        observed = ""
        try:
            observed = _probe_gateway(policy)
            if observed != policy.gateway_identity.fingerprint_sha256:
                error = "gateway_fingerprint_mismatch"
        except Exception as exc:
            error = _probe_error_code(exc)
        results[str(policy.tenant_id)] = {
            "tenant_slug": policy.tenant.slug,
            "ready": not error,
            "error": error,
            "observed_fingerprint_sha256": observed,
        }
    checked_at = timezone.now()
    with transaction.atomic():
        for policy in policies:
            result = results[str(policy.tenant_id)]
            AgentPkiPolicy.objects.filter(id=policy.id).update(
                gateway_last_verified_at=checked_at if result["ready"] else None,
                gateway_last_verified_fingerprint_sha256=(
                    policy.gateway_identity.fingerprint_sha256 if result["ready"] else ""
                ),
                gateway_last_verification_error=result["error"],
            )
    target = results.get(str(requested_tenant.id), {
        "tenant_slug": requested_tenant.slug,
        "ready": False,
        "error": "gateway_not_configured",
        "observed_fingerprint_sha256": "",
    })
    return {
        "checked_at": checked_at.isoformat(),
        "probe_mode": (
            "configured_override"
            if settings.AGENT_GATEWAY_PROBE_HOST
            else "tenant_dns"
        ),
        "requested_tenant": target,
        "all_tenants_preserved": bool(results) and all(
            result["ready"] for result in results.values()
        ),
        "results": list(results.values()),
    }
