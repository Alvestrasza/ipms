from __future__ import annotations

from django.core import signing


WINDOWS_DEPLOYMENT_APPROVAL_SALT = "ipms.windows-deployment-approval.v1"
WINDOWS_DEPLOYMENT_APPROVAL_MAX_AGE_SECONDS = 10 * 60


class WindowsDeploymentApprovalError(Exception):
    pass


def create_windows_deployment_approval(
    *,
    tenant_id: str,
    address: str,
    port: int,
    transport: str,
    fingerprint_sha256: str = "",
    trusted_by_system: bool = False,
) -> str:
    return signing.dumps(
        {
            "tenant_id": tenant_id,
            "address": address,
            "port": port,
            "transport": transport,
            "fingerprint_sha256": fingerprint_sha256,
            "trusted_by_system": trusted_by_system,
        },
        salt=WINDOWS_DEPLOYMENT_APPROVAL_SALT,
        compress=True,
    )


def load_windows_deployment_approval(token: str) -> dict[str, object]:
    try:
        document = signing.loads(
            token,
            salt=WINDOWS_DEPLOYMENT_APPROVAL_SALT,
            max_age=WINDOWS_DEPLOYMENT_APPROVAL_MAX_AGE_SECONDS,
        )
    except signing.SignatureExpired as exc:
        raise WindowsDeploymentApprovalError(
            "windows_deployment_approval_expired"
        ) from exc
    except signing.BadSignature as exc:
        raise WindowsDeploymentApprovalError(
            "windows_deployment_approval_invalid"
        ) from exc
    if not isinstance(document, dict):
        raise WindowsDeploymentApprovalError("windows_deployment_approval_invalid")
    return document
