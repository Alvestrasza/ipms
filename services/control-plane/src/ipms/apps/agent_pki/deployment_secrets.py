import base64
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .models import WindowsAgentDeployment, WindowsAgentDeploymentSecret


def _master_key() -> bytes:
    try:
        key = base64.b64decode(settings.AGENT_DEPLOYMENT_MASTER_KEY, validate=True)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured(
            "IPMS_AGENT_DEPLOYMENT_MASTER_KEY must be base64-encoded."
        ) from exc
    if len(key) != 32:
        raise ImproperlyConfigured(
            "IPMS_AGENT_DEPLOYMENT_MASTER_KEY must decode to exactly 32 bytes."
        )
    return key


def _associated_data(deployment: WindowsAgentDeployment) -> bytes:
    return (
        f"ipms:agent-deployment:v1:{deployment.tenant_id}:{deployment.id}"
    ).encode()


def store_deployment_secret(
    deployment: WindowsAgentDeployment,
    *,
    username: str,
    password: str,
    bootstrap_token: str,
) -> WindowsAgentDeploymentSecret:
    plaintext = json.dumps(
        {
            "username": username,
            "password": password,
            "bootstrap_token": bootstrap_token,
        },
        separators=(",", ":"),
    ).encode()
    nonce = os.urandom(12)
    ciphertext = AESGCM(_master_key()).encrypt(
        nonce,
        plaintext,
        _associated_data(deployment),
    )
    return WindowsAgentDeploymentSecret.objects.create(
        deployment=deployment,
        tenant=deployment.tenant,
        nonce=nonce,
        ciphertext=ciphertext,
    )


def load_deployment_secret(secret: WindowsAgentDeploymentSecret) -> dict[str, str]:
    plaintext = AESGCM(_master_key()).decrypt(
        bytes(secret.nonce),
        bytes(secret.ciphertext),
        _associated_data(secret.deployment),
    )
    document = json.loads(plaintext)
    if not isinstance(document, dict) or set(document) != {
        "username",
        "password",
        "bootstrap_token",
    }:
        raise ValueError("The Agent deployment secret is invalid.")
    if any(not isinstance(value, str) for value in document.values()):
        raise ValueError("The Agent deployment secret is invalid.")
    return document
