import base64
import json
import os
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from .models import ConnectorSecret


def _key() -> bytes:
    try:
        key = base64.b64decode(settings.CONNECTOR_MASTER_KEY, validate=True)
    except (ValueError, TypeError) as exc:
        raise ImproperlyConfigured("IPMS_CONNECTOR_MASTER_KEY must be valid base64.") from exc
    if len(key) != 32:
        raise ImproperlyConfigured("IPMS_CONNECTOR_MASTER_KEY must decode to 32 bytes.")
    return key


def _associated_data(tenant_id: UUID, secret_id: UUID) -> bytes:
    return f"ipms:connector-secret:v1:{tenant_id}:{secret_id}".encode()


def store_connector_secret(*, tenant, secret_id: UUID, username: str, password: str) -> ConnectorSecret:
    plaintext = json.dumps(
        {"username": username, "password": password},
        separators=(",", ":"),
    ).encode()
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(
        nonce,
        plaintext,
        _associated_data(tenant.id, secret_id),
    )
    secret, _ = ConnectorSecret.objects.update_or_create(
        id=secret_id,
        defaults={
            "tenant": tenant,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "key_version": 1,
        },
    )
    return secret


def load_connector_secret(*, tenant_id: UUID, secret_id: UUID) -> tuple[str, str]:
    secret = ConnectorSecret.objects.get(id=secret_id, tenant_id=tenant_id)
    plaintext = AESGCM(_key()).decrypt(
        bytes(secret.nonce),
        bytes(secret.ciphertext),
        _associated_data(tenant_id, secret_id),
    )
    document = json.loads(plaintext)
    return document["username"], document["password"]
