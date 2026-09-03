import os
import re

from django.core.exceptions import ImproperlyConfigured


def required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ImproperlyConfigured(f"Required environment variable is missing: {name}")
    return value


SECRET_KEY = required_environment("IPMS_GATEWAY_SECRET_KEY")
DEBUG = False
USE_TZ = True
TIME_ZONE = "UTC"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "ipms.apps.tenancy",
    "ipms.apps.audit",
    "ipms.apps.agent_pki",
    "ipms.apps.discovery",
]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": required_environment("IPMS_DATABASE_NAME"),
        "USER": required_environment("IPMS_DATABASE_USER"),
        "PASSWORD": required_environment("IPMS_DATABASE_PASSWORD"),
        "HOST": required_environment("IPMS_DATABASE_HOST"),
        "PORT": os.environ.get("IPMS_DATABASE_PORT", "5432"),
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"sslmode": os.environ.get("IPMS_DATABASE_SSLMODE", "prefer")},
    }
}
AGENT_PKI_MASTER_KEY = required_environment("IPMS_AGENT_PKI_MASTER_KEY")
AGENT_WINDOWS_PACKAGE_PATH = required_environment(
    "IPMS_AGENT_WINDOWS_PACKAGE_PATH"
)
AGENT_WINDOWS_PACKAGE_SHA256 = required_environment(
    "IPMS_AGENT_WINDOWS_PACKAGE_SHA256"
).lower()
if not re.fullmatch(r"[0-9a-f]{64}", AGENT_WINDOWS_PACKAGE_SHA256):
    raise ImproperlyConfigured(
        "IPMS_AGENT_WINDOWS_PACKAGE_SHA256 must be a SHA-256 digest."
    )
AGENT_WINDOWS_VERSION = required_environment("IPMS_AGENT_WINDOWS_VERSION")
if not re.fullmatch(
    r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}",
    AGENT_WINDOWS_VERSION,
):
    raise ImproperlyConfigured(
        "IPMS_AGENT_WINDOWS_VERSION must be a three-part numeric version."
    )
