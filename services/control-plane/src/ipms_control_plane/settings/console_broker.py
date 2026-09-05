"""Least-privilege native broker settings; no connector, deployment or CA keys."""
import os

from django.core.exceptions import ImproperlyConfigured


def required_environment(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ImproperlyConfigured(f"Required environment variable is missing: {name}")
    return value


# Must equal the Control Plane's real Django session signing key. A separate
# Gateway key cannot authenticate browser cookies. No fallback/rotation writes
# are allowed by the broker's read-only session store.
SECRET_KEY = required_environment("IPMS_SECRET_KEY")
DEBUG = False
USE_TZ = True
TIME_ZONE = "UTC"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
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
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
SESSION_ENGINE = "django.contrib.sessions.backends.db"
SESSION_COOKIE_NAME = "ipms_sessionid"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Lax"
NATIVE_CONSOLE_KEY_FILE = required_environment("IPMS_NATIVE_CONSOLE_KEY_FILE")
NATIVE_CONSOLE_ORIGIN = required_environment("IPMS_NATIVE_CONSOLE_ORIGIN")
