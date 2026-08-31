import os


os.environ.setdefault("IPMS_SECRET_KEY", "test-only-not-for-deployment")
os.environ.setdefault(
    "IPMS_CONNECTOR_MASTER_KEY",
    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
)
os.environ.setdefault("IPMS_ALLOWED_HOSTS", "testserver")
os.environ.setdefault("IPMS_CERTIFICATE_PROBE_TOKEN", "test-only-probe-token")
os.environ.setdefault("IPMS_DATABASE_NAME", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_USER", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_PASSWORD", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_HOST", "unused-in-test-settings")

from .base import *  # noqa: E402,F403


DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
