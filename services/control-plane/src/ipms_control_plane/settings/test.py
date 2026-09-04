import os


os.environ.setdefault("IPMS_SECRET_KEY", "test-only-not-for-deployment")
os.environ.setdefault(
    "IPMS_CONNECTOR_MASTER_KEY",
    "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
)
os.environ.setdefault(
    "IPMS_AGENT_PKI_MASTER_KEY",
    "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=",
)
os.environ.setdefault(
    "IPMS_AGENT_DEPLOYMENT_MASTER_KEY",
    "YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODk=",
)
os.environ.setdefault(
    "IPMS_AGENT_WINDOWS_PACKAGE_PATH",
    "/tmp/ipms-agent-windows-test.zip",
)
os.environ.setdefault(
    "IPMS_AGENT_WINDOWS_PACKAGE_SHA256",
    "0" * 64,
)
os.environ.setdefault("IPMS_AGENT_WINDOWS_VERSION", "0.2.15")
os.environ.setdefault("IPMS_ALLOWED_HOSTS", "testserver")
os.environ.setdefault("IPMS_CERTIFICATE_PROBE_TOKEN", "test-only-probe-token")
os.environ.setdefault("IPMS_DATABASE_NAME", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_USER", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_PASSWORD", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_HOST", "unused-in-test-settings")

from .base import *  # noqa: E402,F403


DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
