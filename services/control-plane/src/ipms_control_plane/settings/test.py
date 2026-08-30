import os


os.environ.setdefault("IPMS_SECRET_KEY", "test-only-not-for-deployment")
os.environ.setdefault("IPMS_ALLOWED_HOSTS", "testserver")
os.environ.setdefault("IPMS_DATABASE_NAME", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_USER", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_PASSWORD", "unused-in-test-settings")
os.environ.setdefault("IPMS_DATABASE_HOST", "unused-in-test-settings")

from .base import *  # noqa: E402,F403


DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
