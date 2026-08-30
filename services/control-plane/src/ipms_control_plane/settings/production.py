import os

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403


if not CSRF_TRUSTED_ORIGINS:  # noqa: F405
    raise ImproperlyConfigured(
        "IPMS_CSRF_TRUSTED_ORIGINS must be configured in production"
    )

SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = int(os.environ.get("IPMS_HSTS_SECONDS", "31536000"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
