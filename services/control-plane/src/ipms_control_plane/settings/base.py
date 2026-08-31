import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured


BASE_DIR = Path(__file__).resolve().parents[3]


def required_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ImproperlyConfigured(f"Required environment variable is missing: {name}")
    return value


def comma_separated_environment(name: str, *, required: bool = False) -> list[str]:
    raw_value = os.environ.get(name, "")
    values = [value.strip() for value in raw_value.split(",") if value.strip()]
    if required and not values:
        raise ImproperlyConfigured(f"Required environment variable is missing: {name}")
    return values


def bounded_integer_environment(
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw_value = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ImproperlyConfigured(f"Environment variable must be an integer: {name}") from exc
    if not minimum <= value <= maximum:
        raise ImproperlyConfigured(
            f"Environment variable must be between {minimum} and {maximum}: {name}"
        )
    return value


SECRET_KEY = required_environment("IPMS_SECRET_KEY")
CONNECTOR_MASTER_KEY = required_environment("IPMS_CONNECTOR_MASTER_KEY")
CERTIFICATE_PROBE_TOKEN = required_environment("IPMS_CERTIFICATE_PROBE_TOKEN")
CERTIFICATE_PROBE_PORT = bounded_integer_environment(
    "IPMS_CERTIFICATE_PROBE_PORT",
    default=8010,
    minimum=1024,
    maximum=65535,
)
BMC_CONNECT_TIMEOUT_SECONDS = bounded_integer_environment(
    "IPMS_BMC_CONNECT_TIMEOUT_SECONDS",
    default=20,
    minimum=5,
    maximum=60,
)
DEBUG = False
ALLOWED_HOSTS = comma_separated_environment("IPMS_ALLOWED_HOSTS", required=True)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "ipms.apps.core",
    "ipms.apps.tenancy",
    "ipms.apps.audit",
    "ipms.apps.discovery",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "ipms.apps.core.middleware.CorrelationIdMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "ipms_control_plane.urls"
WSGI_APPLICATION = "ipms_control_plane.wsgi.application"
ASGI_APPLICATION = "ipms_control_plane.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
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

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication"
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "EXCEPTION_HANDLER": "ipms.apps.core.exceptions.ipms_exception_handler",
}

CSRF_TRUSTED_ORIGINS = comma_separated_environment("IPMS_CSRF_TRUSTED_ORIGINS")
CSRF_FAILURE_VIEW = "ipms.apps.core.views.csrf_failure"
SESSION_COOKIE_NAME = "ipms_sessionid"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_NAME = "ipms_csrftoken"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
