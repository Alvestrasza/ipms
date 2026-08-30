"""Browser-test settings. Never use this module for a deployed IPMS instance."""

import os

from .test import *  # noqa: F403


DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.environ.get("IPMS_E2E_DATABASE", BASE_DIR / ".e2e.sqlite3"),  # noqa: F405
    }
}
