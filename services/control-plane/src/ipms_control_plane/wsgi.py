import os

from django.core.wsgi import get_wsgi_application


os.environ.setdefault(
    "DJANGO_SETTINGS_MODULE",
    "ipms_control_plane.settings.production",
)

application = get_wsgi_application()
