from django.urls import include, path

from . import views


app_name = "core"

urlpatterns = [
    path("", views.api_information, name="api-information"),
    path("health/live/", views.liveness, name="liveness"),
    path("health/ready/", views.readiness, name="readiness"),
    path("discovery-jobs/", include("ipms.apps.discovery.urls")),
]
