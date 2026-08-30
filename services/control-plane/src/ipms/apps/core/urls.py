from django.urls import include, path

from ipms.apps.discovery.views import (
    ConnectorDiscoveryView,
    ConnectorEndpointListView,
    IloConnectorEnrollmentView,
    PhysicalSystemListView,
)

from . import views


app_name = "core"

urlpatterns = [
    path("", views.api_information, name="api-information"),
    path("health/live/", views.liveness, name="liveness"),
    path("health/ready/", views.readiness, name="readiness"),
    path("auth/", include("ipms.apps.tenancy.urls")),
    path("connectors/", ConnectorEndpointListView.as_view(), name="connector-list"),
    path("connectors/ilo/", IloConnectorEnrollmentView.as_view(), name="ilo-enroll"),
    path(
        "connectors/<uuid:pk>/discover/",
        ConnectorDiscoveryView.as_view(),
        name="connector-discover",
    ),
    path("physical-systems/", PhysicalSystemListView.as_view(), name="physical-list"),
    path("discovery-jobs/", include("ipms.apps.discovery.urls")),
]
