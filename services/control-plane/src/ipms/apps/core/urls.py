from django.urls import include, path

from ipms.apps.discovery.views import (
    BmcCertificateProbeView,
    BmcCommunicationLogExportView,
    BmcCommunicationLogListView,
    BmcEventLogEntryListView,
    BmcEventLogEntryExportView,
    BmcConnectorEnrollmentView,
    ConnectorCredentialView,
    ConnectorDetailView,
    ConnectorDiscoveryView,
    ConnectorEndpointListView,
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
    path("connectors/bmc/", BmcConnectorEnrollmentView.as_view(), name="bmc-enroll"),
    path(
        "connectors/bmc/certificate/",
        BmcCertificateProbeView.as_view(),
        name="bmc-certificate-probe",
    ),
    path(
        "connectors/<uuid:pk>/",
        ConnectorDetailView.as_view(),
        name="connector-detail",
    ),
    path(
        "connectors/<uuid:pk>/credentials/",
        ConnectorCredentialView.as_view(),
        name="connector-credentials",
    ),
    path(
        "connectors/<uuid:pk>/discover/",
        ConnectorDiscoveryView.as_view(),
        name="connector-discover",
    ),
    path("physical-systems/", PhysicalSystemListView.as_view(), name="physical-list"),
    path("bmc-logs/", BmcCommunicationLogListView.as_view(), name="bmc-log-list"),
    path(
        "bmc-event-logs/",
        BmcEventLogEntryListView.as_view(),
        name="bmc-event-log-list",
    ),
    path(
        "bmc-event-logs/export/",
        BmcEventLogEntryExportView.as_view(),
        name="bmc-event-log-export",
    ),
    path(
        "bmc-logs/export/",
        BmcCommunicationLogExportView.as_view(),
        name="bmc-log-export",
    ),
    path("discovery-jobs/", include("ipms.apps.discovery.urls")),
]
