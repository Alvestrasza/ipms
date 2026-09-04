from django.urls import include, path

from ipms.apps.agent_pki.views import (
    AgentAdministrationDetailView,
    AgentAdministrationListView,
    AgentLifecycleView,
    WindowsAgentDeploymentDetailView,
    WindowsAgentDeploymentListCreateView,
    WindowsAgentDeploymentPreflightView,
)

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
    HyperVVirtualMachineListView,
    WindowsServerDetailView,
    WindowsClientFamilyListView,
    WindowsServerListView,
    WindowsServerRoleListView,
    WindowsServerTelemetryView,
)

from . import views


app_name = "core"

urlpatterns = [
    path("", views.api_information, name="api-information"),
    path("health/live/", views.liveness, name="liveness"),
    path("health/ready/", views.readiness, name="readiness"),
    path("auth/", include("ipms.apps.tenancy.urls")),
    path(
        "agents/windows/deployments/",
        WindowsAgentDeploymentListCreateView.as_view(),
        name="windows-agent-deployment-list",
    ),
    path(
        "agents/windows/deployments/preflight/",
        WindowsAgentDeploymentPreflightView.as_view(),
        name="windows-agent-deployment-preflight",
    ),
    path(
        "agents/windows/deployments/<uuid:pk>/",
        WindowsAgentDeploymentDetailView.as_view(),
        name="windows-agent-deployment-detail",
    ),
    path(
        "agents/",
        AgentAdministrationListView.as_view(),
        name="agent-administration-list",
    ),
    path(
        "agents/<uuid:pk>/",
        AgentAdministrationDetailView.as_view(),
        name="agent-administration-detail",
    ),
    path(
        "agents/<uuid:pk>/lifecycle/",
        AgentLifecycleView.as_view(),
        name="agent-lifecycle",
    ),
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
    path("windows-servers/", WindowsServerListView.as_view(), name="windows-server-list"),
    path(
        "windows-server-roles/",
        WindowsServerRoleListView.as_view(),
        name="windows-server-role-list",
    ),
    path(
        "windows-client-families/",
        WindowsClientFamilyListView.as_view(),
        name="windows-client-family-list",
    ),
    path(
        "hyper-v/virtual-machines/",
        HyperVVirtualMachineListView.as_view(),
        name="hyperv-virtual-machine-list",
    ),
    path(
        "windows-servers/<uuid:pk>/",
        WindowsServerDetailView.as_view(),
        name="windows-server-detail",
    ),
    path(
        "windows-servers/<uuid:pk>/telemetry/",
        WindowsServerTelemetryView.as_view(),
        name="windows-server-telemetry",
    ),
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
