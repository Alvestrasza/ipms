from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from ipms.apps.tenancy.permissions import HasSelectedTenantAccess

from .models import ConnectorEndpoint, DiscoveryJob, PhysicalSystem
from .serializers import (
    ConnectorEndpointSerializer,
    DiscoveryJobSerializer,
    PhysicalSystemSerializer,
)


class ConnectorEndpointListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = ConnectorEndpointSerializer

    def get_queryset(self):
        return ConnectorEndpoint.objects.filter(tenant=self.request.tenant)


class PhysicalSystemListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = PhysicalSystemSerializer

    def get_queryset(self):
        return PhysicalSystem.objects.filter(tenant=self.request.tenant)


class DiscoveryJobListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = DiscoveryJobSerializer

    def get_queryset(self):
        return DiscoveryJob.objects.filter(tenant=self.request.tenant)


class DiscoveryJobDetailView(RetrieveAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = DiscoveryJobSerializer

    def get_queryset(self):
        return DiscoveryJob.objects.filter(tenant=self.request.tenant)
