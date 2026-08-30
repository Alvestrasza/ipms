from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated

from ipms.apps.tenancy.permissions import HasSelectedTenantAccess

from .models import DiscoveryJob
from .serializers import DiscoveryJobSerializer


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
