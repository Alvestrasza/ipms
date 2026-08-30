from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAdminUser

from .models import DiscoveryJob
from .serializers import DiscoveryJobSerializer


class DiscoveryJobListView(ListAPIView):
    permission_classes = (IsAdminUser,)
    queryset = DiscoveryJob.objects.select_related("tenant").all()
    serializer_class = DiscoveryJobSerializer


class DiscoveryJobDetailView(RetrieveAPIView):
    permission_classes = (IsAdminUser,)
    queryset = DiscoveryJob.objects.select_related("tenant").all()
    serializer_class = DiscoveryJobSerializer
