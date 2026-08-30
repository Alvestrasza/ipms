from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.audit.models import AuditEvent

from ipms.apps.tenancy.permissions import HasSelectedTenantAccess

from .models import ConnectorEndpoint, DiscoveryJob, PhysicalSystem
from .permissions import CanManageConnectors
from .secrets import store_connector_secret
from .serializers import (
    ConnectorEndpointSerializer,
    DiscoveryJobSerializer,
    IloConnectorEnrollmentSerializer,
    PhysicalSystemSerializer,
)


class ConnectorEndpointListView(ListAPIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    serializer_class = ConnectorEndpointSerializer

    def get_queryset(self):
        return ConnectorEndpoint.objects.filter(tenant=self.request.tenant)


class IloConnectorEnrollmentView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    @transaction.atomic
    def post(self, request):
        serializer = IloConnectorEnrollmentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if ConnectorEndpoint.objects.filter(
            tenant=request.tenant,
            base_url=data["base_url"],
        ).exists():
            raise ValidationError({"base_url": ["This iLO endpoint is already enrolled."]})
        endpoint = ConnectorEndpoint.objects.create(
            tenant=request.tenant,
            connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
            display_name=data["display_name"],
            base_url=data["base_url"],
            tls_certificate_sha256=data["certificate_sha256"],
        )
        store_connector_secret(
            tenant=request.tenant,
            secret_id=endpoint.credential_reference,
            username=data["username"],
            password=data["password"],
        )
        job = DiscoveryJob.objects.create(
            tenant=request.tenant,
            connector=endpoint,
            connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
            requested_by=request.user.get_username(),
        )
        AuditEvent.objects.create(
            tenant=request.tenant,
            actor=request.user.get_username(),
            action="connector.enroll",
            object_type="connector_endpoint",
            object_id=str(endpoint.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            correlation_id=job.correlation_id,
            details={"connector_type": endpoint.connector_type, "job_id": str(job.id)},
        )
        return Response(
            {
                "connector": ConnectorEndpointSerializer(endpoint).data,
                "discovery_job": DiscoveryJobSerializer(job).data,
            },
            status=status.HTTP_201_CREATED,
        )


class ConnectorDiscoveryView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageConnectors)

    def post(self, request, pk):
        endpoint = get_object_or_404(
            ConnectorEndpoint,
            id=pk,
            tenant=request.tenant,
            connector_type=ConnectorEndpoint.ConnectorType.ILO_REDFISH,
            enabled=True,
        )
        active_job = DiscoveryJob.objects.filter(
            connector=endpoint,
            status__in=(DiscoveryJob.Status.QUEUED, DiscoveryJob.Status.RUNNING),
        ).first()
        if active_job:
            return Response(
                {"discovery_job": DiscoveryJobSerializer(active_job).data},
                status=status.HTTP_202_ACCEPTED,
            )
        job = DiscoveryJob.objects.create(
            tenant=request.tenant,
            connector=endpoint,
            connector_type=DiscoveryJob.ConnectorType.ILO_REDFISH,
            requested_by=request.user.get_username(),
        )
        AuditEvent.objects.create(
            tenant=request.tenant,
            actor=request.user.get_username(),
            action="connector.discovery.queued",
            object_type="connector_endpoint",
            object_id=str(endpoint.id),
            outcome=AuditEvent.Outcome.SUCCEEDED,
            correlation_id=job.correlation_id,
            details={"connector_type": endpoint.connector_type, "job_id": str(job.id)},
        )
        return Response(
            {"discovery_job": DiscoveryJobSerializer(job).data},
            status=status.HTTP_202_ACCEPTED,
        )


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
