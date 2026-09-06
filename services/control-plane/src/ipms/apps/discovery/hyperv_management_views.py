"""Tenant-scoped inspector and asynchronous management job endpoints."""

from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.agent_pki.hyperv_management import (
    create_management_job,
    job_payload,
    management_payload,
)
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess, HasTenantPermission
from ipms.apps.tenancy.rbac import Permission
from .hyperv_management_serializers import (
    ManagementOperationSerializer,
    ManagementRefreshSerializer,
)
from .models import HyperVManagementJob, HyperVVirtualMachine


class CanViewManagement(HasTenantPermission):
    required_permission = Permission.INVENTORY_VIEW


class ManagementView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanViewManagement)

    def virtual_machine(self, request, pk):
        return get_object_or_404(
            HyperVVirtualMachine.objects.select_related("host"),
            pk=pk,
            tenant=request.tenant,
        )


class HyperVManagementView(ManagementView):
    def get(self, request, pk):
        return Response(management_payload(self.virtual_machine(request, pk)))


class HyperVManagementRefreshView(ManagementView):
    def post(self, request, pk):
        serializer = ManagementRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = create_management_job(
            virtual_machine=self.virtual_machine(request, pk),
            actor=request.user,
            request_id=serializer.validated_data["request_id"],
            operation="inspect",
        )
        return Response(job_payload(job), status=202)


class HyperVManagementOperationView(ManagementView):
    def post(self, request, pk):
        serializer = ManagementOperationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = create_management_job(
            virtual_machine=self.virtual_machine(request, pk),
            actor=request.user,
            **serializer.validated_data,
        )
        return Response(job_payload(job), status=202)


class HyperVManagementJobView(ManagementView):
    def get(self, request, pk):
        job = get_object_or_404(HyperVManagementJob, pk=pk, tenant=request.tenant)
        return Response(job_payload(job))
