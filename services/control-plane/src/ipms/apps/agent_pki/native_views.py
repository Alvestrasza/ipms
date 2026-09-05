from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.discovery.models import HyperVVirtualMachine
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .native_console import configuration_state


class NativeConsoleConfigurationView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)
    http_method_names = ("get", "head", "options")

    def _vm(self, request, pk):
        return get_object_or_404(HyperVVirtualMachine.objects.select_related("host", "tenant"),
                                 id=pk, tenant=request.tenant, host__tenant=request.tenant)

    def get(self, request, pk):
        if not any(has_tenant_permission(request.user, request.tenant, permission) for permission in (
            Permission.SERVICE_ACCOUNTS_MANAGE, Permission.VIRTUAL_MACHINES_CONSOLE_CONTROL,
        )):
            raise PermissionDenied()
        return Response(configuration_state(self._vm(request, pk), request.user))
