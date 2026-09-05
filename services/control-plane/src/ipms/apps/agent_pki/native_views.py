from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.discovery.models import HyperVVirtualMachine
from ipms.apps.tenancy.permissions import HasSelectedTenantAccess
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .models import AgentEnrollment
from .native_console import configuration_state, store_credential


class NativeConsoleConfigurationView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess)

    def _vm(self, request, pk):
        return get_object_or_404(HyperVVirtualMachine.objects.select_related("host", "tenant"),
                                 id=pk, tenant=request.tenant, host__tenant=request.tenant)

    def get(self, request, pk):
        if not any(has_tenant_permission(request.user, request.tenant, permission) for permission in (
            Permission.AGENTS_MANAGE, Permission.VIRTUAL_MACHINES_CONSOLE_CONTROL,
        )):
            raise PermissionDenied()
        return Response(configuration_state(self._vm(request, pk), request.user))

    def post(self, request, pk):
        vm = self._vm(request, pk)
        if not configuration_state(vm, request.user)["can_manage"]:
            raise PermissionDenied()
        enrollment = get_object_or_404(AgentEnrollment, tenant=request.tenant,
                                     device_uri=vm.host.source_id, status=AgentEnrollment.Status.ACTIVE,
                                     platform=AgentEnrollment.Platform.WINDOWS)
        try:
            store_credential(enrollment, user=request.user, document=request.data)
        except DjangoValidationError:
            raise ValidationError({"code": "native_configuration_invalid"}) from None
        except Exception:
            raise ValidationError({"code": "native_configuration_unavailable"}) from None
        return Response(configuration_state(vm, request.user))
