"""Cookie-authenticated local account settings and tenant-admin identity actions."""

from django.contrib.auth import logout
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.core.exceptions import PublicApiError
from .identity import (
    authentication_source,
    can_manage_own_identity,
    change_identity,
    is_local_identity,
)
from .models import TenantMembership
from .permissions import HasSelectedTenantAccess
from .serializers import (
    IdentityPasswordSerializer,
    IdentityRenameSerializer,
    tenant_user_payload,
)
from .views import CanManageUsers


@method_decorator(sensitive_post_parameters(), name="dispatch")
class AccountView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        if not can_manage_own_identity(request.user):
            raise PublicApiError("forbidden", status_code=403)
        local = is_local_identity(request.user)
        return Response(
            {
                "username": request.user.username,
                "display_name": request.user.get_full_name() or request.user.username,
                "authentication_source": authentication_source(request.user),
                "can_rename": local,
                "can_change_password": local,
            }
        )


@method_decorator(sensitive_post_parameters(), name="dispatch")
class IdentityMutationView(APIView):
    permission_classes = (IsAuthenticated,)
    action = "rename"
    tenant_action = False

    @sensitive_variables()
    def post(self, request, pk=None):
        serializer_class = (
            IdentityRenameSerializer
            if self.action == "rename"
            else IdentityPasswordSerializer
        )
        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = change_identity(
            request,
            data=serializer.validated_data,
            action=self.action,
            membership_id=pk if self.tenant_action else None,
        )
        if self.action == "password":
            if not self.tenant_action:
                logout(request)
            return Response({"reauthentication_required": not self.tenant_action})
        if request.user.pk == target.pk:
            request.user = target
        if self.tenant_action:
            membership = TenantMembership.objects.select_related("tenant", "user").get(
                pk=pk, tenant=request.tenant
            )
            return Response(
                {
                    "user": tenant_user_payload(membership, actor=request.user),
                    "reauthentication_required": False,
                }
            )
        return Response(
            {"username": target.username, "reauthentication_required": False}
        )


class AccountRenameView(IdentityMutationView):
    pass


class AccountPasswordView(IdentityMutationView):
    action = "password"


class TenantUserRenameView(IdentityMutationView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, CanManageUsers)
    tenant_action = True


class TenantUserPasswordView(TenantUserRenameView):
    action = "password"
