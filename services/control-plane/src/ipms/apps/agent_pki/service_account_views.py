from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models.deletion import ProtectedError
from django.shortcuts import get_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from rest_framework import serializers
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ipms.apps.tenancy.permissions import HasSelectedTenantAccess, HasTenantPermission
from ipms.apps.tenancy.rbac import Permission
from .models import AgentEnrollment, NativeConsoleCredential, ServiceAccount
from .service_accounts import (
    account_state, audit_account, close_credential_sessions, decrypt_service_account,
    encrypt_service_account, host_state, list_host_states, lock_account_enrollments, lock_tenant,
)


class ServiceAccountUnavailable(APIException):
    status_code = 503
    default_detail = {"code": "service_account_unavailable"}
    public_code = "service_account_unavailable"


class ServiceAccountInUse(APIException):
    status_code = 409
    default_detail = {"code": "service_account_in_use"}
    public_code = "service_account_in_use"


class ServiceAccountInvalid(APIException):
    status_code = 400
    default_detail = {"code": "service_account_invalid"}
    public_code = "service_account_invalid"


class ManageServiceAccounts(HasTenantPermission):
    required_permission = Permission.SERVICE_ACCOUNTS_MANAGE


class StrictSerializer(serializers.Serializer):
    @sensitive_variables()
    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - self.fields.keys():
            raise serializers.ValidationError("service_account_invalid")
        return super().to_internal_value(data)


class AccountSerializer(StrictSerializer):
    name = serializers.CharField(max_length=128)
    kind = serializers.ChoiceField(choices=("hyperv_console",))
    username = serializers.CharField(max_length=256, trim_whitespace=False)
    domain = serializers.CharField(max_length=256, allow_blank=True, trim_whitespace=False, required=False, default="")
    password = serializers.CharField(max_length=1024, trim_whitespace=False, write_only=True)


class BindingSerializer(StrictSerializer):
    service_account_id = serializers.UUIDField()


@sensitive_variables()
def validated(serializer_class, data, *, partial=False):
    serializer = serializer_class(data=data, partial=partial)
    if not serializer.is_valid() or any(isinstance(value, str) and "\x00" in value for value in serializer.validated_data.values()):
        raise ServiceAccountInvalid()
    return serializer.validated_data


@method_decorator(sensitive_post_parameters(), name="dispatch")
class ServiceAccountView(APIView):
    permission_classes = (IsAuthenticated, HasSelectedTenantAccess, ManageServiceAccounts)

    def handle_exception(self, exc):
        # Do not expose key paths, encrypted payloads, or backend exceptions.
        if isinstance(exc, DjangoValidationError):
            exc = ServiceAccountUnavailable()
        return super().handle_exception(exc)


class ServiceAccountListView(ServiceAccountView):
    def get(self, request):
        return Response({"results": [account_state(account) for account in ServiceAccount.objects.filter(tenant=request.tenant)]})

    @sensitive_variables()
    def post(self, request):
        data = validated(AccountSerializer, request.data)
        with transaction.atomic():
            lock_tenant(request.tenant)
            account = ServiceAccount(tenant=request.tenant, name=data["name"], kind=data["kind"])
            encrypt_service_account(account, {key: data[key] for key in ("username", "password", "domain")})
            account.save()
            audit_account(request.tenant, request.user, "create", account.id)
            return Response(account_state(account), status=201)


class ServiceAccountDetailView(ServiceAccountView):
    @sensitive_variables()
    def patch(self, request, pk):
        data = validated(AccountSerializer, request.data, partial=True)
        with transaction.atomic():
            lock_tenant(request.tenant)
            account = get_object_or_404(ServiceAccount, pk=pk, tenant=request.tenant)
            enrollments = lock_account_enrollments(account)
            account = ServiceAccount.objects.select_for_update().get(pk=account.pk, tenant=request.tenant)
            document = decrypt_service_account(account, tenant_id=request.tenant.id)
            changed_credentials = any(key in data for key in ("username", "password", "domain"))
            if changed_credentials:
                document.update({key: data[key] for key in ("username", "password", "domain") if key in data})
                encrypt_service_account(account, document)
            if "name" in data:
                account.name = data["name"]
            account.save()
            closed = close_credential_sessions(request.tenant, [enrollment.id for enrollment in enrollments]) if changed_credentials else 0
            audit_account(request.tenant, request.user, "rotate" if changed_credentials else "update", account.id, sessions_closed=closed)
            return Response(account_state(account))

    def delete(self, request, pk):
        try:
            with transaction.atomic():
                lock_tenant(request.tenant)
                account = get_object_or_404(ServiceAccount.objects.select_for_update(), pk=pk, tenant=request.tenant)
                if account.bindings.exists():
                    raise ServiceAccountInUse()
                account.delete()
                audit_account(request.tenant, request.user, "delete", pk)
        except (ProtectedError, IntegrityError):
            raise ServiceAccountInUse() from None
        return Response(status=204)


class ServiceAccountHostListView(ServiceAccountView):
    def get(self, request):
        return Response({"results": list_host_states(request.tenant)})


class ServiceAccountHostDetailView(ServiceAccountView):
    def put(self, request, pk):
        data = validated(BindingSerializer, request.data)
        with transaction.atomic():
            lock_tenant(request.tenant)
            enrollment = get_object_or_404(AgentEnrollment.objects.select_for_update(), pk=pk, tenant=request.tenant)
            if not host_state(enrollment)["eligible"]:
                raise ServiceAccountInvalid()
            account = get_object_or_404(ServiceAccount.objects.select_for_update(), pk=data["service_account_id"], tenant=request.tenant)
            # Validate both the encrypted identity binding and usable payload
            # before discarding an explicitly replaced legacy credential.
            decrypt_service_account(account, tenant_id=request.tenant.id)
            NativeConsoleCredential.objects.update_or_create(enrollment=enrollment, defaults={
                "tenant": request.tenant, "service_account": account, "nonce": b"", "ciphertext": b"",
            })
            closed = close_credential_sessions(request.tenant, [enrollment.id])
            audit_account(request.tenant, request.user, "assign", account.id, enrollment_id=str(enrollment.id), sessions_closed=closed)
            return Response(host_state(enrollment))

    def delete(self, request, pk):
        with transaction.atomic():
            lock_tenant(request.tenant)
            enrollment = get_object_or_404(AgentEnrollment.objects.select_for_update(), pk=pk, tenant=request.tenant)
            binding = get_object_or_404(NativeConsoleCredential.objects.select_for_update(), enrollment=enrollment, tenant=request.tenant)
            account_id = binding.service_account_id
            binding.delete()
            closed = close_credential_sessions(request.tenant, [enrollment.id])
            audit_account(request.tenant, request.user, "unassign", account_id or enrollment.id,
                          enrollment_id=str(enrollment.id), legacy=account_id is None, sessions_closed=closed)
        return Response(status=204)
