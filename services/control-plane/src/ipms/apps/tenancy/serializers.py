from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.utils import timezone
from django.views.decorators.debug import sensitive_variables
from rest_framework import serializers

from .models import Tenant, TenantMembership
from .rbac import is_tenant_principal


class StrictInputSerializer(serializers.Serializer):
    @sensitive_variables()
    def to_internal_value(self, data):
        if not isinstance(data, dict) or set(data) - self.fields.keys():
            raise serializers.ValidationError(
                {"non_field_errors": ["Unexpected request fields."]}
            )
        return super().to_internal_value(data)


class TenantUserCreateSerializer(StrictInputSerializer):
    username = serializers.CharField(max_length=150, trim_whitespace=True)
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    role = serializers.ChoiceField(choices=TenantMembership.Role.choices)
    initial_password = serializers.CharField(
        min_length=12,
        max_length=1024,
        trim_whitespace=False,
        write_only=True,
    )
    expires_at = serializers.DateTimeField(required=False, allow_null=True)

    def validate_username(self, value: str) -> str:
        user_model = get_user_model()
        normalized = user_model.normalize_username(value)
        validator = user_model._meta.get_field(user_model.USERNAME_FIELD).validators
        for item in validator:
            item(normalized)
        return normalized

    def validate_expires_at(self, value):
        if value is not None and value <= timezone.now():
            raise serializers.ValidationError("Expiration must be in the future.")
        return value

    @sensitive_variables()
    def validate(self, attrs):
        user_model = get_user_model()
        candidate = user_model(
            username=attrs["username"],
            first_name=attrs.get("first_name", ""),
            last_name=attrs.get("last_name", ""),
            email=attrs.get("email", ""),
        )
        try:
            validate_password(attrs["initial_password"], candidate)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(
                {"initial_password": list(exc.messages)}
            ) from exc
        return attrs


class TenantMembershipUpdateSerializer(StrictInputSerializer):
    role = serializers.ChoiceField(
        choices=TenantMembership.Role.choices,
        required=False,
    )
    is_active = serializers.BooleanField(required=False)
    expires_at = serializers.DateTimeField(required=False, allow_null=True)

    def validate_expires_at(self, value):
        if value is not None and value <= timezone.now():
            raise serializers.ValidationError("Expiration must be in the future.")
        return value

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("At least one change is required.")
        return attrs


def tenant_user_payload(membership: TenantMembership) -> dict:
    user = membership.user
    membership_effective = bool(
        membership.is_active
        and user.is_active
        and is_tenant_principal(user)
        and (membership.expires_at is None or membership.expires_at > timezone.now())
    )
    has_oidc = any(
        identity.is_active for identity in user.ipms_external_identities.all()
    )
    has_local = user.has_usable_password()
    if has_oidc and has_local:
        authentication_source = "hybrid"
    elif has_oidc:
        authentication_source = "oidc"
    else:
        authentication_source = "local"
    return {
        "membership_id": str(membership.id),
        "username": user.get_username(),
        "display_name": user.get_full_name() or user.get_username(),
        "email": user.email,
        "role": membership.role,
        "is_active": membership_effective,
        "membership_active": membership.is_active,
        "expires_at": (
            membership.expires_at.isoformat() if membership.expires_at else None
        ),
        "last_login": user.last_login.isoformat() if user.last_login else None,
        "authentication_source": authentication_source,
        "manageable": is_tenant_principal(user),
    }


class PlatformTenantCreateSerializer(StrictInputSerializer):
    slug = serializers.SlugField(max_length=63)
    display_name = serializers.CharField(max_length=255)
    status = serializers.ChoiceField(
        choices=(Tenant.Status.ACTIVE, Tenant.Status.SUSPENDED),
        required=False,
        default=Tenant.Status.ACTIVE,
    )

    def validate_slug(self, value):
        return value.lower()


class PlatformTenantUpdateSerializer(StrictInputSerializer):
    display_name = serializers.CharField(max_length=255, required=False)
    status = serializers.ChoiceField(
        choices=(Tenant.Status.ACTIVE, Tenant.Status.SUSPENDED), required=False
    )

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError("At least one change is required.")
        return attrs


class InitialTenantAdministratorSerializer(TenantUserCreateSerializer):
    role = None
    expires_at = None
