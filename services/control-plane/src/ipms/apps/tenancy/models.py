import uuid

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.utils import timezone


class PlatformAdministrator(models.Model):
    """Platform identity only; never a customer membership or Django admin."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="ipms_platform_administrator",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        if self.user_id and (
            get_user_model()
            .objects.filter(pk=self.user_id)
            .filter(models.Q(is_staff=True) | models.Q(is_superuser=True))
            .exists()
            or TenantMembership.objects.filter(user_id=self.user_id).exists()
        ):
            raise ValidationError(
                "Platform identities cannot have tenant memberships or Django administrative privileges."
            )

    def save(self, *args, **kwargs):
        with transaction.atomic():
            get_user_model().objects.select_for_update(no_key=True).get(pk=self.user_id)
            self.clean()
            return super().save(*args, **kwargs)


class Tenant(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        SUSPENDED = "suspended", "Suspended"
        DECOMMISSIONED = "decommissioned", "Decommissioned"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=63, unique=True)
    display_name = models.CharField(max_length=255)
    external_reference = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        unique=True,
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    initial_administrator_created_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("slug",)

    def __str__(self) -> str:
        return self.display_name


class TenantMembership(models.Model):
    class Role(models.TextChoices):
        TENANT_ADMIN = "tenant_admin", "Tenant administrator"
        OPERATOR = "operator", "Operator"
        APPROVER = "approver", "Approver"
        AUDITOR = "auditor", "Auditor"
        READER = "reader", "Reader"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ipms_tenant_memberships",
    )
    role = models.CharField(max_length=16, choices=Role.choices)
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("tenant__slug", "user__username")
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "user"),
                name="unique_tenant_membership",
            )
        ]
        indexes = [
            models.Index(
                fields=("user", "is_active"),
                name="membership_user_active_idx",
            )
        ]

    def __str__(self) -> str:
        return f"{self.user} in {self.tenant} ({self.role})"

    def clean(self):
        if (
            self.user_id
            and get_user_model()
            .objects.filter(pk=self.user_id)
            .filter(
                models.Q(is_staff=True)
                | models.Q(is_superuser=True)
                | models.Q(ipms_platform_administrator__isnull=False),
            )
            .exists()
        ):
            raise ValidationError("Platform identities cannot be tenant members.")

    def save(self, *args, **kwargs):
        with transaction.atomic():
            Tenant.objects.select_for_update(no_key=True).get(pk=self.tenant_id)
            get_user_model().objects.select_for_update(no_key=True).get(pk=self.user_id)
            self.clean()
            result = super().save(*args, **kwargs)
            if self.role == self.Role.TENANT_ADMIN:
                # This is a historical fence, not a count of current admins.
                # A later disabled/expired/deleted administrator must not
                # reopen the platform's one-time provisioning capability.
                Tenant.objects.filter(
                    pk=self.tenant_id, initial_administrator_created_at__isnull=True
                ).update(
                    initial_administrator_created_at=timezone.now(),
                )
            return result


class ExternalIdentity(models.Model):
    """Immutable external subject binding used by future OIDC providers."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ipms_external_identities",
    )
    issuer = models.URLField(max_length=512)
    subject = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("issuer", "subject")
        constraints = [
            models.UniqueConstraint(
                fields=("issuer", "subject"),
                name="unique_external_identity_subject",
            ),
            models.UniqueConstraint(
                fields=("user", "issuer"),
                name="unique_user_identity_issuer",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.issuer}#{self.subject}"
