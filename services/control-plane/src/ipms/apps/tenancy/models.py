import uuid

from django.conf import settings
from django.db import models


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
