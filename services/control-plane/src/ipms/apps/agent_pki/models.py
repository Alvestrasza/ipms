import uuid

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models

from ipms.apps.tenancy.models import Tenant


class AgentPkiPolicy(models.Model):
    class TrustMode(models.TextChoices):
        IPMS_MANAGED = "ipms_managed", "IPMS managed"
        EXTERNAL_ISSUING_CA = "external_issuing_ca", "External issuing CA"
        EXTERNAL_CERTIFICATES = "external_certificates", "External certificates"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.OneToOneField(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_pki_policy",
    )
    trust_mode = models.CharField(max_length=32, choices=TrustMode.choices)
    gateway_dns_name = models.CharField(max_length=253)
    gateway_port = models.PositiveIntegerField(
        default=9419,
        validators=(MinValueValidator(1024), MaxValueValidator(65535)),
    )
    root_certificate_pem = models.TextField(blank=True)
    root_fingerprint_sha256 = models.CharField(max_length=64, blank=True)
    root_recovery_exported_at = models.DateTimeField(blank=True, null=True)
    certificate_lifetime_days = models.PositiveSmallIntegerField(
        default=30,
        validators=(MinValueValidator(1), MaxValueValidator(90)),
    )
    renewal_window_days = models.PositiveSmallIntegerField(
        default=10,
        validators=(MinValueValidator(1), MaxValueValidator(30)),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Agent PKI for {self.tenant}"


class AgentIssuer(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        OVERLAP = "overlap", "Overlap"
        RETIRED = "retired", "Retired"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_issuers",
    )
    policy = models.ForeignKey(
        AgentPkiPolicy,
        on_delete=models.PROTECT,
        related_name="issuers",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
    )
    certificate_pem = models.TextField()
    chain_pem = models.TextField()
    fingerprint_sha256 = models.CharField(max_length=64, unique=True)
    serial_number = models.CharField(max_length=64)
    private_key_nonce = models.BinaryField(blank=True, null=True)
    private_key_ciphertext = models.BinaryField(blank=True, null=True)
    key_version = models.PositiveSmallIntegerField(default=1)
    external = models.BooleanField(default=False)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "serial_number"),
                name="unique_tenant_agent_issuer_serial",
            )
        ]


class AgentGatewayIdentity(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_gateway_identities",
    )
    policy = models.OneToOneField(
        AgentPkiPolicy,
        on_delete=models.PROTECT,
        related_name="gateway_identity",
    )
    issuer = models.ForeignKey(
        AgentIssuer,
        on_delete=models.PROTECT,
        related_name="gateway_identities",
        blank=True,
        null=True,
    )
    certificate_pem = models.TextField()
    chain_pem = models.TextField()
    fingerprint_sha256 = models.CharField(max_length=64, unique=True)
    private_key_nonce = models.BinaryField()
    private_key_ciphertext = models.BinaryField()
    key_version = models.PositiveSmallIntegerField(default=1)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(blank=True, null=True)


class AgentEnrollment(models.Model):
    class Platform(models.TextChoices):
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"
        REMOVED = "removed", "Removed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_enrollments",
    )
    device_id = models.UUIDField(default=uuid.uuid4, editable=False)
    device_uri = models.CharField(max_length=64, unique=True)
    display_name = models.CharField(max_length=255)
    platform = models.CharField(
        max_length=16,
        choices=Platform.choices,
        default=Platform.WINDOWS,
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    issuer = models.ForeignKey(
        AgentIssuer,
        on_delete=models.PROTECT,
        related_name="enrollments",
        blank=True,
        null=True,
    )
    certificate_pem = models.TextField(blank=True)
    certificate_fingerprint_sha256 = models.CharField(max_length=64, blank=True)
    certificate_serial_number = models.CharField(max_length=64, blank=True)
    certificate_not_before = models.DateTimeField(blank=True, null=True)
    certificate_not_after = models.DateTimeField(blank=True, null=True)
    key_algorithm = models.CharField(max_length=32, blank=True)
    first_inventory_at = models.DateTimeField(blank=True, null=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("display_name",)
        constraints = [
            models.UniqueConstraint(
                fields=("tenant", "device_id"),
                name="unique_tenant_agent_device",
            )
        ]
        indexes = [
            models.Index(
                fields=("tenant", "status"),
                name="agent_enroll_tenant_status",
            )
        ]


class AgentEnrollmentToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_enrollment_tokens",
    )
    enrollment = models.ForeignKey(
        AgentEnrollment,
        on_delete=models.PROTECT,
        related_name="bootstrap_tokens",
    )
    token_digest = models.CharField(max_length=64, unique=True)
    gateway_fingerprint_sha256 = models.CharField(max_length=64)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(blank=True, null=True)
    created_by = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(
                fields=("tenant", "expires_at"),
                name="agent_token_tenant_expiry",
            )
        ]


class WindowsAgentDeployment(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"

    class Transport(models.TextChoices):
        HTTPS = "https", "HTTPS"
        HTTP = "http", "HTTP with message encryption"

    class CertificateTrustMode(models.TextChoices):
        SYSTEM = "system", "System trust"
        PINNED = "pinned", "Administrator-approved certificate pin"
        NONE = "none", "Not applicable"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="windows_agent_deployments",
    )
    enrollment = models.OneToOneField(
        AgentEnrollment,
        on_delete=models.PROTECT,
        related_name="windows_deployment",
    )
    lifecycle_bootstrap_enrollment = models.ForeignKey(
        AgentEnrollment,
        blank=True,
        null=True,
        on_delete=models.PROTECT,
        related_name="lifecycle_bootstrap_deployments",
    )
    display_name = models.CharField(max_length=255)
    target_address = models.CharField(max_length=253)
    target_port = models.PositiveIntegerField(
        default=5986,
        validators=(MinValueValidator(1), MaxValueValidator(65535)),
    )
    transport = models.CharField(
        max_length=8,
        choices=Transport.choices,
        default=Transport.HTTPS,
    )
    certificate_trust_mode = models.CharField(
        max_length=8,
        choices=CertificateTrustMode.choices,
        default=CertificateTrustMode.SYSTEM,
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    requested_by = models.CharField(max_length=255)
    certificate_fingerprint_sha256 = models.CharField(max_length=64, blank=True)
    error_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("tenant", "-created_at"),
                name="agent_deploy_tenant_time",
            ),
            models.Index(
                fields=("status", "created_at"),
                name="agent_deploy_status_time",
            ),
        ]


class WindowsAgentDeploymentSecret(models.Model):
    deployment = models.OneToOneField(
        WindowsAgentDeployment,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name="secret",
    )
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="windows_agent_deployment_secrets",
    )
    nonce = models.BinaryField()
    ciphertext = models.BinaryField()
    key_version = models.PositiveSmallIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)


class AgentRevocation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_revocations",
    )
    enrollment = models.OneToOneField(
        AgentEnrollment,
        on_delete=models.PROTECT,
        related_name="revocation",
    )
    certificate_serial_number = models.CharField(max_length=64)
    reason = models.CharField(max_length=64)
    revoked_by = models.CharField(max_length=255)
    revoked_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-revoked_at",)


class AgentLifecycleJob(models.Model):
    class Action(models.TextChoices):
        UPDATE = "update", "Update"
        UNINSTALL = "uninstall", "Uninstall"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        DELIVERED = "delivered", "Delivered"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(
        Tenant,
        on_delete=models.PROTECT,
        related_name="agent_lifecycle_jobs",
    )
    enrollment = models.ForeignKey(
        AgentEnrollment,
        on_delete=models.PROTECT,
        related_name="lifecycle_jobs",
    )
    action = models.CharField(max_length=16, choices=Action.choices)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    target_version = models.CharField(max_length=64, blank=True)
    artifact_sha256 = models.CharField(max_length=64, blank=True)
    requested_by = models.CharField(max_length=255)
    result_code = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(blank=True, null=True)
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(
                fields=("tenant", "-created_at"),
                name="agent_lifecycle_tenant_time",
            ),
            models.Index(
                fields=("enrollment", "status"),
                name="agent_lifecycle_device_state",
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("enrollment",),
                condition=models.Q(status__in=("queued", "delivered", "running")),
                name="unique_active_agent_lifecycle_job",
            )
        ]
