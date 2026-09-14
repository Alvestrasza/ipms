# File Name: models.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant baseline evidence, domain plans and bounded pilot GPO jobs.
import uuid

from django.core.exceptions import ValidationError
from django.conf import settings
from django.db import models
from django.utils import timezone


class DomainSecuritySettings(models.Model):
    """Draft directory bindings; saving never resolves or mutates AD objects."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=253)
    revision = models.PositiveIntegerField(default=1)
    tier_ous = models.JSONField(default=dict)
    gpo_name_template = models.CharField(max_length=160)
    baseline_order = models.JSONField(default=list)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('domain_name', 'id')
        constraints = [models.UniqueConstraint(fields=('tenant', 'domain_name'), name='security_tenant_domain')]


class GpoExecutorReport(models.Model):
    """Authenticated local DC observations, not a delegation or approval."""

    enrollment = models.OneToOneField('agent_pki.AgentEnrollment', on_delete=models.CASCADE, primary_key=True)
    agent_version = models.CharField(max_length=32)
    domain_dns_name = models.CharField(max_length=253, blank=True)
    domain_guid = models.CharField(max_length=36, blank=True)
    forest_dns_name = models.CharField(max_length=253, blank=True)
    dc_fqdn = models.CharField(max_length=253, blank=True)
    role = models.CharField(max_length=40)
    gpmc_available = models.BooleanField(default=False)
    result_code = models.CharField(max_length=48)
    observed_at = models.DateTimeField(default=timezone.now)


class GpoImportJob(models.Model):
    """Immutable single-component pilot intent and durable mutation fence."""

    id = models.UUIDField(primary_key=True, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    domain = models.ForeignKey(DomainSecuritySettings, on_delete=models.PROTECT)
    enrollment = models.ForeignKey('agent_pki.AgentEnrollment', on_delete=models.PROTECT)
    system = models.ForeignKey('discovery.WindowsServer', on_delete=models.PROTECT)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    domain_guid = models.CharField(max_length=36)
    request_sha256 = models.CharField(max_length=64)
    input_digest = models.CharField(max_length=64)
    assignment = models.JSONField()
    pilot_display_name = models.CharField(max_length=240)
    pilot_name_key = models.CharField(max_length=240)
    status = models.CharField(max_length=32, default='queued')
    error_code = models.CharField(max_length=48, blank=True)
    requested_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    claimed_at = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)
    gpo_guid = models.CharField(max_length=36, blank=True)
    result_digest = models.CharField(max_length=64, blank=True)
    result_evidence = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ('-requested_at', '-id')
        constraints = [
            models.UniqueConstraint(fields=('tenant', 'domain_guid'), condition=models.Q(status__in=(
                'queued', 'awaiting_approval', 'running', 'reconciliation_required',
            )), name='security_gpo_domain_fence'),
            models.UniqueConstraint(fields=('tenant', 'domain_guid', 'pilot_name_key'), name='security_gpo_pilot_identity'),
        ]
        indexes = [models.Index(fields=('enrollment', 'status'), name='security_gpo_agent_status')]


class BaselinePreference(models.Model):
    """Tenant catalog visibility, independent of scan policy and evidence."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("tenancy.Tenant", on_delete=models.CASCADE)
    baseline_id = models.CharField(max_length=96)
    hidden = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=("tenant", "baseline_id"), name="security_tenant_baseline_pref")]


class BaselineAssessment(models.Model):
    """A trusted evaluator's complete-scope receipt, never a browser assertion.

    scope_verified must only be set after validating the entire imported rule
    manifest and role profile in the authenticated native evidence receiver.
    Partial probes, user-scope omissions and missing rules cannot set this flag.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    system = models.ForeignKey("discovery.WindowsServer", on_delete=models.CASCADE, related_name="baseline_assessments")
    enrollment = models.ForeignKey("agent_pki.AgentEnrollment", on_delete=models.PROTECT)
    baseline_id = models.CharField(max_length=96)
    baseline_revision = models.CharField(max_length=64, blank=True)
    catalog_revision = models.CharField(max_length=32)
    content_sha256 = models.CharField(max_length=64, blank=True)
    findings = models.JSONField(default=list, blank=True)
    profile = models.CharField(max_length=24)
    os_build = models.CharField(max_length=64)
    operating_system = models.CharField(max_length=255)
    scope_verified = models.BooleanField(default=False)
    total_controls = models.PositiveIntegerField(default=0)
    passed_controls = models.PositiveIntegerField(default=0)
    failed_controls = models.PositiveIntegerField(default=0)
    unknown_controls = models.PositiveIntegerField(default=0)
    not_applicable_controls = models.PositiveIntegerField(default=0)
    error_code = models.CharField(max_length=32, blank=True, choices=(
        ("", "None"), ("collection_failed", "Collection failed"),
        ("access_denied", "Access denied"), ("unsupported", "Unsupported"),
    ))
    observed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-observed_at", "-created_at", "-id")
        indexes = [models.Index(fields=("system", "baseline_id", "-observed_at"), name="security_system_baseline_idx")]
        constraints = [models.CheckConstraint(
            condition=models.Q(total_controls=models.F("passed_controls") + models.F("failed_controls") + models.F("unknown_controls") + models.F("not_applicable_controls")),
            name="security_control_counts_match",
        )]

    def clean(self):
        if self.system_id and self.enrollment_id and (
            self.system.tenant_id != self.enrollment.tenant_id
            or self.system.inventory_source != "agent"
            or self.system.source_id != self.enrollment.device_uri
            or self.enrollment.platform != "windows"
        ):
            raise ValidationError("Assessment identity must match the tenant's enrolled system.")
        if self.observed_at and self.observed_at > timezone.now():
            raise ValidationError("Assessment time must not be in the future.")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


class BaselineScanJob(models.Model):
    """One bounded read request, bound to an immutable manifest and identity."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("tenancy.Tenant", on_delete=models.CASCADE)
    system = models.ForeignKey("discovery.WindowsServer", on_delete=models.CASCADE)
    enrollment = models.ForeignKey("agent_pki.AgentEnrollment", on_delete=models.PROTECT)
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    baseline_id = models.CharField(max_length=96)
    baseline_revision = models.CharField(max_length=64, blank=True)
    catalog_revision = models.CharField(max_length=32)
    profile = models.CharField(max_length=24)
    manifest_sha256 = models.CharField(max_length=64)
    os_build = models.CharField(max_length=64)
    operating_system = models.CharField(max_length=255)
    status = models.CharField(max_length=16, default="queued", choices=[(s, s) for s in (
        "queued", "running", "completed", "failed", "expired",
    )])
    requested_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    attempt_id = models.UUIDField(null=True, blank=True)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    lease_expires_at = models.DateTimeField(null=True, blank=True)
    assessment = models.OneToOneField(BaselineAssessment, on_delete=models.SET_NULL, null=True, blank=True)
    # Pending pages are cleared on every new attempt and after completion.
    pages = models.JSONField(default=dict, blank=True)
    page_hashes = models.JSONField(default=dict, blank=True)
    page_count = models.PositiveSmallIntegerField(default=0)
    evidence_system = models.JSONField(default=dict, blank=True)
    error_code = models.CharField(max_length=32, blank=True)

    class Meta:
        ordering = ("-requested_at", "-id")
        constraints = [models.UniqueConstraint(
            fields=("system", "baseline_id"), condition=models.Q(status__in=("queued", "running")),
            name="security_one_active_scan",
        )]
        indexes = [models.Index(fields=("enrollment", "status"), name="security_scan_agent_status")]
