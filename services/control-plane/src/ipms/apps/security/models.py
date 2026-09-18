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


class GpoApprovalPolicy(models.Model):
    """Tenant approval rule; absent row means revision 1, four eyes disabled."""

    tenant = models.OneToOneField('tenancy.Tenant', on_delete=models.CASCADE, primary_key=True)
    four_eyes_required = models.BooleanField(default=False, db_default=False)
    revision = models.PositiveIntegerField(default=1)


class GpoDomainAuthorization(models.Model):
    """Explicit domain/tier grants, independent of broad tenant administration."""

    domain = models.OneToOneField(DomainSecuritySettings, on_delete=models.CASCADE, primary_key=True)
    revision = models.PositiveIntegerField(default=1)
    grants = models.JSONField(default=list)


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
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
                                    related_name='approved_gpo_import_jobs')
    approved_at = models.DateTimeField(null=True)
    approval_digest = models.CharField(max_length=64, blank=True, db_default="")
    policy_revision = models.PositiveIntegerField(default=1, db_default=1)
    four_eyes_required = models.BooleanField(default=False, db_default=False)
    authorization_revision = models.PositiveIntegerField(default=1, db_default=1)
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
            models.UniqueConstraint(fields=('tenant', 'domain_guid', 'pilot_name_key'),
                                    condition=models.Q(assignment__schema__in=(1, 2)), name='security_gpo_pilot_identity'),
        ]
        indexes = [models.Index(fields=('enrollment', 'status'), name='security_gpo_agent_status')]


class GpoOverride(models.Model):
    """Tenant-owned sparse policy definition pinned to one trusted component."""

    OVERRIDE = 'override'
    CUSTOM = 'custom'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    kind = models.CharField(max_length=16, default=OVERRIDE, choices=((OVERRIDE, 'Override'), (CUSTOM, 'Custom')))
    name = models.CharField(max_length=80)
    baseline_id = models.CharField(max_length=96)
    backup_id = models.CharField(max_length=38)
    artifact_sha256 = models.CharField(max_length=64)
    revision = models.PositiveIntegerField(default=1)
    enabled = models.BooleanField(default=True)
    entries = models.JSONField(default=list)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name', 'id')


class ManagedGpoPolicy(models.Model):
    """Stable directory identity; immutable jobs retain prepared and active content."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    domain = models.ForeignKey(DomainSecuritySettings, on_delete=models.PROTECT)
    domain_guid = models.CharField(max_length=36)
    override = models.ForeignKey(GpoOverride, on_delete=models.PROTECT, null=True, related_name='policies')
    logical_key = models.CharField(max_length=64)
    tier = models.PositiveSmallIntegerField()
    target_ous = models.JSONField(default=list)
    baseline_id = models.CharField(max_length=96)
    profile = models.CharField(max_length=32)
    purpose = models.CharField(max_length=80)
    target = models.CharField(max_length=32)
    gpo_guid = models.CharField(max_length=36, blank=True)
    display_name = models.CharField(max_length=240)
    name_key = models.CharField(max_length=240)
    version = models.CharField(max_length=32)
    backup_id = models.CharField(max_length=38)
    state = models.CharField(max_length=32, default='new')
    revision = models.PositiveIntegerField(default=1)
    origin_job = models.ForeignKey(GpoImportJob, on_delete=models.PROTECT, null=True, related_name='+')
    staged_job = models.ForeignKey(GpoImportJob, on_delete=models.PROTECT, null=True, related_name='+')
    active_job = models.ForeignKey(GpoImportJob, on_delete=models.PROTECT, null=True, related_name='+')

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=('tenant', 'domain_guid', 'logical_key'), name='security_managed_gpo_identity'),
            models.UniqueConstraint(fields=('tenant', 'domain_guid', 'name_key'), name='security_managed_gpo_name'),
            models.UniqueConstraint(fields=('tenant', 'domain_guid', 'gpo_guid'), condition=~models.Q(gpo_guid=''),
                                    name='security_managed_gpo_guid'),
        ]


class GpoReconciliation(models.Model):
    """Immutable observations and scoped decisions; the original job retains its fence."""

    id = models.UUIDField(primary_key=True, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    job = models.ForeignKey(GpoImportJob, on_delete=models.PROTECT, related_name='reconciliations')
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    accepted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    accepted_actor = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=24, default='requested')
    request_digest = models.CharField(max_length=64)
    job_result_digest = models.CharField(max_length=64, blank=True)
    journal_sha256 = models.CharField(max_length=64, blank=True)
    scope_revision = models.PositiveIntegerField()
    policy_revision = models.PositiveIntegerField()
    authorization_revision = models.PositiveIntegerField()
    managed_revision = models.PositiveIntegerField()
    four_eyes_required = models.BooleanField(default=False)
    observation = models.JSONField(null=True)
    observation_digest = models.CharField(max_length=64, blank=True)
    drift_observation = models.JSONField(null=True)
    drift_digest = models.CharField(max_length=64, blank=True)
    decision_digest = models.CharField(max_length=64, blank=True)
    requested_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField()
    observed_at = models.DateTimeField(null=True)
    accepted_at = models.DateTimeField(null=True)
    finalized_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ('-requested_at', '-id')
        constraints = [models.UniqueConstraint(fields=('job',), condition=models.Q(
            status__in=('requested', 'observed', 'accept_requested')), name='security_gpo_one_reconcile')]


class DeviceCollection(models.Model):
    """Tenant-owned direct and inventory-rule membership definition."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500, blank=True)
    revision = models.PositiveIntegerField(default=1)
    static_system_ids = models.JSONField(default=list)
    rules = models.JSONField(default=list)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name', 'id')
        constraints = [models.UniqueConstraint(fields=('tenant', 'name'), name='security_device_collection_name')]


class PolicyCollection(models.Model):
    """Versioned ordered policy stack with explicit domain target bindings."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500, blank=True)
    revision = models.PositiveIntegerField(default=1)
    entries = models.JSONField(default=list)
    bindings = models.JSONField(default=list)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name', 'id')
        constraints = [models.UniqueConstraint(fields=('tenant', 'name'), name='security_policy_collection_name')]


class PolicyCollectionDeployment(models.Model):
    """Immutable collection revision expanded into independently fenced domain jobs."""

    id = models.UUIDField(primary_key=True, editable=False)
    tenant = models.ForeignKey('tenancy.Tenant', on_delete=models.CASCADE)
    collection = models.ForeignKey(PolicyCollection, on_delete=models.PROTECT, related_name='deployments')
    collection_revision = models.PositiveIntegerField()
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    status = models.CharField(max_length=32, default='queued')
    snapshot = models.JSONField()
    requested_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ('-requested_at', '-id')


class PolicyCollectionDeploymentItem(models.Model):
    """One ordered policy/domain expansion and its preflight/write receipts."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    deployment = models.ForeignKey(PolicyCollectionDeployment, on_delete=models.CASCADE, related_name='items')
    domain = models.ForeignKey(DomainSecuritySettings, on_delete=models.PROTECT)
    policy_index = models.PositiveSmallIntegerField()
    sequence = models.PositiveIntegerField()
    status = models.CharField(max_length=32, default='pending')
    selection = models.JSONField()
    preflight_job = models.OneToOneField(GpoImportJob, on_delete=models.PROTECT, null=True, related_name='+')
    write_job = models.OneToOneField(GpoImportJob, on_delete=models.PROTECT, null=True, related_name='+')
    error_code = models.CharField(max_length=64, blank=True)
    completed_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ('sequence', 'id')
        constraints = [models.UniqueConstraint(
            fields=('deployment', 'domain', 'policy_index'), name='security_policy_deployment_item')]


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
