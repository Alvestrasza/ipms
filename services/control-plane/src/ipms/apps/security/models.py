# File Name: models.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Internal assessment evidence for future trusted native evaluators; no write API.
import uuid

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone


class BaselineAssessment(models.Model):
    """A trusted evaluator's complete-scope receipt, never a browser assertion.

    No production producer is enabled in this release. scope_verified must only
    be set after validating the entire imported rule manifest and role profile.
    Partial probes, user-scope omissions and missing rules cannot set this flag.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    system = models.ForeignKey("discovery.WindowsServer", on_delete=models.CASCADE, related_name="baseline_assessments")
    enrollment = models.ForeignKey("agent_pki.AgentEnrollment", on_delete=models.PROTECT)
    baseline_id = models.CharField(max_length=96)
    baseline_revision = models.CharField(max_length=64, blank=True)
    catalog_revision = models.CharField(max_length=32)
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
