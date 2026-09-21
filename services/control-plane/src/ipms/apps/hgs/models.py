# File Name: models.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Immutable HGS plans, enrolled Windows node bindings and durable step receipts.
import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q


class HgsDeployment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("tenancy.Tenant", on_delete=models.PROTECT)
    name = models.CharField(max_length=128)
    profile = models.CharField(max_length=16)
    attestation_mode = models.CharField(max_length=16)
    domain_name = models.CharField(max_length=253)
    service_name = models.CharField(max_length=63)
    config = models.JSONField(default=dict)
    plan_digest = models.CharField(max_length=64)
    status = models.CharField(max_length=32, default="draft")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="hgs_plans")
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name="hgs_approvals")
    approved_at = models.DateTimeField(null=True)
    plan_expires_at = models.DateTimeField()
    approval_expires_at = models.DateTimeField(null=True)
    authority_revoked_at = models.DateTimeField(null=True)
    blockers = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=("tenant", "status"), name="hgs_plan_tenant_status")]


class HgsNode(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    deployment = models.ForeignKey(HgsDeployment, on_delete=models.PROTECT, related_name="nodes")
    system = models.ForeignKey("discovery.WindowsServer", on_delete=models.PROTECT)
    enrollment = models.ForeignKey("agent_pki.AgentEnrollment", on_delete=models.PROTECT)
    device_uri = models.CharField(max_length=64)
    hostname = models.CharField(max_length=255)
    ordinal = models.PositiveSmallIntegerField()
    role = models.CharField(max_length=16)
    status = models.CharField(max_length=32, default="pending")
    readiness = models.JSONField(null=True)
    blockers = models.JSONField(default=list)
    observed_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ("ordinal",)
        constraints = [
            models.UniqueConstraint(fields=("deployment", "ordinal"), name="hgs_node_ordinal_unique"),
            models.UniqueConstraint(fields=("deployment", "enrollment"), name="hgs_node_enrollment_unique"),
        ]


class HgsJob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    deployment = models.ForeignKey(HgsDeployment, on_delete=models.PROTECT, related_name="jobs")
    node = models.ForeignKey(HgsNode, on_delete=models.PROTECT, related_name="jobs")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name="hgs_jobs")
    operation = models.CharField(max_length=24)
    sequence = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=32, default="queued")
    assignment = models.JSONField(default=dict)
    receipt = models.JSONField(null=True)
    preboot_id = models.CharField(max_length=64, blank=True, default="")
    reconciliation_release = models.JSONField(null=True)
    result_code = models.CharField(max_length=64, blank=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    offered_at = models.DateTimeField(null=True)
    claimed_at = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)

    class Meta:
        ordering = ("created_at", "id")
        constraints = [models.UniqueConstraint(
            fields=("node",), condition=Q(status__in=("queued", "offered", "running", "waiting_for_reboot")),
            name="hgs_one_active_node_job",
        )]
