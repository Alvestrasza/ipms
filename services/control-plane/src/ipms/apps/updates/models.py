# File Name: models.py
# Version: v0.2.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Tenant-bound WSUS sources and atomically published metadata snapshots.
import uuid

from django.db import models

from ipms.apps.tenancy.models import Tenant


class UpdateSource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.PROTECT)
    name = models.CharField(max_length=128)
    scope = models.CharField(max_length=255)
    # Configured publisher target only; the Control Plane never dials this host.
    wsus_host = models.CharField(max_length=253, blank=True, default="")
    wsus_port = models.PositiveIntegerField(default=8531)
    wsus_use_ssl = models.BooleanField(default=True)
    wsus_changed_at = models.DateTimeField(null=True, blank=True)
    enabled = models.BooleanField(default=True)
    token_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    current_snapshot = models.ForeignKey(
        "WsusSnapshot", on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )

    class Meta:
        ordering = ("name", "id")


class WsusSnapshot(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(UpdateSource, on_delete=models.CASCADE, related_name="snapshots")
    snapshot_id = models.UUIDField()
    digest = models.CharField(max_length=64)
    observed_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True)
    # Explicit bounded catalog scope. Missing computer/update cells remain unknown.
    updates = models.JSONField(default=list)
    update_count = models.PositiveIntegerField()
    computer_count = models.PositiveIntegerField()

    class Meta:
        constraints = [models.UniqueConstraint(
            fields=("source", "snapshot_id"), name="unique_wsus_source_snapshot"
        )]


class WsusComputerReport(models.Model):
    snapshot = models.ForeignKey(WsusSnapshot, on_delete=models.CASCADE, related_name="computers")
    computer_id = models.UUIDField()
    fqdn = models.CharField(max_length=253)
    reported_at = models.DateTimeField(null=True)
    updates = models.JSONField(default=list)

    class Meta:
        constraints = [models.UniqueConstraint(
            fields=("snapshot", "computer_id"), name="unique_wsus_snapshot_computer"
        )]
        indexes = [models.Index(fields=("snapshot", "fqdn"), name="wsus_snapshot_fqdn_idx")]
