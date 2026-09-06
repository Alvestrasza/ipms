import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0011_lifecycle_authority_withdrawal"),
        ("discovery", "0021_action_authority_withdrawal"),
        ("tenancy", "0005_username_reservation"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="HyperVManagementJob",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("request_id", models.UUIDField(unique=True)),
                ("request_digest", models.CharField(max_length=64)),
                ("input_digest", models.CharField(max_length=64)),
                ("requested_by", models.CharField(max_length=255)),
                ("vm_source_id", models.CharField(max_length=64)),
                ("vm_name", models.CharField(max_length=256)),
                (
                    "operation",
                    models.CharField(
                        choices=[
                            ("inspect", "Inspect"),
                            ("checkpoint_create", "Create checkpoint"),
                            ("checkpoint_delete", "Delete checkpoint"),
                            ("checkpoint_apply", "Apply checkpoint"),
                            ("settings_update", "Update settings"),
                        ],
                        max_length=32,
                    ),
                ),
                ("expected_revision", models.CharField(blank=True, max_length=64)),
                ("parameters", models.JSONField(default=dict)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("delivered", "Delivered"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                            ("cancelled", "Cancelled"),
                            ("requires_reconciliation", "Requires reconciliation"),
                        ],
                        default="queued",
                        max_length=32,
                    ),
                ),
                ("phase", models.CharField(blank=True, max_length=64)),
                ("progress", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("result_code", models.CharField(blank=True, max_length=64)),
                ("result_digest", models.CharField(blank=True, max_length=64)),
                (
                    "execution_lease_expires_at",
                    models.DateTimeField(blank=True, null=True),
                ),
                ("authority_revoked_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "actor",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="hyperv_management_jobs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "enrollment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="hyperv_management_jobs",
                        to="agent_pki.agentenrollment",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="hyperv_management_jobs",
                        to="tenancy.tenant",
                    ),
                ),
                (
                    "virtual_machine",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="management_jobs",
                        to="discovery.hypervvirtualmachine",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="HyperVManagementSnapshot",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("revision", models.CharField(max_length=64)),
                ("document", models.JSONField(default=dict)),
                ("observed_at", models.DateTimeField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "enrollment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="hyperv_management_snapshots",
                        to="agent_pki.agentenrollment",
                    ),
                ),
                (
                    "job",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="snapshots",
                        to="discovery.hypervmanagementjob",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="hyperv_management_snapshots",
                        to="tenancy.tenant",
                    ),
                ),
                (
                    "virtual_machine",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="management_snapshot",
                        to="discovery.hypervvirtualmachine",
                    ),
                ),
            ],
        ),
        migrations.AddIndex(
            model_name="hypervmanagementjob",
            index=models.Index(
                fields=["enrollment", "status"], name="hvmgmt_agent_state_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="hypervmanagementjob",
            constraint=models.UniqueConstraint(
                condition=models.Q(
                    status__in=(
                        "queued",
                        "delivered",
                        "running",
                        "requires_reconciliation",
                    )
                ),
                fields=("enrollment", "vm_source_id"),
                name="unique_active_hvmgmt_vm",
            ),
        ),
        migrations.AddConstraint(
            model_name="hypervmanagementjob",
            constraint=models.CheckConstraint(
                condition=models.Q(progress__isnull=True) | models.Q(progress__lte=100),
                name="hvmgmt_progress_lte100",
            ),
        ),
    ]
