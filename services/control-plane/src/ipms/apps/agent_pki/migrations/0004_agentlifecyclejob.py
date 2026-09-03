import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0003_windows_deployment_transport"),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentLifecycleJob",
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
                (
                    "action",
                    models.CharField(
                        choices=[("update", "Update"), ("uninstall", "Uninstall")],
                        max_length=16,
                    ),
                ),
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
                        ],
                        default="queued",
                        max_length=16,
                    ),
                ),
                ("target_version", models.CharField(blank=True, max_length=64)),
                ("artifact_sha256", models.CharField(blank=True, max_length=64)),
                ("requested_by", models.CharField(max_length=255)),
                ("result_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "enrollment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="lifecycle_jobs",
                        to="agent_pki.agentenrollment",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="agent_lifecycle_jobs",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at",),
                "indexes": [
                    models.Index(
                        fields=["tenant", "-created_at"],
                        name="agent_lifecycle_tenant_time",
                    ),
                    models.Index(
                        fields=["enrollment", "status"],
                        name="agent_lifecycle_device_state",
                    ),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        condition=models.Q(
                            status__in=("queued", "delivered", "running")
                        ),
                        fields=("enrollment",),
                        name="unique_active_agent_lifecycle_job",
                    ),
                ],
            },
        ),
    ]
