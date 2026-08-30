import django.db.models.deletion
import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [("tenancy", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="DiscoveryJob",
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
                    "connector_type",
                    models.CharField(
                        choices=[
                            ("ilo-redfish", "iLO Redfish"),
                            ("hyper-v", "Hyper-V"),
                        ],
                        max_length=32,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        default="queued",
                        max_length=16,
                    ),
                ),
                ("requested_by", models.CharField(max_length=255)),
                (
                    "correlation_id",
                    models.UUIDField(default=uuid.uuid4, editable=False),
                ),
                ("parameters", models.JSONField(blank=True, default=dict)),
                ("result_summary", models.JSONField(blank=True, default=dict)),
                ("error_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="discovery_jobs",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ("-created_at",),
                "indexes": [
                    models.Index(
                        fields=["tenant", "-created_at"],
                        name="job_tenant_time_idx",
                    ),
                    models.Index(fields=["status"], name="job_status_idx"),
                ],
            },
        ),
    ]
