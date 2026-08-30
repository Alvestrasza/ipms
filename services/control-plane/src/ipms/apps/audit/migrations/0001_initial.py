import django.db.models.deletion
import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [("tenancy", "0001_initial")]

    operations = [
        migrations.CreateModel(
            name="AuditEvent",
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
                ("occurred_at", models.DateTimeField(auto_now_add=True)),
                ("actor", models.CharField(max_length=255)),
                ("action", models.CharField(max_length=255)),
                ("object_type", models.CharField(blank=True, max_length=255)),
                ("object_id", models.CharField(blank=True, max_length=255)),
                (
                    "outcome",
                    models.CharField(
                        choices=[
                            ("succeeded", "Succeeded"),
                            ("denied", "Denied"),
                            ("failed", "Failed"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "correlation_id",
                    models.UUIDField(default=uuid.uuid4, editable=False),
                ),
                ("request_id", models.CharField(blank=True, max_length=255)),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("details", models.JSONField(blank=True, default=dict)),
                (
                    "tenant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="audit_events",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ("-occurred_at",),
                "indexes": [
                    models.Index(
                        fields=["tenant", "-occurred_at"],
                        name="audit_tenant_time_idx",
                    ),
                    models.Index(
                        fields=["correlation_id"],
                        name="audit_correlation_idx",
                    ),
                ],
            },
        ),
    ]
