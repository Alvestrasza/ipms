import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("discovery", "0004_connector_error_detail")]

    operations = [
        migrations.AddField(
            model_name="connectorendpoint",
            name="bmc_family",
            field=models.CharField(
                choices=[
                    ("hpe-ilo4", "HPE iLO 4"),
                    ("hpe-ilo-modern", "HPE iLO 5/6/7"),
                    ("dell-idrac", "Dell iDRAC"),
                    ("generic-redfish", "Generic Redfish"),
                ],
                default="hpe-ilo4",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="connectorendpoint",
            name="removed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="connectorendpoint",
            name="removed_by",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.RemoveConstraint(
            model_name="connectorendpoint",
            name="unique_tenant_connector_url",
        ),
        migrations.AddConstraint(
            model_name="connectorendpoint",
            constraint=models.UniqueConstraint(
                condition=models.Q(removed_at__isnull=True),
                fields=("tenant", "base_url"),
                name="unique_tenant_connector_url",
            ),
        ),
        migrations.CreateModel(
            name="BmcCommunicationLog",
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
                ("bmc_name", models.CharField(max_length=255)),
                ("bmc_family", models.CharField(max_length=32)),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("debug", "Debug"),
                            ("info", "Info"),
                            ("warning", "Warning"),
                            ("error", "Error"),
                        ],
                        max_length=16,
                    ),
                ),
                ("event_type", models.CharField(max_length=64)),
                ("method", models.CharField(blank=True, max_length=12)),
                ("resource_path", models.CharField(blank=True, max_length=512)),
                (
                    "http_status",
                    models.PositiveSmallIntegerField(blank=True, null=True),
                ),
                (
                    "duration_ms",
                    models.PositiveIntegerField(blank=True, null=True),
                ),
                ("error_code", models.CharField(blank=True, max_length=128)),
                (
                    "redfish_error_code",
                    models.CharField(blank=True, max_length=128),
                ),
                (
                    "redfish_message_id",
                    models.CharField(blank=True, max_length=128),
                ),
                ("correlation_id", models.UUIDField(blank=True, null=True)),
                ("occurred_at", models.DateTimeField(auto_now_add=True)),
                (
                    "connector",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="communication_logs",
                        to="discovery.connectorendpoint",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="bmc_communication_logs",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={
                "ordering": ("-occurred_at",),
                "indexes": [
                    models.Index(
                        fields=["tenant", "-occurred_at"],
                        name="bmc_log_tenant_time_idx",
                    ),
                    models.Index(
                        fields=["tenant", "severity", "-occurred_at"],
                        name="bmc_log_severity_idx",
                    ),
                    models.Index(
                        fields=["connector", "-occurred_at"],
                        name="bmc_log_connector_idx",
                    ),
                ],
            },
        ),
    ]
