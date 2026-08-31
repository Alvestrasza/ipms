import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0006_physicalsystem_detail_snapshot")]

    operations = [
        migrations.CreateModel(
            name="BmcEventLogEntry",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("bmc_name", models.CharField(max_length=255)),
                ("log_type", models.CharField(choices=[("ilo_event_log", "iLO Event Log"), ("integrated_management_log", "Integrated Management Log")], max_length=32)),
                ("source_record_id", models.CharField(max_length=255)),
                ("severity", models.CharField(choices=[("info", "Info"), ("warning", "Warning"), ("critical", "Critical"), ("unknown", "Unknown")], max_length=16)),
                ("message", models.TextField(max_length=8192)),
                ("source_created_at", models.DateTimeField(blank=True, null=True)),
                ("source_updated_at", models.DateTimeField(blank=True, null=True)),
                ("repeat_count", models.PositiveIntegerField(blank=True, null=True)),
                ("repaired", models.BooleanField(blank=True, null=True)),
                ("event_class", models.IntegerField(blank=True, null=True)),
                ("event_code", models.IntegerField(blank=True, null=True)),
                ("event_number", models.IntegerField(blank=True, null=True)),
                ("record_format", models.CharField(blank=True, max_length=64)),
                ("first_discovered_at", models.DateTimeField(auto_now_add=True)),
                ("last_discovered_at", models.DateTimeField()),
                ("connector", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="event_log_entries", to="discovery.connectorendpoint")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="bmc_event_log_entries", to="tenancy.tenant")),
            ],
            options={
                "ordering": ("-source_created_at", "-last_discovered_at"),
                "indexes": [models.Index(fields=["tenant", "-source_created_at"], name="bmc_event_tenant_time_idx"), models.Index(fields=["tenant", "severity", "-source_created_at"], name="bmc_event_severity_idx"), models.Index(fields=["connector", "log_type", "-source_created_at"], name="bmc_event_source_idx")],
                "constraints": [models.UniqueConstraint(fields=("connector", "log_type", "source_record_id"), name="unique_bmc_source_log_entry")],
            },
        )
    ]
