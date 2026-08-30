import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("discovery", "0001_initial"),
        ("tenancy", "0002_tenantmembership"),
    ]

    operations = [
        migrations.CreateModel(
            name="ConnectorEndpoint",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("connector_type", models.CharField(choices=[("ilo-redfish", "iLO Redfish"), ("hyper-v", "Hyper-V")], max_length=32)),
                ("display_name", models.CharField(max_length=255)),
                ("base_url", models.URLField(max_length=512)),
                ("credential_reference", models.UUIDField(default=uuid.uuid4, unique=True)),
                ("tls_certificate_sha256", models.CharField(max_length=64)),
                ("enabled", models.BooleanField(default=True)),
                ("health", models.CharField(choices=[("unknown", "Unknown"), ("healthy", "Healthy"), ("warning", "Warning"), ("critical", "Critical")], default="unknown", max_length=16)),
                ("last_error_code", models.CharField(blank=True, max_length=64)),
                ("last_attempt_at", models.DateTimeField(blank=True, null=True)),
                ("last_success_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="connector_endpoints", to="tenancy.tenant")),
            ],
            options={"ordering": ("display_name",)},
        ),
        migrations.AddConstraint(
            model_name="connectorendpoint",
            constraint=models.UniqueConstraint(fields=("tenant", "base_url"), name="unique_tenant_connector_url"),
        ),
        migrations.AddField(
            model_name="discoveryjob",
            name="connector",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="discovery_jobs", to="discovery.connectorendpoint"),
        ),
        migrations.CreateModel(
            name="PhysicalSystem",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("source_resource_id", models.CharField(max_length=512)),
                ("name", models.CharField(max_length=255)),
                ("manufacturer", models.CharField(blank=True, max_length=255)),
                ("model", models.CharField(blank=True, max_length=255)),
                ("serial_number", models.CharField(blank=True, max_length=255)),
                ("sku", models.CharField(blank=True, max_length=255)),
                ("system_uuid", models.CharField(blank=True, max_length=64)),
                ("power_state", models.CharField(blank=True, max_length=32)),
                ("health", models.CharField(choices=[("ok", "OK"), ("warning", "Warning"), ("critical", "Critical"), ("unknown", "Unknown")], default="unknown", max_length=16)),
                ("state", models.CharField(blank=True, max_length=32)),
                ("processor_count", models.PositiveIntegerField(blank=True, null=True)),
                ("processor_model", models.CharField(blank=True, max_length=255)),
                ("total_cores", models.PositiveIntegerField(blank=True, null=True)),
                ("memory_bytes", models.PositiveBigIntegerField(blank=True, null=True)),
                ("bios_version", models.CharField(blank=True, max_length=255)),
                ("bmc_firmware_version", models.CharField(blank=True, max_length=255)),
                ("discovered_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("connector", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="physical_systems", to="discovery.connectorendpoint")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="physical_systems", to="tenancy.tenant")),
            ],
            options={
                "ordering": ("name",),
                "indexes": [models.Index(fields=["tenant", "health"], name="physical_tenant_health")],
            },
        ),
        migrations.AddConstraint(
            model_name="physicalsystem",
            constraint=models.UniqueConstraint(fields=("connector", "source_resource_id"), name="unique_connector_physical_resource"),
        ),
    ]
