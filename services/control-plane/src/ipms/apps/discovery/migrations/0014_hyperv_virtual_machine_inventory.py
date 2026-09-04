import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0013_windows_system_classification")]

    operations = [
        migrations.AddField(
            model_name="windowsserver",
            name="hyperv_inventory_error",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="windowsserver",
            name="hyperv_inventory_status",
            field=models.CharField(
                choices=[
                    ("not-reported", "Not reported"),
                    ("not-applicable", "Not applicable"),
                    ("collected", "Collected"),
                    ("unavailable", "Unavailable"),
                ],
                default="not-reported",
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name="HyperVVirtualMachine",
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
                ("source_id", models.CharField(max_length=64)),
                ("name", models.CharField(max_length=255)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("running", "Running"),
                            ("stopped", "Stopped"),
                            ("starting", "Starting"),
                            ("stopping", "Stopping"),
                            ("paused", "Paused"),
                            ("pausing", "Pausing"),
                            ("suspended", "Suspended"),
                            ("saving", "Saving"),
                            ("resuming", "Resuming"),
                            ("quiesced", "Quiesced"),
                            ("offline", "Offline"),
                            ("unknown", "Unknown"),
                        ],
                        default="unknown",
                        max_length=16,
                    ),
                ),
                ("vcpu_count", models.PositiveIntegerField(blank=True, null=True)),
                ("memory_bytes", models.PositiveBigIntegerField(blank=True, null=True)),
                (
                    "uptime_seconds",
                    models.PositiveBigIntegerField(blank=True, null=True),
                ),
                ("configuration_version", models.CharField(blank=True, max_length=64)),
                ("ip_addresses", models.JSONField(blank=True, default=list)),
                ("observed_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "host",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="hyperv_virtual_machines",
                        to="discovery.windowsserver",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="hyperv_virtual_machines",
                        to="tenancy.tenant",
                    ),
                ),
            ],
            options={"ordering": ("name", "source_id")},
        ),
        migrations.AddConstraint(
            model_name="hypervvirtualmachine",
            constraint=models.UniqueConstraint(
                fields=("host", "source_id"),
                name="unique_hyperv_host_virtual_machine",
            ),
        ),
        migrations.AddIndex(
            model_name="hypervvirtualmachine",
            index=models.Index(
                fields=["tenant", "state"],
                name="hyperv_vm_tenant_state_idx",
            ),
        ),
    ]
