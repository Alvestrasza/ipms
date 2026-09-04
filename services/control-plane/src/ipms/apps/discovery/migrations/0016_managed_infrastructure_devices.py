import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0015_softwareinventorysnapshot_softwarepackage_and_more")]

    operations = [
        migrations.AlterField(
            model_name="connectorendpoint",
            name="base_url",
            field=models.CharField(max_length=512),
        ),
        migrations.AlterField(
            model_name="connectorendpoint",
            name="connector_type",
            field=models.CharField(
                choices=[
                    ("ilo-redfish", "iLO Redfish"),
                    ("hyper-v", "Hyper-V"),
                    ("sophos-firewall", "Sophos Firewall"),
                    ("loadbalancer-org", "Loadbalancer.org ADC"),
                    ("hpe-comware", "HPE Comware"),
                ],
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="discoveryjob",
            name="connector_type",
            field=models.CharField(
                choices=[
                    ("ilo-redfish", "iLO Redfish"),
                    ("hyper-v", "Hyper-V"),
                    ("sophos-firewall", "Sophos Firewall"),
                    ("loadbalancer-org", "Loadbalancer.org ADC"),
                    ("hpe-comware", "HPE Comware"),
                ],
                max_length=32,
            ),
        ),
        migrations.CreateModel(
            name="ManagedInfrastructureDevice",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("category", models.CharField(choices=[("firewall", "Firewall"), ("load-balancer", "Load balancer"), ("switch", "Switch")], max_length=24)),
                ("name", models.CharField(max_length=255)),
                ("vendor", models.CharField(max_length=128)),
                ("product", models.CharField(max_length=128)),
                ("model", models.CharField(blank=True, max_length=255)),
                ("software_version", models.CharField(blank=True, max_length=255)),
                ("serial_number", models.CharField(blank=True, max_length=255)),
                ("uptime_seconds", models.PositiveBigIntegerField(blank=True, null=True)),
                ("health", models.CharField(choices=[("healthy", "Healthy"), ("warning", "Warning"), ("critical", "Critical"), ("unknown", "Unknown")], default="unknown", max_length=16)),
                ("interfaces", models.JSONField(blank=True, default=list)),
                ("details", models.JSONField(blank=True, default=dict)),
                ("discovered_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("connector", models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name="managed_device", to="discovery.connectorendpoint")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="managed_infrastructure_devices", to="tenancy.tenant")),
            ],
            options={"ordering": ("category", "name")},
        ),
        migrations.AddConstraint(
            model_name="managedinfrastructuredevice",
            constraint=models.UniqueConstraint(fields=("tenant", "connector"), name="unique_tenant_managed_device_connector"),
        ),
    ]
