import uuid
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0009_nativeconsolecredential"),
        ("tenancy", "0003_tenantmembership_expires_at_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServiceAccount",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=128)),
                ("kind", models.CharField(choices=[("hyperv_console", "Hyper-V console")], default="hyperv_console", max_length=32)),
                ("nonce", models.BinaryField()),
                ("ciphertext", models.BinaryField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="tenancy.tenant")),
            ],
            options={"ordering": ("name", "id")},
        ),
        migrations.AddField(
            model_name="nativeconsolecredential", name="service_account",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="bindings", to="agent_pki.serviceaccount"),
        ),
        migrations.AddConstraint(
            model_name="nativeconsolecredential",
            constraint=models.CheckConstraint(
                condition=models.Q(service_account__isnull=True) | models.Q(nonce=b"", ciphertext=b""),
                name="native_central_binding_no_legacy_secret",
            ),
        ),
    ]
