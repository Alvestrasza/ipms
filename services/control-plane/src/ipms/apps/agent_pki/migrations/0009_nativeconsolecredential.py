import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0008_agent_enrollment_heartbeat"),
        ("tenancy", "0003_tenantmembership_expires_at_and_more"),
    ]
    operations = [migrations.CreateModel(
        name="NativeConsoleCredential",
        fields=[
            ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
            ("nonce", models.BinaryField()), ("ciphertext", models.BinaryField()),
            ("updated_at", models.DateTimeField(auto_now=True)),
            ("enrollment", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="native_console_credential", to="agent_pki.agentenrollment")),
            ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="tenancy.tenant")),
        ],
    )]
