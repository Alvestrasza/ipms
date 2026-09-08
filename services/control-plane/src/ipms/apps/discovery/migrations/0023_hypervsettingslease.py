from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("discovery", "0022_hyperv_management"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="HyperVSettingsLease",
            fields=[
                (
                    "virtual_machine",
                    models.OneToOneField(
                        primary_key=True,
                        serialize=False,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="settings_lease",
                        to="discovery.hypervvirtualmachine",
                    ),
                ),
                (
                    "actor",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("dialog_id", models.UUIDField()),
                ("session_digest", models.CharField(max_length=64)),
                ("expires_at", models.DateTimeField()),
            ],
        ),
    ]
