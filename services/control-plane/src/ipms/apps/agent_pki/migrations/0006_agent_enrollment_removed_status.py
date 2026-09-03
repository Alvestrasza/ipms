from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0005_windowsagentdeployment_lifecycle_bootstrap"),
    ]

    operations = [
        migrations.AlterField(
            model_name="agentenrollment",
            name="status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("active", "Active"),
                    ("revoked", "Revoked"),
                    ("removed", "Removed"),
                ],
                default="pending",
                max_length=16,
            ),
        ),
    ]
