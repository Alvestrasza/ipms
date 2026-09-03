from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0004_agentlifecyclejob"),
    ]

    operations = [
        migrations.AddField(
            model_name="windowsagentdeployment",
            name="lifecycle_bootstrap_enrollment",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="lifecycle_bootstrap_deployments",
                to="agent_pki.agentenrollment",
            ),
        ),
    ]
