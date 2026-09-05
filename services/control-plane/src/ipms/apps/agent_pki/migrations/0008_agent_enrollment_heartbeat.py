from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agent_pki", "0007_agent_enrollment_platform")]

    operations = [
        migrations.AddField(
            model_name="agentenrollment",
            name="last_heartbeat_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
