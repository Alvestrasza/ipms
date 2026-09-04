from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agent_pki", "0006_agent_enrollment_removed_status")]

    operations = [
        migrations.AddField(
            model_name="agentenrollment",
            name="platform",
            field=models.CharField(
                choices=[("windows", "Windows"), ("linux", "Linux")],
                default="windows",
                max_length=16,
            ),
        ),
    ]
