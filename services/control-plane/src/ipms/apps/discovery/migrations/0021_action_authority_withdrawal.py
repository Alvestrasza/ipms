from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0020_native_console_transport")]
    operations = [
        migrations.AddField(
            model_name="hypervvirtualmachineactionjob",
            name="authority_revoked_at",
            field=models.DateTimeField(blank=True, null=True),
        )
    ]
