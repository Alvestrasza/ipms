from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0005_bmc_management_and_logs")]

    operations = [
        migrations.AddField(
            model_name="physicalsystem",
            name="detail_snapshot",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
