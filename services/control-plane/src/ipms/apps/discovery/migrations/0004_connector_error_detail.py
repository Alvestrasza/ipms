from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0003_connectorsecret")]

    operations = [
        migrations.AddField(
            model_name="connectorendpoint",
            name="last_error_detail",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="discoveryjob",
            name="error_detail",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
