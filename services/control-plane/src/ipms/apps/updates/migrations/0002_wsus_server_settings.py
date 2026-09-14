# File Name: 0002_wsus_server_settings.py
# Version: v0.1.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Persist optional WSUS publisher endpoint settings without network actions.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("updates", "0001_initial")]

    operations = [
        migrations.AddField(model_name="updatesource", name="wsus_host",
                            field=models.CharField(blank=True, default="", max_length=253)),
        migrations.AddField(model_name="updatesource", name="wsus_port",
                            field=models.PositiveIntegerField(default=8531)),
        migrations.AddField(model_name="updatesource", name="wsus_use_ssl",
                            field=models.BooleanField(default=True)),
        migrations.AddField(model_name="updatesource", name="wsus_changed_at",
                            field=models.DateTimeField(blank=True, null=True)),
    ]
