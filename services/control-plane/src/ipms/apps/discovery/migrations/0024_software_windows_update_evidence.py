# File Name: 0024_software_windows_update_evidence.py
# Version: v0.1.0
# Created: 2026-09-13
# Last Modified: 2026-09-13
# Author: Alice Endelgard
# Organization: Alvestrasza Corporation
# Description: Preserve authenticated local Windows installed-update observations.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0023_hypervsettingslease")]
    operations = [migrations.AddField(
        model_name="softwareinventorysnapshot", name="windows_update_evidence",
        field=models.JSONField(default=dict, blank=True),
    )]
