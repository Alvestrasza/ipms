# File Name: 0004_hgsjob_preboot_id.py
# Version: v0.1.0 | Created: 2026-09-20 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Preserve the first pre-reboot evidence independently of later receipts.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("hgs", "0003_hgsjob_requested_by")]
    operations = [migrations.AddField(
        model_name="hgsjob", name="preboot_id",
        field=models.CharField(blank=True, default="", max_length=64),
    )]
