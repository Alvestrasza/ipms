# File Name: 0002_hgsjob_reconciliation_release.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Preserve reviewed observation receipts that release an interrupted HGS step.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("hgs", "0001_initial")]
    operations = [migrations.AddField(model_name="hgsjob", name="reconciliation_release", field=models.JSONField(null=True))]
