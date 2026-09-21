# File Name: 0003_hgsjob_requested_by.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Bind each HGS inspection or execution step to its current authorizing actor.
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("hgs", "0002_hgsjob_reconciliation_release"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [migrations.AddField(model_name="hgsjob", name="requested_by", field=models.ForeignKey(
        null=True, on_delete=django.db.models.deletion.PROTECT, related_name="hgs_jobs", to=settings.AUTH_USER_MODEL))]
