# File Name: 0006_tenant_purpose.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-19
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Preserve infrastructure tenants and introduce a dedicated HGS identity scope.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("tenancy", "0005_username_reservation")]
    operations = [migrations.AddField(
        model_name="tenant", name="purpose",
        field=models.CharField(max_length=16, default="infrastructure",
                               choices=[("infrastructure", "Infrastructure"), ("hgs", "Host Guardian Service")]),
    )]
