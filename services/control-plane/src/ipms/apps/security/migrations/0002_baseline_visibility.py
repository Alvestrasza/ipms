# File Name: 0002_baseline_visibility.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Add tenant baseline visibility preferences; existing baselines stay visible.
import uuid
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("security", "0001_initial"), ("tenancy", "0001_initial")]
    operations = [migrations.CreateModel(
        name="BaselinePreference",
        fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("baseline_id", models.CharField(max_length=96)),
            ("hidden", models.BooleanField(default=False)),
            ("updated_at", models.DateTimeField(auto_now=True)),
            ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="tenancy.tenant")),
        ],
        options={"constraints": [models.UniqueConstraint(fields=("tenant", "baseline_id"), name="security_tenant_baseline_pref")]},
    )]
