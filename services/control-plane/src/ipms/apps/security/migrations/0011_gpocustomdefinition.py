# File Name: 0011_gpocustomdefinition.py
# Version: v0.1.0 | Created: 2026-09-18 | Last Modified: 2026-09-18
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Distinguish tenant custom GPO definitions from baseline overrides.
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('security', '0010_collections')]

    operations = [
        migrations.AddField(
            model_name='gpooverride',
            name='kind',
            field=models.CharField(
                choices=[('override', 'Override'), ('custom', 'Custom')],
                default='override',
                max_length=16,
            ),
        ),
    ]
