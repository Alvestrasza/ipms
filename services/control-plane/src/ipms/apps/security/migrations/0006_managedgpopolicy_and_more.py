# File Name: 0006_managedgpopolicy_and_more.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Add stable managed GPO identities without changing legacy job columns.
import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agent_pki', '0011_lifecycle_authority_withdrawal'),
        ('discovery', '0024_software_windows_update_evidence'),
        ('security', '0005_gpoapprovalpolicy_gpodomainauthorization_and_more'),
        ('tenancy', '0005_username_reservation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(name='ManagedGpoPolicy', fields=[
            ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ('domain_guid', models.CharField(max_length=36)),
            ('logical_key', models.CharField(max_length=64)),
            ('tier', models.PositiveSmallIntegerField()),
            ('baseline_id', models.CharField(max_length=96)),
            ('profile', models.CharField(max_length=32)),
            ('purpose', models.CharField(max_length=80)),
            ('target', models.CharField(max_length=32)),
            ('gpo_guid', models.CharField(blank=True, max_length=36)),
            ('display_name', models.CharField(max_length=240)),
            ('name_key', models.CharField(max_length=240)),
            ('version', models.CharField(max_length=32)),
            ('backup_id', models.CharField(max_length=38)),
            ('state', models.CharField(default='new', max_length=32)),
            ('revision', models.PositiveIntegerField(default=1)),
            ('active_job', models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='security.gpoimportjob')),
            ('domain', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='security.domainsecuritysettings')),
            ('origin_job', models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='security.gpoimportjob')),
            ('staged_job', models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='security.gpoimportjob')),
            ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tenancy.tenant')),
        ]),
        migrations.RemoveConstraint(model_name='gpoimportjob', name='security_gpo_pilot_identity'),
        migrations.AddConstraint(model_name='gpoimportjob', constraint=models.UniqueConstraint(
            condition=models.Q(assignment__schema__in=(1, 2)), fields=('tenant', 'domain_guid', 'pilot_name_key'), name='security_gpo_pilot_identity')),
        migrations.AddConstraint(model_name='managedgpopolicy', constraint=models.UniqueConstraint(
            fields=('tenant', 'domain_guid', 'logical_key'), name='security_managed_gpo_identity')),
        migrations.AddConstraint(model_name='managedgpopolicy', constraint=models.UniqueConstraint(
            fields=('tenant', 'domain_guid', 'name_key'), name='security_managed_gpo_name')),
        migrations.AddConstraint(model_name='managedgpopolicy', constraint=models.UniqueConstraint(
            condition=~models.Q(gpo_guid=''), fields=('tenant', 'domain_guid', 'gpo_guid'), name='security_managed_gpo_guid')),
    ]
