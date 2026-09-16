# File Name: 0009_managed_gpo_target_ous.py
# Version: v0.1.0 | Created: 2026-09-16 | Last Modified: 2026-09-16
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Persist the exact configured OU scope of every managed GPO.

from django.db import migrations, models

DOMAIN_BACKUPS = {
    '{816D1B8C-378B-48D9-B2F4-D5E582A57D7C}',
    '{A4EA0481-872A-4286-839D-A64FFC8F521B}',
    '{04602802-38C4-4900-87CD-B126DA8875ED}',
    '{666ED8AB-DF4A-45CE-9666-61F802515051}',
    '{1D2C9D38-6BB1-4C90-B5EB-2850EA18AE06}',
    '{B9263530-926F-46F3-8382-832C31EC81B5}',
    '{AAC7C960-51D3-4BEE-89BD-7FB10361AA16}',
    '{40CF40AD-F1B2-433F-A5C9-032DB7424608}',
}


def domain_root(name):
    return ','.join(f'DC={part}' for part in name.split('.'))


def backfill_target_ous(apps, schema_editor):
    ManagedGpoPolicy = apps.get_model('security', 'ManagedGpoPolicy')
    policies = ManagedGpoPolicy.objects.select_related('domain', 'origin_job', 'staged_job', 'active_job')
    for policy in policies.iterator():
        targets = []
        for job in (policy.active_job, policy.staged_job, policy.origin_job):
            if job and isinstance(job.assignment, dict) and isinstance(job.assignment.get('target_ous'), list):
                targets = list(job.assignment['target_ous'])
                if targets:
                    break
        if not targets:
            targets = ([domain_root(policy.domain.domain_name)] if policy.backup_id in DOMAIN_BACKUPS
                       else list(policy.domain.tier_ous.get(str(policy.tier), [])))
        policy.target_ous = targets
        policy.save(update_fields=('target_ous',))


class Migration(migrations.Migration):

    dependencies = [
        ('security', '0008_gpo_overrides'),
    ]

    operations = [
        migrations.AddField(
            model_name='managedgpopolicy',
            name='target_ous',
            field=models.JSONField(default=list),
        ),
        migrations.RunPython(backfill_target_ous, migrations.RunPython.noop),
    ]
