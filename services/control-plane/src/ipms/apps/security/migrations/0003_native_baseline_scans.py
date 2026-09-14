# File Name: 0003_native_baseline_scans.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Add bounded native scan jobs and per-control assessment findings.
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('agent_pki', '0011_lifecycle_authority_withdrawal'),
        ('discovery', '0024_software_windows_update_evidence'),
        ('security', '0002_baseline_visibility'),
        ('tenancy', '0005_username_reservation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.AddField(model_name='baselineassessment', name='content_sha256', field=models.CharField(blank=True, max_length=64)),
        migrations.AddField(model_name='baselineassessment', name='findings', field=models.JSONField(blank=True, default=list)),
        migrations.CreateModel(
            name='BaselineScanJob',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('baseline_id', models.CharField(max_length=96)),
                ('baseline_revision', models.CharField(blank=True, max_length=64)),
                ('catalog_revision', models.CharField(max_length=32)),
                ('profile', models.CharField(max_length=24)),
                ('manifest_sha256', models.CharField(max_length=64)),
                ('os_build', models.CharField(max_length=64)),
                ('operating_system', models.CharField(max_length=255)),
                ('status', models.CharField(choices=[('queued', 'queued'), ('running', 'running'), ('completed', 'completed'), ('failed', 'failed'), ('expired', 'expired')], default='queued', max_length=16)),
                ('requested_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('expires_at', models.DateTimeField()),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('attempt_id', models.UUIDField(blank=True, null=True)),
                ('attempt_count', models.PositiveSmallIntegerField(default=0)),
                ('lease_expires_at', models.DateTimeField(blank=True, null=True)),
                ('pages', models.JSONField(blank=True, default=dict)),
                ('page_hashes', models.JSONField(blank=True, default=dict)),
                ('page_count', models.PositiveSmallIntegerField(default=0)),
                ('evidence_system', models.JSONField(blank=True, default=dict)),
                ('error_code', models.CharField(blank=True, max_length=32)),
                ('assessment', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='security.baselineassessment')),
                ('enrollment', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='agent_pki.agentenrollment')),
                ('requested_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('system', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='discovery.windowsserver')),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tenancy.tenant')),
            ],
            options={
                'ordering': ('-requested_at', '-id'),
                'indexes': [models.Index(fields=['enrollment', 'status'], name='security_scan_agent_status')],
                'constraints': [models.UniqueConstraint(condition=models.Q(('status__in', ('queued', 'running'))), fields=('system', 'baseline_id'), name='security_one_active_scan')],
            },
        ),
    ]
