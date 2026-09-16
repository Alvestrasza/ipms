# File Name: 0007_gpo_reconciliation.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Add immutable reconciliation evidence without modifying existing job or policy columns.
import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('security', '0006_managedgpopolicy_and_more'), ('tenancy', '0005_username_reservation'),
                    migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [migrations.CreateModel(name='GpoReconciliation', fields=[
        ('id', models.UUIDField(editable=False, primary_key=True, serialize=False)),
        ('status', models.CharField(default='requested', max_length=24)),
        ('accepted_actor', models.CharField(blank=True, max_length=64)),
        ('request_digest', models.CharField(max_length=64)),
        ('job_result_digest', models.CharField(blank=True, max_length=64)),
        ('journal_sha256', models.CharField(blank=True, max_length=64)),
        ('scope_revision', models.PositiveIntegerField()),
        ('policy_revision', models.PositiveIntegerField()),
        ('authorization_revision', models.PositiveIntegerField()),
        ('managed_revision', models.PositiveIntegerField()),
        ('four_eyes_required', models.BooleanField(default=False)),
        ('observation', models.JSONField(null=True)),
        ('observation_digest', models.CharField(blank=True, max_length=64)),
        ('drift_observation', models.JSONField(null=True)),
        ('drift_digest', models.CharField(blank=True, max_length=64)),
        ('decision_digest', models.CharField(blank=True, max_length=64)),
        ('requested_at', models.DateTimeField(default=django.utils.timezone.now)),
        ('expires_at', models.DateTimeField()),
        ('observed_at', models.DateTimeField(null=True)),
        ('accepted_at', models.DateTimeField(null=True)),
        ('finalized_at', models.DateTimeField(null=True)),
        ('accepted_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
        ('requested_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
        ('job', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='reconciliations', to='security.gpoimportjob')),
        ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tenancy.tenant')),
    ], options={'ordering': ('-requested_at', '-id'), 'constraints': [models.UniqueConstraint(
        condition=models.Q(status__in=('requested', 'observed', 'accept_requested')), fields=('job',), name='security_gpo_one_reconcile')]})]
