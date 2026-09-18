# File Name: 0010_collections.py
# Version: v0.1.0 | Created: 2026-09-18 | Last Modified: 2026-09-18
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Persist tenant device collections and ordered multi-domain policy rollouts.
import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('security', '0009_managed_gpo_target_ous'),
        ('tenancy', '0005_username_reservation'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='PolicyCollection',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.CharField(blank=True, max_length=500)),
                ('revision', models.PositiveIntegerField(default=1)),
                ('entries', models.JSONField(default=list)),
                ('bindings', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tenancy.tenant')),
            ],
            options={'ordering': ('name', 'id')},
        ),
        migrations.CreateModel(
            name='PolicyCollectionDeployment',
            fields=[
                ('id', models.UUIDField(editable=False, primary_key=True, serialize=False)),
                ('collection_revision', models.PositiveIntegerField()),
                ('status', models.CharField(default='queued', max_length=32)),
                ('snapshot', models.JSONField()),
                ('requested_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('completed_at', models.DateTimeField(null=True)),
                ('collection', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='deployments', to='security.policycollection')),
                ('requested_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tenancy.tenant')),
            ],
            options={'ordering': ('-requested_at', '-id')},
        ),
        migrations.CreateModel(
            name='PolicyCollectionDeploymentItem',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('policy_index', models.PositiveSmallIntegerField()),
                ('sequence', models.PositiveIntegerField()),
                ('status', models.CharField(default='pending', max_length=32)),
                ('selection', models.JSONField()),
                ('error_code', models.CharField(blank=True, max_length=64)),
                ('completed_at', models.DateTimeField(null=True)),
                ('deployment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='items', to='security.policycollectiondeployment')),
                ('domain', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='security.domainsecuritysettings')),
                ('preflight_job', models.OneToOneField(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='security.gpoimportjob')),
                ('write_job', models.OneToOneField(null=True, on_delete=django.db.models.deletion.PROTECT, related_name='+', to='security.gpoimportjob')),
            ],
            options={'ordering': ('sequence', 'id')},
        ),
        migrations.CreateModel(
            name='DeviceCollection',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100)),
                ('description', models.CharField(blank=True, max_length=500)),
                ('revision', models.PositiveIntegerField(default=1)),
                ('static_system_ids', models.JSONField(default=list)),
                ('rules', models.JSONField(default=list)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('tenant', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='tenancy.tenant')),
            ],
            options={
                'ordering': ('name', 'id'),
                'constraints': [models.UniqueConstraint(fields=('tenant', 'name'), name='security_device_collection_name')],
            },
        ),
        migrations.AddConstraint(
            model_name='policycollection',
            constraint=models.UniqueConstraint(fields=('tenant', 'name'), name='security_policy_collection_name'),
        ),
        migrations.AddConstraint(
            model_name='policycollectiondeploymentitem',
            constraint=models.UniqueConstraint(fields=('deployment', 'domain', 'policy_index'), name='security_policy_deployment_item'),
        ),
    ]
