import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.utils import timezone


def separate_platform_principals(apps, schema_editor):
    alias = schema_editor.connection.alias
    users = apps.get_model(*settings.AUTH_USER_MODEL.split("."))
    tenants = apps.get_model("tenancy", "Tenant")
    memberships = apps.get_model("tenancy", "TenantMembership")
    platform = apps.get_model("tenancy", "PlatformAdministrator")
    legacy_ids = list(
        users.objects.using(alias)
        .filter(models.Q(is_staff=True) | models.Q(is_superuser=True))
        .values_list("pk", flat=True)
    )
    # Include inactive/expired memberships and disabled users. Losing the
    # last independent administrator never reopens platform provisioning.
    initialized = (
        memberships.objects.using(alias)
        .filter(role="tenant_admin")
        .exclude(user_id__in=legacy_ids)
        .values("tenant_id")
    )
    tenants.objects.using(alias).filter(
        pk__in=initialized, initial_administrator_created_at__isnull=True
    ).update(
        initial_administrator_created_at=timezone.now(),
    )
    for user_id in legacy_ids:
        platform.objects.using(alias).get_or_create(user_id=user_id)
    memberships.objects.using(alias).filter(user_id__in=legacy_ids).delete()
    users.objects.using(alias).filter(pk__in=legacy_ids).update(
        is_staff=False, is_superuser=False
    )


class Migration(migrations.Migration):
    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
        ("tenancy", "0003_tenantmembership_expires_at_and_more"),
    ]
    operations = [
        migrations.CreateModel(
            name="PlatformAdministrator",
            fields=[
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        primary_key=True,
                        related_name="ipms_platform_administrator",
                        serialize=False,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddField(
            model_name="tenant",
            name="initial_administrator_created_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        # A downlevel rollback deliberately cannot restore broad privilege.
        migrations.RunPython(
            separate_platform_principals, reverse_code=migrations.RunPython.noop
        ),
    ]
