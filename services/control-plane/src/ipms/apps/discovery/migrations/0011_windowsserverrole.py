import uuid

import django.db.models.deletion
from django.db import migrations, models


def backfill_installed_roles(apps, schema_editor):
    WindowsServer = apps.get_model("discovery", "WindowsServer")
    WindowsServerRole = apps.get_model("discovery", "WindowsServerRole")
    pending = []
    for server in WindowsServer.objects.only("id", "installed_roles_features").iterator():
        features = server.installed_roles_features
        if not isinstance(features, list):
            continue
        for feature in features:
            if not isinstance(feature, dict) or feature.get("type") != "role":
                continue
            name = feature.get("name")
            display_name = feature.get("display_name")
            if not isinstance(name, str) or not isinstance(display_name, str):
                continue
            if not name or not display_name:
                continue
            pending.append(
                WindowsServerRole(
                    id=uuid.uuid4(),
                    server_id=server.id,
                    name=name[:255],
                    display_name=display_name[:255],
                )
            )
            if len(pending) >= 1000:
                WindowsServerRole.objects.bulk_create(pending, ignore_conflicts=True)
                pending.clear()
    if pending:
        WindowsServerRole.objects.bulk_create(pending, ignore_conflicts=True)


class Migration(migrations.Migration):
    dependencies = [
        ("discovery", "0010_windowsserver_installed_roles_features"),
    ]

    operations = [
        migrations.CreateModel(
            name="WindowsServerRole",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                ("display_name", models.CharField(max_length=255)),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="installed_roles",
                        to="discovery.windowsserver",
                    ),
                ),
            ],
            options={
                "ordering": ("display_name", "name"),
                "indexes": [
                    models.Index(
                        fields=["name", "server"],
                        name="windows_role_server_idx",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("server", "name"),
                        name="unique_windows_server_role",
                    )
                ],
            },
        ),
        migrations.RunPython(
            backfill_installed_roles,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
