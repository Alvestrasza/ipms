from django.db import migrations, models


def classify_existing_windows_systems(apps, schema_editor):
    WindowsServer = apps.get_model("discovery", "WindowsServer")
    for system in WindowsServer.objects.only(
        "id", "operating_system", "installed_roles_features"
    ).iterator():
        operating_system = (system.operating_system or "").casefold()
        installed = system.installed_roles_features
        role_names = {
            str(item.get("name", "")).casefold()
            for item in installed
            if isinstance(item, dict) and item.get("type") == "role"
        } if isinstance(installed, list) else set()
        if "windows" in operating_system and "server" not in operating_system:
            role = "client"
        elif {
            "ad-domain-services",
            "win32-server-feature-1",
        } & role_names:
            role = "domain-controller"
        elif "windows" in operating_system:
            role = "server"
        else:
            role = "unknown"

        family = ""
        if role == "client":
            if "windows 11" in operating_system:
                family = (
                    "windows-11-ltsc"
                    if "ltsc" in operating_system
                    else "windows-11"
                )
            elif "windows 10" in operating_system:
                family = (
                    "windows-10-ltsc"
                    if "ltsc" in operating_system
                    else "windows-10"
                )
            else:
                family = "windows-client"
        WindowsServer.objects.filter(id=system.id).update(
            operating_system_role=role,
            operating_system_family=family,
        )


class Migration(migrations.Migration):
    dependencies = [("discovery", "0012_windowsserver_installed_roles_features_error")]

    operations = [
        migrations.AlterField(
            model_name="windowsserver",
            name="installed_roles_features_status",
            field=models.CharField(
                choices=[
                    ("not-reported", "Not reported"),
                    ("collected", "Collected"),
                    ("unavailable", "Unavailable"),
                    ("not-applicable", "Not applicable"),
                ],
                default="not-reported",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="windowsserver",
            name="operating_system_family",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="windowsserver",
            name="operating_system_role",
            field=models.CharField(
                choices=[
                    ("client", "Client"),
                    ("server", "Server"),
                    ("domain-controller", "Domain controller"),
                    ("unknown", "Unknown"),
                ],
                default="server",
                max_length=24,
            ),
        ),
        migrations.RunPython(
            classify_existing_windows_systems,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AddIndex(
            model_name="windowsserver",
            index=models.Index(
                fields=["tenant", "operating_system_role", "server_type"],
                name="windows_tenant_role_idx",
            ),
        ),
    ]
