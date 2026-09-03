from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("discovery", "0011_windowsserverrole"),
    ]

    operations = [
        migrations.AddField(
            model_name="windowsserver",
            name="installed_roles_features_error",
            field=models.CharField(blank=True, max_length=64),
        ),
    ]
