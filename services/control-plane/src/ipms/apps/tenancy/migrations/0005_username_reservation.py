import unicodedata

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def reserve_existing_names(apps, schema_editor):
    users = apps.get_model(settings.AUTH_USER_MODEL)
    reservations = apps.get_model("tenancy", "UsernameReservation")
    alias = schema_editor.connection.alias
    seen = set()
    rows = []
    for user_id, username in users.objects.using(alias).values_list("pk", "username"):
        normalized = unicodedata.normalize("NFKC", username).casefold()
        if normalized in seen:
            raise RuntimeError(
                "Normalized username conflicts must be resolved before migration."
            )
        seen.add(normalized)
        rows.append(reservations(normalized_username=normalized, user_id=user_id))
    reservations.objects.using(alias).bulk_create(rows)


class Migration(migrations.Migration):
    dependencies = [
        ("tenancy", "0004_platformadministrator_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="UsernameReservation",
            fields=[
                (
                    "normalized_username",
                    models.CharField(max_length=450, primary_key=True, serialize=False),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="ipms_username_reservations",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        # Removing the reservation ledger would silently reopen retired names.
        migrations.RunPython(reserve_existing_names),
    ]
