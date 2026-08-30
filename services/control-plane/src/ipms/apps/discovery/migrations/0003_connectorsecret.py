import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("discovery", "0002_connectorendpoint_physicalsystem")]

    operations = [
        migrations.CreateModel(
            name="ConnectorSecret",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("nonce", models.BinaryField()),
                ("ciphertext", models.BinaryField()),
                ("key_version", models.PositiveSmallIntegerField(default=1)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="connector_secrets", to="tenancy.tenant")),
            ],
        ),
    ]
