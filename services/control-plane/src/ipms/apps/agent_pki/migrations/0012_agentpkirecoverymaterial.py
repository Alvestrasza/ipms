# File Name: 0012_agentpkirecoverymaterial.py
# Version: v0.2.76 | Created: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Stage encrypted Agent Root recovery material until custody is confirmed.

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agent_pki", "0011_lifecycle_authority_withdrawal")]

    operations = [
        migrations.AddField(
            model_name="agentpkipolicy",
            name="gateway_last_verification_error",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="agentpkipolicy",
            name="gateway_last_verified_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="agentpkipolicy",
            name="gateway_last_verified_fingerprint_sha256",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.CreateModel(
            name="AgentPkiRecoveryMaterial",
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
                ("bundle_sha256", models.CharField(max_length=64)),
                ("nonce", models.BinaryField()),
                ("ciphertext", models.BinaryField()),
                ("downloaded_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "policy",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="recovery_material",
                        to="agent_pki.agentpkipolicy",
                    ),
                ),
                (
                    "tenant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="agent_pki_recovery_material",
                        to="tenancy.tenant",
                    ),
                ),
            ],
        )
    ]
