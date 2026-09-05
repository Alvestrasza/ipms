from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("agent_pki", "0010_serviceaccount_and_more")]
    operations = [
        migrations.AddField(
            model_name="agentlifecyclejob",
            name="authority_revoked_at",
            field=models.DateTimeField(blank=True, null=True),
        )
    ]
