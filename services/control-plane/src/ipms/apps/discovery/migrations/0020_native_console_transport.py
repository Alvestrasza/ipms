import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("discovery", "0019_hyperv_console_sessions"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.AddField(model_name="hypervconsolesession", name="browser_claim", field=models.UUIDField(blank=True, null=True)),
        migrations.AddField(model_name="hypervconsolesession", name="stream_generation", field=models.UUIDField(blank=True, null=True)),
        migrations.AddField(model_name="hypervconsolesession", name="owner", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="native_console_sessions", to=settings.AUTH_USER_MODEL)),
        migrations.AddField(model_name="hypervconsolesession", name="transport", field=models.CharField(choices=[("thumbnail", "Thumbnail"), ("vmconnect", "Native VMConnect")], default="thumbnail", max_length=16)),
    ]
