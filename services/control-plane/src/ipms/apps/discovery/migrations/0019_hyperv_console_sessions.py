import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0007_agent_enrollment_platform"),
        ("discovery", "0018_alter_hypervvirtualmachineactionjob_action"),
    ]

    operations = [
        migrations.CreateModel(
            name="HyperVConsoleSession",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("vm_source_id", models.CharField(max_length=64)),
                ("vm_name", models.CharField(max_length=255)),
                ("requested_by", models.CharField(max_length=255)),
                ("status", models.CharField(choices=[("requested", "Requested"), ("active", "Active"), ("closed", "Closed"), ("failed", "Failed"), ("expired", "Expired")], default="requested", max_length=16)),
                ("lease_expires_at", models.DateTimeField()),
                ("frame_sequence", models.PositiveBigIntegerField(default=0)),
                ("frame_width", models.PositiveSmallIntegerField(default=0)),
                ("frame_height", models.PositiveSmallIntegerField(default=0)),
                ("frame_png", models.BinaryField(blank=True, default=bytes)),
                ("failure_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("connected_at", models.DateTimeField(blank=True, null=True)),
                ("last_activity_at", models.DateTimeField()),
                ("last_agent_contact_at", models.DateTimeField(blank=True, null=True)),
                ("closed_at", models.DateTimeField(blank=True, null=True)),
                ("enrollment", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="hyperv_console_sessions", to="agent_pki.agentenrollment")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="hyperv_console_sessions", to="tenancy.tenant")),
                ("virtual_machine", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="console_sessions", to="discovery.hypervvirtualmachine")),
            ],
            options={
                "ordering": ("-created_at",),
                "indexes": [models.Index(fields=["tenant", "-created_at"], name="hyperv_console_tenant_time"), models.Index(fields=["enrollment", "status"], name="hyperv_console_agent_state")],
                "constraints": [models.UniqueConstraint(condition=models.Q(("status__in", ("requested", "active"))), fields=("tenant", "vm_source_id"), name="unique_active_hyperv_console")],
            },
        ),
        migrations.CreateModel(
            name="HyperVConsoleInputEvent",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("event_type", models.CharField(choices=[("key", "Key"), ("mouse_move", "Mouse move"), ("mouse_button", "Mouse button"), ("mouse_wheel", "Mouse wheel"), ("secure_attention", "Secure attention")], max_length=24)),
                ("payload", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("session", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="input_events", to="discovery.hypervconsolesession")),
            ],
            options={
                "ordering": ("created_at", "id"),
                "indexes": [models.Index(fields=["session", "delivered_at", "created_at"], name="hyperv_console_input_queue")],
            },
        ),
    ]
