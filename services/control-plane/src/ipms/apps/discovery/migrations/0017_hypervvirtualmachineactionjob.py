import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("agent_pki", "0007_agent_enrollment_platform"),
        ("discovery", "0016_managed_infrastructure_devices"),
    ]

    operations = [
        migrations.CreateModel(
            name="HyperVVirtualMachineActionJob",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("vm_source_id", models.CharField(max_length=64)),
                ("vm_name", models.CharField(max_length=255)),
                ("action", models.CharField(choices=[("start", "Start"), ("stop", "Stop"), ("pause", "Pause"), ("resume", "Resume")], max_length=16)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("delivered", "Delivered"), ("running", "Running"), ("succeeded", "Succeeded"), ("failed", "Failed"), ("cancelled", "Cancelled")], default="queued", max_length=16)),
                ("requested_by", models.CharField(max_length=255)),
                ("result_code", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("enrollment", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="hyperv_action_jobs", to="agent_pki.agentenrollment")),
                ("tenant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="hyperv_action_jobs", to="tenancy.tenant")),
                ("virtual_machine", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="action_jobs", to="discovery.hypervvirtualmachine")),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.AddIndex(model_name="hypervvirtualmachineactionjob", index=models.Index(fields=["tenant", "-created_at"], name="hyperv_action_tenant_time")),
        migrations.AddIndex(model_name="hypervvirtualmachineactionjob", index=models.Index(fields=["enrollment", "status"], name="hyperv_action_agent_state")),
        migrations.AddConstraint(model_name="hypervvirtualmachineactionjob", constraint=models.UniqueConstraint(condition=models.Q(("status__in", ("queued", "delivered", "running"))), fields=("enrollment", "vm_source_id"), name="unique_active_hyperv_vm_action")),
    ]
