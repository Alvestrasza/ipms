# File Name: tests.py
# Version: v0.1.0 | Created: 2026-09-19 | Last Modified: 2026-09-20
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: HGS tenant isolation, reviewed plans, native exchange, reboot and receipt recovery tests.
import copy
import uuid
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.agent_pki import gateway
from ipms.apps.agent_pki.models import AgentEnrollment, AgentLifecycleJob
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant, TenantMembership, PlatformAdministrator
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from . import contract as c
from .models import HgsDeployment, HgsJob
from .services import hgs_exchange, withdraw_hgs_jobs

BASE = "/api/v1/hgs/"


class HgsTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="guardian", display_name="Guardian", purpose="hgs")
        self.user = get_user_model().objects.create_user("guardian-admin", password="synthetic-test-password")
        self.member = TenantMembership.objects.create(tenant=self.tenant, user=self.user, role="tenant_admin")
        self.fabric = Tenant.objects.create(slug="fabric", display_name="Fabric")
        self.fabric_user = get_user_model().objects.create_user("fabric-admin")
        TenantMembership.objects.create(tenant=self.fabric, user=self.fabric_user, role="tenant_admin")
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        self.agent, self.system = self.node("guardian01")

    def node(self, name, tenant=None):
        tenant = tenant or self.tenant
        agent = AgentEnrollment.objects.create(tenant=tenant, device_uri=f"urn:ipms:agent:{uuid.uuid4()}",
            display_name=name, platform="windows", status="active", last_heartbeat_at=timezone.now())
        system = WindowsServer.objects.create(tenant=tenant, source_id=agent.device_uri, inventory_source="agent",
            hostname=name, os_build="26100", operating_system="Windows Server 2025", operating_system_role="server",
            agent_version="0.2.49", discovered_at=timezone.now())
        return agent, system

    def payload(self, **changes):
        body = {"name": "Guardian deployment", "profile": "shielded", "attestation_mode": "tpm",
                "domain_name": "guardian.example.invalid", "service_name": "hgs", "node_ids": [str(self.system.id)],
                "feature_source": "D:\\sources\\sxs", "signing_thumbprint": "A" * 40,
                "encryption_thumbprint": "B" * 40, "dsrm_secret_ref": "dsrm", "join_secret_ref": "",
                "allow_reboot": True, "primary_server": ""}
        body.update(changes)
        return body

    def create(self, **changes):
        response = self.client.post(BASE + "deployments/", self.payload(**changes), format="json")
        self.assertEqual(response.status_code, 201, response.data)
        return response.data

    def action(self, plan, action, data=None):
        return self.client.post(BASE + f"deployments/{plan['id']}/{action}/", data or {}, format="json")

    def exchange(self, agent=None, mode="poll", **fields):
        agent = agent or self.agent
        envelope = {"type": "hgs", "device_uri": agent.device_uri, "mode": mode}
        if mode == "poll":
            envelope.update(agent_version="0.2.49", hgs_provider_version=1)
        envelope.update(fields)
        return hgs_exchange(agent, envelope)

    def observation(self, **changes):
        value = {field: False for field in c.BOOLEAN_OBSERVATIONS}
        value.update(is_server=True, os_build="26100", computer_name="guardian01", domain_name="WORKGROUP", domain_role=2,
            attestation_mode="none", boot_id="20260919090000.000000+000", signing_certificate_ready=True,
            encryption_certificate_ready=True, feature_source_ready=True, dsrm_secret_ready=True, join_secret_ready=True,
            mode_supported=True, offline_source_policy_ready=True)
        value.update(configured_service_name="", configured_signing_thumbprint="", configured_encryption_thumbprint="")
        value.update(changes)
        return value

    def claim(self, agent=None):
        job = self.exchange(agent)["hgs_job"]
        self.assertIsNotNone(job)
        self.assertEqual(self.exchange(agent, "claim", job_id=job["job_id"], plan_digest=job["plan_digest"])["hgs_job"], job)
        return job

    def report(self, job, observation=None, *, agent=None, status="succeeded", code="hgs_step_succeeded"):
        return self.exchange(agent, "result", job_id=job["job_id"], plan_digest=job["plan_digest"],
            result={"status": status, "result_code": code, "observation": observation if observation is not None else self.observation()})

    def ready(self, **changes):
        plan = self.create(**changes)
        self.assertEqual(self.action(plan, "inspect").status_code, 202)
        job = self.claim()
        self.report(job)
        plan = self.client.get(BASE + f"deployments/{plan['id']}/").data
        self.assertEqual(plan["status"], "ready", plan)
        return plan

    def execute(self, plan):
        response = self.action(plan, "execute", {"plan_digest": plan["plan_digest"], "confirm": True})
        self.assertEqual(response.status_code, 202, response.data)

    def test_one_appliance_both_profiles_and_no_implicit_jobs(self):
        overview = self.client.get(BASE)
        self.assertEqual(overview.status_code, 200)
        self.assertTrue(overview.data["single_appliance_supported"])
        self.assertEqual({p["id"] for p in overview.data["profiles"]}, {"vtpm", "shielded"})
        plan = self.create(profile="vtpm", attestation_mode="tpm")
        self.assertEqual(plan["status"], "draft")
        self.assertEqual(plan["jobs"], [])
        self.assertEqual(len(plan["steps"]), 6)
        self.assertEqual(HgsJob.objects.count(), 0)

    def test_hgs_tenant_cannot_perform_fabric_operations(self):
        for permission in (Permission.VIRTUAL_MACHINES_OPERATE, Permission.VIRTUAL_MACHINES_CONFIGURE,
                           Permission.SECURITY_GPO_IMPORTS_RUN, Permission.CONNECTORS_MANAGE):
            self.assertFalse(has_tenant_permission(self.user, self.tenant, permission))
        self.assertTrue(has_tenant_permission(self.user, self.tenant, Permission.AGENTS_MANAGE))
        self.assertTrue(has_tenant_permission(self.user, self.tenant, Permission.HGS_MANAGE))

    def test_fabric_tenant_does_not_expose_hgs_nodes_or_jobs(self):
        self.create()
        self.client.force_authenticate(self.fabric_user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.fabric.id))
        response = self.client.get(BASE)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["systems"], [])
        self.assertEqual(response.data["deployments"], [])
        self.assertEqual(self.client.post(BASE + "deployments/", self.payload(), format="json").status_code, 403)

    def test_identity_may_not_bridge_hgs_and_fabric_tenants(self):
        for user, tenant in ((self.user, self.fabric), (self.fabric_user, self.tenant)):
            with self.assertRaises(ValidationError):
                TenantMembership.objects.create(user=user, tenant=tenant, role="reader")

    def test_tenant_purpose_is_immutable_and_platform_creates_it(self):
        self.tenant.purpose = "infrastructure"
        with self.assertRaises(ValidationError):
            self.tenant.save()
        platform = get_user_model().objects.create_user("platform")
        PlatformAdministrator.objects.create(user=platform)
        self.client.force_authenticate(platform)
        response = self.client.post("/api/v1/platform/tenants/", {"slug": "hgs-second", "display_name": "Second HGS", "purpose": "hgs"}, format="json")
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data["purpose"], "hgs")
        self.assertEqual(self.client.get(BASE).status_code, 404)

    def test_reader_sees_plan_but_cannot_change_it(self):
        plan = self.create()
        self.member.role = "reader"
        self.member.save()
        self.assertEqual(self.client.get(BASE).status_code, 200)
        self.assertEqual(self.action(plan, "inspect").status_code, 403)

    def test_cross_tenant_node_and_plan_substitution_rejected(self):
        _, other = self.node("fabric-host", self.fabric)
        response = self.client.post(BASE + "deployments/", self.payload(node_ids=[str(other.id)]), format="json")
        self.assertEqual(response.status_code, 409)
        plan = self.create()
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.fabric.id))
        self.assertEqual(self.action(plan, "inspect").status_code, 404)

    def test_strict_plan_rejects_commands_secrets_mode_downgrade_and_remote_sources(self):
        bad = [dict(script="noop"), dict(dsrm_password="not-accepted"), dict(attestation_mode="host_key"),
               dict(feature_source="https://example.invalid/feature"), dict(feature_source="D:\\safe\\..\\other"),
               dict(feature_source="D:\\offline$sources"), dict(feature_source="D:\\offline;sources"),
               dict(feature_source="D:\\offline`sources"), dict(feature_source="D:\\offline..sources"),
               dict(primary_server="fe80::1%12"), dict(allow_reboot=1), dict(node_ids=[str(self.system.id)] * 2), dict(signing_thumbprint="x" * 40)]
        for changes in bad:
            with self.subTest(changes=list(changes)):
                response = self.client.post(BASE + "deployments/", self.payload(**changes), format="json")
                self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(HgsDeployment.objects.count(), 0)

    def test_mode_and_node_conflicts_do_not_reconfigure_existing_plan(self):
        self.create()
        self.assertEqual(self.client.post(BASE + "deployments/", self.payload(profile="vtpm", attestation_mode="host_key"), format="json").status_code, 409)
        self.assertEqual(self.client.post(BASE + "deployments/", self.payload(domain_name="other.example.invalid"), format="json").status_code, 409)

    def test_readiness_required_and_wrong_digest_cannot_execute(self):
        plan = self.create()
        self.assertEqual(self.action(plan, "execute", {"confirm": True, "plan_digest": plan["plan_digest"]}).status_code, 409)
        self.action(plan, "inspect")
        self.report(self.claim())
        self.assertEqual(self.action(plan, "execute", {"confirm": True, "plan_digest": "f" * 64}).status_code, 409)

    def test_readiness_fails_wrong_domain_missing_key_and_missing_source(self):
        plan = self.create()
        self.action(plan, "inspect")
        self.report(self.claim(), self.observation(domain_joined=True, domain_name="fabric.example.invalid",
                     signing_certificate_ready=False, feature_source_ready=False))
        record = HgsDeployment.objects.get(pk=plan["id"])
        self.assertEqual(record.status, "blocked")
        self.assertTrue({"different_domain_membership", "certificate_private_key_unavailable", "offline_feature_source_unavailable"} <= set(record.blockers))

    def test_readiness_expiry_rejects_execution(self):
        plan = self.ready()
        HgsDeployment.objects.get(pk=plan["id"]).nodes.update(observed_at=timezone.now() - timedelta(hours=1))
        self.assertEqual(self.action(plan, "execute", {"confirm": True, "plan_digest": plan["plan_digest"]}).status_code, 409)

    def test_one_node_provisioning_advances_only_after_verified_receipts(self):
        plan = self.ready()
        self.execute(plan)
        state = self.observation()
        last = None
        for operation in ("install_role", "reboot", "create_forest", "reboot", "initialize", "verify"):
            job = self.claim()
            self.assertEqual(job["operation"], operation)
            if operation == "install_role":
                state["role_installed"] = True
            if operation == "create_forest":
                state.update(domain_joined=True, domain_name="guardian.example.invalid", domain_role=5)
            if operation == "initialize":
                state.update(service_initialized=True, attestation_mode="tpm", key_access_verified=True, configured_service_name="hgs",
                             configured_signing_thumbprint="A" * 40, configured_encryption_thumbprint="B" * 40)
            if operation == "verify":
                state.update(service_healthy=True, key_access_verified=True)
            self.assertEqual(self.report(job, state), {"accepted": True})
            last = job
        record = HgsDeployment.objects.get(pk=plan["id"])
        self.assertEqual(record.status, "succeeded")
        self.assertIsNone(self.exchange()["hgs_job"])
        self.assertEqual(self.report(last, state), {"accepted": True})
        record.refresh_from_db()
        self.assertEqual(record.status, "succeeded")
        self.assertIsNone(record.authority_revoked_at)

    def test_additional_nodes_wait_for_primary_verification(self):
        extra, system = self.node("guardian02")
        plan = self.create(node_ids=[str(self.system.id), str(system.id)], primary_server="192.0.2.40", join_secret_ref="join")
        self.action(plan, "inspect")
        self.report(self.claim())
        self.report(self.claim(extra), self.observation(computer_name="guardian02"), agent=extra)
        self.execute(plan)
        self.assertEqual(self.claim()["operation"], "install_role")
        self.assertIsNone(self.exchange(extra)["hgs_job"])

    def test_reboot_receipt_requires_new_boot_before_advancing(self):
        plan = self.ready()
        self.execute(plan)
        self.report(self.claim(), self.observation(role_installed=True))
        job = self.claim()
        before = self.observation(role_installed=True, reboot_pending=True)
        self.report(job, before, status="reboot_required", code="hgs_reboot_required")
        self.assertEqual(HgsDeployment.objects.get(pk=plan["id"]).status, "waiting_for_reboot")
        self.assertEqual(self.exchange()["hgs_job"]["job_id"], job["job_id"])
        with self.assertRaises(ValidationError):
            self.report(job, self.observation(role_installed=True))
        self.report(job, self.observation(role_installed=True, boot_id="20260919100000.000000+000"))
        self.assertEqual(self.claim()["operation"], "create_forest")

    def test_cancel_accepts_late_receipt_but_never_queues_next_write(self):
        plan = self.ready()
        self.execute(plan)
        job = self.claim()
        self.assertEqual(self.action(plan, "cancel").status_code, 202)
        self.report(job, self.observation(role_installed=True))
        self.assertIsNone(self.exchange()["hgs_job"])
        self.assertEqual(HgsDeployment.objects.get(pk=plan["id"]).status, "reconciliation_required")

    def test_late_success_after_cancel_can_resume_only_after_fresh_explicit_resolution(self):
        plan = self.ready()
        self.execute(plan)
        job = self.claim()
        self.action(plan, "cancel")
        observed = self.observation(role_installed=True)
        self.report(job, observed)
        original = HgsJob.objects.get(pk=job["job_id"])
        self.assertEqual(original.status, "reconciliation_required")
        self.assertEqual(original.receipt["status"], "succeeded")
        self.assertFalse(self.client.get(BASE + f"deployments/{plan['id']}/").data["reconciliation"]["can_resolve"])
        self.action(plan, "reconcile")
        self.report(self.claim(), observed)
        state = self.client.get(BASE + f"deployments/{plan['id']}/").data["reconciliation"]
        self.assertTrue(state["can_resolve"])
        response = self.action(plan, "resolve", {"job_id": job["job_id"], "plan_digest": plan["plan_digest"],
            "observation_digest": state["observation_digest"], "confirm": True})
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(self.claim()["operation"], "reboot")
        original.refresh_from_db()
        self.assertEqual(original.receipt["status"], "succeeded")
        self.assertTrue(self.report(job, observed)["accepted"])

    def test_cancelled_running_inspection_settles_without_a_write_fence(self):
        plan = self.create()
        self.action(plan, "inspect")
        job = self.claim()
        self.action(plan, "cancel")
        self.report(job)
        record = HgsDeployment.objects.get(pk=plan["id"])
        self.assertEqual(record.status, "cancelled")
        self.assertIsNone(self.client.get(BASE + f"deployments/{plan['id']}/").data["reconciliation"])

    def test_withdrawal_does_not_revive_when_user_returns(self):
        plan = self.ready()
        self.execute(plan)
        withdraw_hgs_jobs(actor_id=self.user.id)
        self.assertIsNone(self.exchange()["hgs_job"])
        self.assertEqual(HgsDeployment.objects.get(pk=plan["id"]).status, "cancelled")

    def test_claim_rechecks_permissions_and_plan_drift(self):
        plan = self.ready()
        self.execute(plan)
        self.member.is_active = False
        self.member.save()
        self.assertIsNone(self.exchange()["hgs_job"])
        self.member.is_active = True
        self.member.save()
        self.assertIsNone(self.exchange()["hgs_job"])

    def test_expired_grant_accepts_late_receipt_without_advancing(self):
        plan = self.ready()
        self.execute(plan)
        job = self.claim()
        HgsJob.objects.filter(pk=job["job_id"]).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.report(job, self.observation(role_installed=True))
        self.assertIsNone(self.exchange()["hgs_job"])
        self.assertEqual(HgsDeployment.objects.get(pk=plan["id"]).status, "reconciliation_required")

    def test_wrong_agent_cannot_claim_or_report(self):
        plan = self.create()
        self.action(plan, "inspect")
        job = self.claim()
        other, _ = self.node("guardian02")
        for mode in ("claim", "result"):
            with self.assertRaises(ValidationError):
                self.exchange(other, mode, job_id=job["job_id"], plan_digest=job["plan_digest"],
                    **({"result": {"status": "succeeded", "result_code": "hgs_inspected", "observation": self.observation()}} if mode == "result" else {}))

    def test_unsolicited_extra_and_contradictory_evidence_are_rejected(self):
        plan = self.ready()
        self.execute(plan)
        job = self.claim()
        with self.assertRaises(ValidationError):
            self.report(job)  # No installed role: claimed success is not proof.
        evidence = self.observation(role_installed=True)
        evidence["private_key"] = "must-never-be-stored"
        with self.assertRaises(ValidationError):
            self.report(job, evidence)
        self.assertIsNone(HgsJob.objects.get(pk=job["job_id"]).receipt)

    def test_reconciliation_is_read_only_and_does_not_reapprove(self):
        plan = self.ready()
        self.execute(plan)
        job = self.claim()
        self.report(job, {}, status="reconciliation_required", code="hgs_reconciliation_required")
        self.assertEqual(self.action(plan, "reconcile").status_code, 202)
        inspected = self.claim()
        self.assertEqual(inspected["operation"], "inspect")
        self.report(inspected)
        self.assertEqual(HgsDeployment.objects.get(pk=plan["id"]).status, "reconciliation_required")
        self.assertIsNone(self.exchange()["hgs_job"])

    def test_lifecycle_work_blocks_hgs_dispatch(self):
        plan = self.create()
        self.action(plan, "inspect")
        AgentLifecycleJob.objects.create(tenant=self.tenant, enrollment=self.agent, action="update", requested_by=self.user.username)
        self.assertIsNone(self.exchange()["hgs_job"])

    def test_gateway_route_and_duplicate_key_rejection(self):
        path, _, _ = gateway._parse_http_request(b"POST /v1/hgs HTTP/1.1\r\nHost: gateway.example.invalid\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n")
        self.assertEqual(path, "/v1/hgs")
        with self.assertRaises(ValidationError):
            gateway._unique_management_json(b'{"type":"hgs","mode":"poll","mode":"claim"}')

    def test_unclaimed_failure_is_settled_without_write_authority(self):
        plan = self.create()
        self.action(plan, "inspect")
        job = self.exchange()["hgs_job"]
        self.report(job, {}, status="failed", code="hgs_provider_failed")
        self.assertEqual(HgsDeployment.objects.get(pk=plan["id"]).status, "blocked")
        self.assertEqual(self.report(job, {}, status="failed", code="hgs_provider_failed"), {"accepted": True})
        self.assertEqual(self.action(plan, "inspect").status_code, 202)

    def test_cancel_between_offer_and_claim_accepts_nonexecution_receipt(self):
        plan = self.ready()
        self.execute(plan)
        job = self.exchange()["hgs_job"]
        self.action(plan, "cancel")
        self.assertIsNone(self.exchange(mode="claim", job_id=job["job_id"], plan_digest=job["plan_digest"])["hgs_job"])
        self.assertEqual(self.report(job, {}, status="failed", code="hgs_authority_lost"), {"accepted": True})
        self.assertEqual(HgsJob.objects.get(pk=job["job_id"]).status, "cancelled")
        self.assertIsNone(self.exchange()["hgs_job"])

    def test_new_administrator_can_inspect_revoked_plan_without_reviving_it(self):
        plan = self.ready()
        self.execute(plan)
        job = self.claim()
        self.report(job, {}, status="reconciliation_required", code="hgs_reconciliation_required")
        withdraw_hgs_jobs(actor_id=self.user.id)
        self.member.is_active = False
        self.member.save()
        user = get_user_model().objects.create_user("new-guardian-admin")
        TenantMembership.objects.create(tenant=self.tenant, user=user, role="tenant_admin")
        self.client.force_authenticate(user)
        response = self.action(plan, "reconcile")
        self.assertEqual(response.status_code, 202, response.data)
        inspection = self.claim()
        self.assertEqual(inspection["operation"], "inspect")
        self.report(inspection, self.observation(role_installed=True))
        self.assertIsNone(self.exchange()["hgs_job"])
        self.assertIsNotNone(HgsDeployment.objects.get(pk=plan["id"]).authority_revoked_at)

    def test_resolution_requires_observation_digest_then_skips_proven_step(self):
        plan = self.ready()
        self.execute(plan)
        interrupted = self.claim()
        self.report(interrupted, {}, status="reconciliation_required", code="hgs_reconciliation_required")
        self.action(plan, "reconcile")
        self.report(self.claim(), self.observation(role_installed=True))
        view = self.client.get(BASE + f"deployments/{plan['id']}/").data
        state = view["reconciliation"]
        self.assertTrue(state["can_resolve"])
        payload = {"job_id": interrupted["job_id"], "plan_digest": plan["plan_digest"], "observation_digest": "f" * 64, "confirm": True}
        self.assertEqual(self.action(plan, "resolve", payload).status_code, 409)
        payload["observation_digest"] = state["observation_digest"]
        self.assertEqual(self.action(plan, "resolve", payload).status_code, 202)
        offered = self.exchange()
        self.assertEqual(offered["hgs_job"]["operation"], "reboot")
        self.assertEqual(offered["hgs_reconciliation_release"], {"job_id": interrupted["job_id"], "plan_digest": plan["plan_digest"]})
        record = HgsJob.objects.get(pk=interrupted["job_id"])
        self.assertEqual(record.receipt["status"], "reconciliation_required")
        self.assertEqual(record.reconciliation_release["observation_digest"], state["observation_digest"])

    def test_verify_rejects_other_configured_certificates(self):
        cfg = {**self.payload(), "node_role": "primary"}
        observed = self.observation(service_initialized=True, attestation_mode="tpm", service_healthy=True,
            key_access_verified=True, configured_service_name="hgs", configured_signing_thumbprint="C" * 40,
            configured_encryption_thumbprint="B" * 40)
        self.assertFalse(c.postcondition("verify", cfg, observed))
        self.assertIn("hgs_configuration_mismatch", c.readiness_blockers(cfg, observed, hostname="guardian01", role="primary"))

    def test_initialize_requires_configured_domain_and_service_key_access(self):
        cfg = self.payload()
        observed = self.observation(role_installed=True, domain_joined=True, domain_role=5,
            domain_name=cfg["domain_name"], service_initialized=True, attestation_mode="tpm",
            configured_service_name="hgs", configured_signing_thumbprint="A" * 40,
            configured_encryption_thumbprint="B" * 40, key_access_verified=True)
        self.assertTrue(c.postcondition("initialize", cfg, observed))
        for field, value in (("reboot_pending", True), ("key_access_verified", False), ("role_installed", False), ("domain_name", "other.invalid"), ("domain_role", 2)):
            with self.subTest(field=field):
                self.assertFalse(c.postcondition("initialize", cfg, {**observed, field: value}))

    def test_reboot_resolution_without_preboot_evidence_is_rejected(self):
        plan = self.ready()
        self.execute(plan)
        self.report(self.claim(), self.observation(role_installed=True))
        interrupted = self.claim()
        self.report(interrupted, {}, status="reconciliation_required", code="hgs_reconciliation_required")
        self.action(plan, "reconcile")
        self.report(self.claim(), self.observation(role_installed=True, boot_id="20260920090000.000000+000"))
        state = self.client.get(BASE + f"deployments/{plan['id']}/").data["reconciliation"]
        self.assertFalse(state["can_resolve"])

    def test_reboot_reconciliation_preserves_first_boot_baseline(self):
        plan = self.ready()
        self.execute(plan)
        self.report(self.claim(), self.observation(role_installed=True))
        job = self.claim()
        self.report(job, self.observation(role_installed=True, reboot_pending=True),
            status="reboot_required", code="hgs_reboot_required")
        later = self.observation(role_installed=True, reboot_pending=True, boot_id="20260920100000.000000+000")
        self.report(job, later, status="reconciliation_required", code="hgs_reconciliation_required")
        self.assertEqual(HgsJob.objects.get(pk=job["job_id"]).preboot_id, self.observation()["boot_id"])
        self.action(plan, "reconcile")
        self.report(self.claim(), {**later, "reboot_pending": False})
        state = self.client.get(BASE + f"deployments/{plan['id']}/").data["reconciliation"]
        self.assertTrue(state["can_resolve"])

    def test_existing_same_domain_cannot_be_approved_as_fresh_node(self):
        plan = self.create()
        self.action(plan, "inspect")
        self.report(self.claim(), self.observation(domain_joined=True, domain_name=plan["domain_name"]))
        record = HgsDeployment.objects.get(pk=plan["id"])
        self.assertEqual(record.status, "blocked")
        self.assertIn("fresh_workgroup_node_required", record.blockers)
