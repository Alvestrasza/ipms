# File Name: test_gpo_jobs.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Native pilot authority, immutable artifacts, retries and ambiguous write fences.
import asyncio
import hashlib
import json
import os
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from ipms.apps.agent_pki import gateway
from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.agent_pki.test_console_transport import ConsoleWriter, request as wire_request
from ipms.apps.audit.models import AuditEvent
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import TenantMembership
from ipms.apps.tenancy.operations import apply_tenant_status_change, withdraw_identity_operations
from .gpo_content import COMPONENTS, PROFILE_COMPONENTS
from .gpo_jobs import artifact_bytes, digest, security_gpo_exchange
from .models import BaselineAssessment, DomainSecuritySettings, GpoExecutorReport, GpoImportJob
from . import test_domains

SERVER = 'microsoft-windows-server-2025'
URL = test_domains.URL
DOMAIN_GUID = 'e99d4445-1d3b-4a30-92ca-77c04e725eab'
PILOT_GUID = 'c1d8698d-50cc-4d43-b6fb-10c8e078b846'


class GpoJobTests(TestCase):
    draft = test_domains.DomainSettingsTests.draft
    create = test_domains.DomainSettingsTests.create
    # Keep these tests independent from vendor cache availability. The actual
    # binary integrity boundary is covered below and by the package importer.
    def setUp(self):
        test_domains.DomainSettingsTests.setUp(self)
        self.artifacts = patch('ipms.apps.security.gpo_jobs.artifact_bytes', return_value=b'synthetic-pinned-content')
        self.artifacts.start()
        self.addCleanup(self.artifacts.stop)
        self.config = self.create().data
        self.import_url = URL + self.config['id'] + '/gpo-imports/'
        self.agent = AgentEnrollment.objects.create(
            tenant=self.tenant, device_uri=f'urn:ipms:agent:{uuid.uuid4()}', display_name='pilot-dc',
            platform='windows', status='active', last_heartbeat_at=timezone.now(),
            certificate_fingerprint_sha256='a' * 64,
            certificate_not_before=timezone.now() - timedelta(days=1),
            certificate_not_after=timezone.now() + timedelta(days=1),
        )
        self.system = WindowsServer.objects.create(
            tenant=self.tenant, source_id=self.agent.device_uri, inventory_source='agent',
            hostname='pilot-dc', fqdn='pilot-dc.example.invalid', domain_name='example.invalid',
            agent_version='0.2.32', operating_system_role='domain-controller',
            operating_system='Microsoft Windows Server 2025 Standard', os_build='26100',
            discovered_at=timezone.now(),
        )
        self.report = {'schema': 1, 'domain_dns_name': 'example.invalid', 'domain_guid': DOMAIN_GUID,
                       'forest_dns_name': 'example.invalid', 'dc_fqdn': self.system.fqdn,
                       'role': 'writable-domain-controller', 'gpmc_available': True,
                       'result_code': 'ready_for_approval'}
        self.poll()
        backup = next(item for item in PROFILE_COMPONENTS[(SERVER, 'server')]
                      if COMPONENTS[(SERVER, item)]['scope'] == 'machine')
        self.selection = {'revision': 1, 'system_id': str(self.system.id), 'baseline_id': SERVER,
                          'backup_id': backup, 'tier': '1', 'target': 'ALL', 'version': '1.0.0',
                          'idempotency_key': str(uuid.uuid4())}

    def envelope(self, action='poll', **values):
        return {'type': 'security_gpo', 'schema_version': '1', 'device_uri': self.agent.device_uri,
                'correlation_id': 'synthetic-gpo', 'action': action, **values}

    def poll(self, **changes):
        return security_gpo_exchange(self.agent, self.envelope(agent_version='0.2.32', executor={**self.report, **changes}))['gpo_job']

    def queue(self, **changes):
        response = self.client.post(self.import_url, {**self.selection, **changes}, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        return response.data['approval_document']

    def exchange(self, job, action, **values):
        return security_gpo_exchange(self.agent, self.envelope(action, job_id=job['job_id'], input_digest=job['input_digest'], **values))

    def result(self, job, status='failed', code='gpo_provider_failed', guid=None, evidence=None):
        return self.exchange(job, 'result', status=status, result_code=code, gpo_guid=guid, evidence=evidence)

    def staged_evidence(self):
        return {'computer_enabled': False, 'user_enabled': False, 'unlinked': True,
                'domain_dns_name': 'example.invalid', 'domain_guid': DOMAIN_GUID, 'dc_fqdn': self.system.fqdn}

    def test_observation_does_not_create_a_job_and_only_eligible_dc_is_selectable(self):
        data = self.client.get(self.import_url).data
        self.assertEqual(data['results'], [])
        self.assertTrue(data['executors'][0]['eligible'])
        self.assertFalse(GpoImportJob.objects.exists())
        self.poll(role='read-only-domain-controller', result_code='not_writable_domain_controller')
        self.assertFalse(self.client.get(self.import_url).data['executors'][0]['eligible'])
        self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 409)

    def test_queue_pins_exact_assignment_and_retries_do_not_duplicate_it(self):
        job = self.queue()
        self.assertEqual(job, self.queue())
        self.assertEqual(job, self.poll())
        self.assertEqual(GpoImportJob.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action='security.gpo_import_requested').count(), 1)
        self.assertEqual(job['input_digest'], digest({key: value for key, value in job.items() if key != 'input_digest'}))
        self.assertEqual(job['operation'], 'create_unlinked_pilot')
        self.assertEqual(job['domain_guid'], DOMAIN_GUID)
        self.assertIn('-Pilot-', job['pilot_display_name'])
        self.assertNotIn('tier_ous', job)
        self.assertFalse(BaselineAssessment.objects.exists())
        conflict = {**self.selection, 'target': 'DIFFERENT'}
        self.assertEqual(self.client.post(self.import_url, conflict, format='json').status_code, 409)

    def test_only_one_active_job_per_domain_and_pilot_names_cannot_be_reused(self):
        job = self.queue()
        second = {**self.selection, 'idempotency_key': str(uuid.uuid4()), 'version': '1.0.1'}
        self.assertEqual(self.client.post(self.import_url, second, format='json').status_code, 409)
        self.result(job)
        self.assertEqual(GpoImportJob.objects.get().status, 'failed')
        same_name = {**self.selection, 'idempotency_key': str(uuid.uuid4())}
        self.assertEqual(self.client.post(self.import_url, same_name, format='json').status_code, 409)
        self.assertEqual(self.client.post(self.import_url, second, format='json').status_code, 202)

    def test_import_requires_admin_fresh_revision_and_fresh_executor(self):
        for role in ('reader', 'operator', 'approver', 'auditor'):
            self.membership.role = role
            self.membership.save()
            self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 403)
        self.membership.role = 'tenant_admin'
        self.membership.save()
        self.assertEqual(self.client.post(self.import_url, {**self.selection, 'revision': 2}, format='json').status_code, 409)
        for model, changes in ((AgentEnrollment, {'last_heartbeat_at': timezone.now() - timedelta(minutes=6)}),
                               (WindowsServer, {'agent_version': '0.2.31'}),
                               (GpoExecutorReport, {'gpmc_available': False})):
            old = model.objects.get()
            model.objects.update(**changes)
            self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 409)
            old.save()
        self.assertFalse(GpoImportJob.objects.exists())

    def test_strict_import_selection_rejects_unsafe_values_without_internal_errors(self):
        for changes in ({'command': 'anything'}, {'target': '\ud800'}, {'backup_id': '../backup'},
                        {'target': 'ALL/../../'}, {'tier': 'A'}, {'revision': True}, {'baseline_id': []}):
            with self.subTest(changes=changes):
                self.assertEqual(self.client.post(self.import_url, json.dumps({**self.selection, **changes}), content_type='application/json').status_code, 400)
        self.assertFalse(GpoImportJob.objects.exists())

    def test_missing_artifact_and_foreign_executor_cannot_queue(self):
        with patch('ipms.apps.security.gpo_jobs.artifact_bytes', side_effect=ValidationError('unavailable')):
            self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 409)
        WindowsServer.objects.filter(pk=self.system.id).update(tenant=self.other)
        self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 409)

    def test_approval_pending_then_single_claim_and_idempotent_staged_receipt(self):
        job = self.queue()
        self.result(job, 'awaiting_local_approval', 'gpo_local_approval_required')
        self.result(job, 'awaiting_local_approval', 'gpo_local_approval_required')
        self.assertEqual(AuditEvent.objects.filter(action='security.gpo_import_awaiting_approval').count(), 1)
        with self.assertRaises(ValidationError):
            self.result(job, 'staged', 'gpo_staged_unlinked', PILOT_GUID, self.staged_evidence())
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'execute')
        observed = self.exchange(job, 'claim')['gpo_claim']
        self.assertEqual((observed['mode'], observed['authorized']), ('observe', False))
        self.assertIsNone(self.poll())
        self.result(job, 'staged', 'gpo_staged_unlinked', PILOT_GUID, self.staged_evidence())
        self.result(job, 'staged', 'gpo_staged_unlinked', PILOT_GUID, self.staged_evidence())
        row = GpoImportJob.objects.get()
        self.assertEqual((row.status, row.gpo_guid), ('staged', PILOT_GUID))
        self.assertEqual(AuditEvent.objects.filter(action='security.gpo_import_result').count(), 1)
        self.assertFalse(BaselineAssessment.objects.exists())
        with self.assertRaises(ValidationError):
            self.result(job)

    def test_default_guids_enabled_linked_or_falsely_typed_receipts_are_rejected(self):
        job = self.queue()
        self.exchange(job, 'claim')
        for guid, evidence in [
            ('31b2f340-016d-11d2-945f-00c04fb984f9', self.staged_evidence()),
            ('6ac1786c-016f-11d2-945f-00c04fb984f9', self.staged_evidence()),
            (PILOT_GUID, {**self.staged_evidence(), 'computer_enabled': True}),
            (PILOT_GUID, {**self.staged_evidence(), 'unlinked': False}),
            (PILOT_GUID, {**self.staged_evidence(), 'user_enabled': 0}),
            (PILOT_GUID, {**self.staged_evidence(), 'domain_guid': str(uuid.uuid4())}),
        ]:
            with self.subTest(guid=guid, evidence=evidence), self.assertRaises(ValidationError):
                self.result(job, 'staged', 'gpo_staged_unlinked', guid, evidence)
        self.assertEqual(GpoImportJob.objects.get().status, 'running')

    def test_expired_unclaimed_journal_can_acknowledge_failure_but_never_claim(self):
        job = self.queue()
        GpoImportJob.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(self.poll())
        self.assertEqual(GpoImportJob.objects.get().status, 'expired')
        self.result(job, code='gpo_job_expired')
        self.result(job, code='gpo_job_expired')
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')
        self.assertEqual(GpoImportJob.objects.get().status, 'expired')

    def test_ambiguous_claimed_failure_or_expiry_holds_the_domain_fence(self):
        job = self.queue()
        self.exchange(job, 'claim')
        self.result(job, code='gpo_worker_timeout')
        self.assertEqual(GpoImportJob.objects.get().status, 'reconciliation_required')
        GpoImportJob.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'reconcile')
        self.assertEqual(self.client.post(self.import_url, {**self.selection, 'idempotency_key': str(uuid.uuid4()), 'version': '1.0.1'}, format='json').status_code, 409)
        # A late exact success receipt can resolve a lost reply, even after its
        # authority expired. It describes the already granted action only.
        self.result(job, 'staged', 'gpo_staged_unlinked', PILOT_GUID, self.staged_evidence())
        self.assertEqual(GpoImportJob.objects.get().status, 'staged')

    def test_settings_revision_or_requester_revocation_cancels_unclaimed_authority(self):
        job = self.queue()
        DomainSecuritySettings.objects.filter(pk=self.config['id']).update(revision=2)
        claim = self.exchange(job, 'claim')['gpo_claim']
        self.assertEqual((claim['authorized'], claim['mode']), (False, 'cancelled'))
        self.result(job, code='gpo_authority_expired')
        self.assertEqual(GpoImportJob.objects.get().error_code, 'scope_changed')
        DomainSecuritySettings.objects.filter(pk=self.config['id']).update(revision=1)
        next_job = self.queue(idempotency_key=str(uuid.uuid4()), version='1.0.1')
        self.membership.role = 'reader'
        self.membership.save()
        self.assertFalse(self.exchange(next_job, 'claim')['gpo_claim']['authorized'])

    def test_changed_executor_identity_cannot_receive_new_write_grant(self):
        job = self.queue()
        self.assertIsNone(self.poll(domain_guid=str(uuid.uuid4())))
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')
        self.assertEqual(GpoImportJob.objects.get().status, 'failed')

    def test_prepared_lookup_withdraws_changed_settings_before_artifact_fetch(self):
        job = self.queue()
        DomainSecuritySettings.objects.filter(pk=self.config['id']).update(revision=2)
        response = self.exchange(job, 'lookup', agent_version='0.2.32', executor=self.report)
        self.assertIsNone(response['gpo_job'])
        self.assertEqual(GpoImportJob.objects.get().status, 'failed')
        self.result(job, code='gpo_authority_expired')

    def test_reconciliation_cannot_retarget_the_recorded_created_guid(self):
        job = self.queue()
        self.exchange(job, 'claim')
        self.result(job, 'requires_reconciliation', 'gpo_verification_failed', PILOT_GUID)
        with self.assertRaises(ValidationError):
            self.result(job, 'staged', 'gpo_staged_unlinked', str(uuid.uuid4()), self.staged_evidence())
        self.result(job, 'staged', 'gpo_staged_unlinked', PILOT_GUID, self.staged_evidence())
        self.assertEqual(GpoImportJob.objects.get().gpo_guid, PILOT_GUID)

    def test_enrollment_tenant_and_input_digest_must_match(self):
        job = self.queue()
        for changes in ({'job_id': str(uuid.uuid4())}, {'input_digest': 'b' * 64},
                        {'device_uri': 'urn:ipms:agent:other'}):
            document = self.envelope('claim', job_id=job['job_id'], input_digest=job['input_digest'])
            with self.assertRaises(ValidationError):
                security_gpo_exchange(self.agent, {**document, **changes})
        other_agent = AgentEnrollment.objects.create(tenant=self.other, platform='windows', status='active', device_uri=f'urn:ipms:agent:{uuid.uuid4()}')
        with self.assertRaises(ValidationError):
            security_gpo_exchange(other_agent, self.envelope('claim', device_uri=other_agent.device_uri, job_id=job['job_id'], input_digest=job['input_digest']))

    def test_artifact_uses_separate_authenticated_route_and_exact_scope(self):
        job = self.queue()
        request = self.envelope('artifact', job_id=job['job_id'], input_digest=job['input_digest'])
        with self.assertRaises(ValidationError):
            security_gpo_exchange(self.agent, request)
        content, content_digest = security_gpo_exchange(self.agent, request, artifact=True)
        self.assertEqual(content, b'synthetic-pinned-content')
        self.assertEqual(content_digest, job['artifact_sha256'])
        self.assertEqual(GpoImportJob.objects.get().status, 'queued')
        GpoExecutorReport.objects.update(observed_at=timezone.now() - timedelta(minutes=6))
        with self.assertRaises(ValidationError):
            security_gpo_exchange(self.agent, request, artifact=True)

    def test_malformed_reports_and_receipts_are_bounded_rejections(self):
        for changes in ({'result_code': []}, {'result_code': {}}, {'role': []}, {'schema': True},
                        {'gpmc_available': 1}, {'domain_guid': []}, {'dc_fqdn': '\ud800'}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.poll(**changes)
        job = self.queue()
        for value in ([], {}, None, 1):
            with self.subTest(code=value), self.assertRaises(ValidationError):
                self.result(job, code=value)
        for value in ([], {}, None):
            with self.subTest(status=value), self.assertRaises(ValidationError):
                self.result(job, status=value)

    def test_tenant_reactivation_and_password_reset_cannot_revive_previous_jobs(self):
        job = self.queue()
        self.tenant.status = 'suspended'
        self.tenant.save()
        apply_tenant_status_change(self.tenant, 'active', self.user.username)
        self.tenant.status = 'active'
        self.tenant.save()
        apply_tenant_status_change(self.tenant, 'suspended', self.user.username)
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')
        next_job = self.queue(idempotency_key=str(uuid.uuid4()), version='1.0.1')
        with transaction.atomic():
            withdraw_identity_operations(self.user, reason='password_reset')
        self.assertEqual(self.exchange(next_job, 'claim')['gpo_claim']['mode'], 'cancelled')

    def test_membership_downgrade_and_reactivation_require_new_approval(self):
        job = self.queue()
        second_admin = get_user_model().objects.create_user(username='second-domain-admin', password='test')
        TenantMembership.objects.create(tenant=self.tenant, user=second_admin, role='tenant_admin')
        self.client.force_authenticate(second_admin)
        url = f'/api/v1/auth/users/{self.membership.id}/'
        for changes in ({'role': 'reader'}, {'role': 'tenant_admin'}):
            response = self.client.patch(url, changes, format='json')
            self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')

    def test_agent_lifecycle_reservation_and_gpo_are_mutually_exclusive(self):
        from ipms.apps.agent_pki.lifecycle import create_lifecycle_job, offer_lifecycle_job
        from ipms.apps.agent_pki.models import AgentLifecycleJob
        lifecycle = create_lifecycle_job(enrollment=self.agent, action='uninstall', actor=self.user.username)
        self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 409)
        lifecycle.status = 'failed'
        lifecycle.save()
        job = self.queue()
        self.exchange(job, 'claim')
        with self.assertRaises(ValidationError):
            create_lifecycle_job(enrollment=self.agent, action='uninstall', actor=self.user.username)
        # Legacy/directly persisted queued maintenance must also not dispatch.
        AgentLifecycleJob.objects.create(tenant=self.tenant, enrollment=self.agent, action='uninstall', requested_by=self.user.username)
        self.assertIsNone(offer_lifecycle_job(self.agent))
        self.result(job, code='gpo_worker_timeout')
        self.assertIsNone(offer_lifecycle_job(self.agent))

    def test_offline_executor_removal_preserves_an_ambiguous_write_fence(self):
        from django.urls import reverse
        job = self.queue()
        self.exchange(job, 'claim')
        old = timezone.now() - timedelta(days=2)
        AgentEnrollment.objects.update(last_heartbeat_at=old, last_seen_at=old)
        WindowsServer.objects.update(last_seen_at=old, discovered_at=old)
        response = self.client.delete(reverse('core:agent-administration-detail', kwargs={'pk': self.agent.id}))
        self.assertEqual(response.status_code, 400, response.data)
        self.agent.refresh_from_db()
        self.assertEqual(self.agent.status, 'active')
        self.assertEqual(GpoImportJob.objects.get().status, 'running')

    def test_expired_unclaimed_offer_does_not_block_agent_maintenance_forever(self):
        from ipms.apps.agent_pki.lifecycle import create_lifecycle_job
        job = self.queue()
        GpoImportJob.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        lifecycle = create_lifecycle_job(enrollment=self.agent, action='uninstall', actor=self.user.username)
        self.assertEqual(lifecycle.status, 'queued')
        self.assertFalse(self.exchange(job, 'claim')['gpo_claim']['authorized'])

    def test_deleted_requester_is_readable_but_cannot_receive_a_grant(self):
        job = self.queue()
        GpoImportJob.objects.update(requested_by=None)
        self.assertIsNone(self.poll())
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')


class GpoArtifactTests(SimpleTestCase):
    def test_integrity_missing_corrupt_oversized_and_hardlinked_files(self):
        content = b'IPMSGPO1' + bytes(4)
        component = {'artifact_sha256': hashlib.sha256(content).hexdigest(), 'artifact_size': len(content)}
        with tempfile.TemporaryDirectory() as temporary, override_settings(IPMS_SECURITY_GPO_ARTIFACT_DIR=temporary):
            path = Path(temporary) / (component['artifact_sha256'] + '.ipmsgpo')
            with self.assertRaises(ValidationError):
                artifact_bytes(component)
            path.write_bytes(content)
            self.assertEqual(artifact_bytes(component), content)
            path.write_bytes(b'corrupt-data')
            with self.assertRaises(ValidationError):
                artifact_bytes(component)
            path.write_bytes(content)
            with self.assertRaises(ValidationError):
                artifact_bytes({**component, 'artifact_size': 2 * 1024 * 1024})
            os.link(path, Path(temporary) / 'hardlink')
            with self.assertRaises(ValidationError):
                artifact_bytes(component)


class GpoTransportTests(SimpleTestCase):
    async def test_routes_authenticate_and_never_offer_unrelated_agent_jobs(self):
        for path, action in (('/v1/security-gpo', 'poll'), ('/v1/security-gpo-artifact', 'artifact')):
            reader = asyncio.StreamReader()
            reader.feed_data(wire_request(path=path, type='security_gpo', schema_version='1', action=action))
            reader.feed_eof()
            writer = ConsoleWriter()
            calls = []

            async def database(function, *args, **kwargs):
                calls.append(function.__name__)
                if function.__name__ == 'validate_peer_certificate':
                    self.assertEqual(kwargs['allow_suspended_report'], action == 'poll')
                    return SimpleNamespace(device_uri='test-device')
                self.assertEqual(function.__name__, 'security_gpo_exchange')
                self.assertEqual(kwargs['artifact'], action == 'artifact')
                return (b'pinned-test-content', 'a' * 64) if action == 'artifact' else {'status': 'accepted', 'gpo_job': None}

            with patch.object(gateway, '_database_call_async', database):
                await gateway.handle_connection(reader, writer)
            self.assertIn(b'HTTP/1.1 200', bytes(writer.output))
            self.assertEqual(calls, ['validate_peer_certificate', 'security_gpo_exchange'])
            if action == 'artifact':
                self.assertIn(b'Content-Type: application/octet-stream', bytes(writer.output))
                self.assertTrue(bytes(writer.output).endswith(b'pinned-test-content'))
