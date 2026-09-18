# File Name: test_gpo_production.py
# Version: v0.2.1 | Created: 2026-09-15 | Last Modified: 2026-09-18
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Production GPO lifecycle, scoped inspection and immutable approval regression tests.
import copy
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import IntegrityError, connection, transaction
from django.test import TestCase, SimpleTestCase, TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from .gpo_jobs import digest, security_gpo_exchange
from .gpo_production import (ACTIVATE, DEACTIVATE, DELETE, IMPORT, IMPORT_LINK, INSPECT, LINK, SUCCESS, active_binding,
                             compact_purpose, validate_snapshot)
from .models import DomainSecuritySettings, GpoExecutorReport, GpoImportJob, ManagedGpoPolicy
from . import test_gpo_approvals as approval_tests
from .test_gpo_jobs import DOMAIN_GUID, PILOT_GUID

DOMAIN = 'example.invalid'
OTHER_GUID = 'd7221a0b-d83a-45e6-8ef0-e41bab0255fe'


class ProductionGpoTests(TestCase):
    draft = approval_tests.PortalApprovalTests.draft
    create = approval_tests.PortalApprovalTests.create
    envelope = approval_tests.PortalApprovalTests.envelope
    exchange = approval_tests.PortalApprovalTests.exchange
    result = approval_tests.PortalApprovalTests.result
    approve = approval_tests.PortalApprovalTests.approve
    grants = approval_tests.PortalApprovalTests.grants
    policy = approval_tests.PortalApprovalTests.policy
    poll = approval_tests.PortalApprovalTests.poll

    def setUp(self):
        approval_tests.PortalApprovalTests.setUp(self)
        from .gpo_jobs import _content
        patch('ipms.apps.security.gpo_production._content', return_value=_content()).start()
        patch('ipms.apps.security.gpo_production.artifact_bytes', return_value=self.bundle).start()
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        self.selection['target_ous'] = list(self.config['tier_ous']['1'])
        self.base = f"/api/v1/security/domain-settings/{self.config['id']}/"
        self.managed = None

    def inspect(self, operation=IMPORT, **changes):
        selection = {**self.selection, 'idempotency_key': str(uuid.uuid4()), 'operation': operation,
                     'managed_id': str(self.managed.pk) if self.managed else None, 'adopt_job_id': None, **changes}
        response = self.client.post(self.base + 'gpo-preflights/', selection, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        job = GpoImportJob.objects.get(pk=response.data['id'])
        self.managed = ManagedGpoPolicy.objects.get(pk=job.assignment['managed_id'])
        return job.assignment

    def legacy_queue(self):
        selection = self.selection
        self.selection = {key: value for key, value in selection.items() if key != 'target_ous'}
        try:
            return approval_tests.PortalApprovalTests.queue(self)
        finally:
            self.selection = selection

    def snapshot(self, job, gpo=None):
        return {'schema': 1, 'domain_admins_sid': 'S-1-5-21-1-2-3-512',
                'gpo': copy.deepcopy(gpo), 'name_available': True, 'ous': [
            {'dn': dn, 'guid': str(uuid.UUID(int=index + 10)), 'usn': '10', 'blocked': False,
             'links': [], 'inherited_links': []} for index, dn in enumerate(job['target_ous'])]}

    def gpo(self, job):
        return {'guid': PILOT_GUID, 'name': job['pilot_display_name'],
                'description': 'IPMS managed GPO; id=' + job['managed_id'],
                'computer_enabled': False, 'user_enabled': False,
                'computer_ds': 1, 'computer_sysvol': 1, 'user_ds': 0, 'user_sysvol': 0,
                'owner_sid': 'S-1-5-21-1-2-3-512',
                'security_digest': 'a' * 64, 'wmi_filter': '', 'links': []}

    def report_success(self, job, state, *, backup=False, **changes):
        operation = job['operation']
        evidence = {'schema': 3, 'operation': operation, 'managed_id': job['managed_id'], 'state': state,
                    'prepared_artifact_sha256': job['artifact_sha256'] if operation in (IMPORT, IMPORT_LINK, ACTIVATE) else '',
                    'backup_id': str(uuid.UUID(int=50)) if backup else '',
                    'backup_manifest_sha256': 'b' * 64 if backup else ''}
        values = {'status': SUCCESS[operation][0], 'result_code': SUCCESS[operation][1],
                  'gpo_guid': state['gpo']['guid'] if state['gpo'] else None, 'evidence': evidence, **changes}
        return self.exchange(job, 'result', **values)

    def change(self, preflight, **changes):
        data = {'preflight_id': preflight['job_id'], 'idempotency_key': str(uuid.uuid4()),
                'safety_review': {'management_access': preflight['intended_operation'] == ACTIVATE,
                                  'recovery_access': preflight['intended_operation'] == ACTIVATE}, **changes}
        response = self.client.post(self.base + 'managed-gpos/', data, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        return GpoImportJob.objects.get(pk=response.data['id']).assignment

    def execute(self, job):
        row = GpoImportJob.objects.get(pk=job['job_id'])
        self.assertEqual(row.status, 'queued')
        self.assertEqual(row.approved_by_id, row.requested_by_id)
        self.assertIsNotNone(row.approved_at)
        claim = self.exchange(job, 'claim')['gpo_claim']
        self.assertTrue(claim['authorized'])
        self.assertEqual(claim['approval']['operation'], job['operation'])

    def imported(self):
        inspected = self.inspect()
        self.report_success(inspected, self.snapshot(inspected))
        job = self.change(inspected)
        self.execute(job)
        state = self.snapshot(job, self.gpo(job))
        self.report_success(job, state)
        self.managed.refresh_from_db()
        return job, state['gpo']

    def linked(self):
        imported, gpo = self.imported()
        inspection = self.inspect(LINK)
        snapshot = self.snapshot(inspection, gpo)
        self.report_success(inspection, snapshot)
        job = self.change(inspection)
        self.execute(job)
        post = self.linked_state(job, snapshot)
        self.report_success(job, post)
        self.managed.refresh_from_db()
        return job, post

    def linked_state(self, job, before, *, enabled=False, kind='ou'):
        state = copy.deepcopy(before)
        state['gpo']['links'] = []
        for index, ou in enumerate(state['ous']):
            others = [link for link in ou['links'] if link['guid'] != PILOT_GUID]
            link = {'guid': PILOT_GUID, 'domain': DOMAIN, 'dn': ou['dn'], 'kind': kind,
                    'enabled': enabled, 'enforced': False, 'order': job['link_orders'][index]}
            others.insert(link['order'] - 1, link)
            for order, item in enumerate(others, 1):
                item['order'] = order
            ou['links'] = others
            ou['usn'] = '11'
            state['gpo']['links'].append(link)
        return state

    def activated(self):
        linked, state = self.linked()
        inspection = self.inspect(ACTIVATE)
        self.report_success(inspection, state)
        job = self.change(inspection)
        self.execute(job)
        post = self.linked_state(job, state, enabled=True)
        post['gpo'].update(computer_enabled=True, computer_ds=2, computer_sysvol=2)
        self.report_success(job, post, backup=True)
        self.managed.refresh_from_db()
        return job, post

    def test_read_only_inspection_never_claims_fetches_or_approves(self):
        job = self.inspect()
        row = GpoImportJob.objects.get(pk=job['job_id'])
        self.assertEqual(row.status, 'queued')
        self.assertIsNone(row.approved_at)
        self.assertEqual(job['approval_mode'], 'inspection')
        self.assertEqual(self.client.get('/api/v1/security/gpo-imports/' + str(row.pk) + '/').data['approval_mode'], 'inspection')
        self.assertNotIn('Pilot', job['pilot_display_name'])
        self.assertNotIn(self.selection['backup_id'][1:9].lower(), job['pilot_display_name'])
        self.assertEqual(self.approve(job).status_code, 409)
        with self.assertRaises(ValidationError), transaction.atomic():
            self.exchange(job, 'claim')
        with self.assertRaises(ValidationError), transaction.atomic():
            security_gpo_exchange(self.agent, self.envelope('artifact', job_id=job['job_id'], input_digest=job['input_digest']), artifact=True)
        self.report_success(job, self.snapshot(job))
        row.refresh_from_db()
        self.assertIsNone(row.claimed_at)
        self.assertEqual(row.status, 'inspected')
        self.assertTrue(self.client.get('/api/v1/security/gpo-imports/' + str(row.pk) + '/').data['can_prepare'])

    def test_import_link_activation_are_three_immutable_approved_jobs(self):
        linked, state = self.linked()
        self.assertEqual(self.managed.state, 'linked')
        self.assertIsNone(self.managed.active_job_id)
        inspection = self.inspect(ACTIVATE)
        self.report_success(inspection, state)
        job = self.change(inspection)
        self.assertEqual(job['expected_state'], state)
        self.execute(job)
        post = self.linked_state(job, state, enabled=True)
        post['gpo'].update(computer_enabled=True, computer_ds=2, computer_sysvol=2)
        self.report_success(job, post, backup=True)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'active')
        self.assertEqual(str(self.managed.active_job_id), job['job_id'])
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)
        self.assertIsNotNone(active_binding(self.managed, timezone.now()))
        jobs = GpoImportJob.objects.filter(assignment__approval_mode='portal')
        self.assertEqual(jobs.count(), 3)
        self.assertEqual(jobs.filter(approved_at__isnull=True).count(), 0)

    def test_delete_baseline_uses_only_managed_identity_and_removes_projection(self):
        _, state = self.activated()
        managed_id = self.managed.pk
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        request = {'revision': self.config['revision'], 'system_id': self.selection['system_id'],
                   'idempotency_key': str(uuid.uuid4()), 'operation': DELETE,
                   'managed_id': str(managed_id), 'domain_root_confirmed': False}
        response = self.client.post(self.base + 'gpo-preflights/', request, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        inspection = GpoImportJob.objects.get(pk=response.data['id']).assignment
        self.assertEqual(inspection['schema'], 3)
        self.assertEqual(inspection['intended_operation'], DELETE)
        self.assertEqual(inspection['pilot_display_name'], self.managed.display_name)
        self.report_success(inspection, state)
        deletion = self.change(inspection)
        self.execute(deletion)
        post = copy.deepcopy(state)
        removed_guid = post['gpo']['guid']
        post['gpo'] = None
        for ou in post['ous']:
            ou['links'] = [link for link in ou['links'] if link['guid'] != removed_guid]
            for order, link in enumerate(ou['links'], 1):
                link['order'] = order
            ou['usn'] = '12'
        self.report_success(deletion, post, backup=True)
        self.assertFalse(ManagedGpoPolicy.objects.filter(pk=managed_id).exists())
        retry = self.client.post(self.base + 'gpo-preflights/', request, format='json')
        self.assertEqual(retry.status_code, 202, retry.data)
        self.assertEqual(retry.data['id'], response.data['id'])

    def test_unimported_local_draft_can_be_deleted_without_an_agent_write(self):
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        managed_id = self.managed.pk
        response = self.client.delete(self.base + 'managed-gpos/', {
            'revision': self.config['revision'], 'managed_id': str(managed_id)}, format='json')
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.assertFalse(ManagedGpoPolicy.objects.filter(pk=managed_id).exists())

    def test_missing_stale_guid_is_forgotten_only_after_agent_inspection(self):
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        managed_id = self.managed.pk
        self.managed.gpo_guid = PILOT_GUID
        self.managed.save(update_fields=('gpo_guid',))
        request = {'revision': self.config['revision'], 'system_id': self.selection['system_id'],
                   'idempotency_key': str(uuid.uuid4()), 'operation': DELETE,
                   'managed_id': str(managed_id), 'domain_root_confirmed': False}
        response = self.client.post(self.base + 'gpo-preflights/', request, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        deletion_check = GpoImportJob.objects.get(pk=response.data['id']).assignment
        self.assertEqual(deletion_check['intended_operation'], DELETE)
        self.report_success(deletion_check, self.snapshot(deletion_check))
        self.assertFalse(ManagedGpoPolicy.objects.filter(pk=managed_id).exists())

    def test_delete_rejects_creation_fields_instead_of_revalidating_them(self):
        self.linked()
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        response = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
            'idempotency_key': str(uuid.uuid4()), 'operation': DELETE,
            'managed_id': str(self.managed.pk), 'adopt_job_id': None}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertFalse(GpoImportJob.objects.filter(assignment__intended_operation=DELETE).exists())

    def test_initial_import_receipt_rejects_enabled_or_linked_policy(self):
        inspected = self.inspect()
        self.report_success(inspected, self.snapshot(inspected))
        job = self.change(inspected)
        self.execute(job)
        for mutation in ('computer_enabled', 'user_enabled', 'wmi_filter', 'description'):
            with self.subTest(mutation=mutation):
                state = self.snapshot(job, self.gpo(job))
                state['gpo'][mutation] = True if mutation.endswith('enabled') else 'unexpected'
                with self.assertRaises(ValidationError), transaction.atomic():
                    self.report_success(job, state)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.gpo_guid, '')

    def agent_036(self):
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')

    def agent_046(self):
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')

    def combined(self, *, root=False):
        self.agent_036()
        inspected = self.root_inspection(IMPORT_LINK) if root else self.inspect(IMPORT_LINK)
        state = self.root_snapshot(inspected, None) if root else self.snapshot(inspected)
        self.report_success(inspected, state)
        job = self.change(inspected)
        self.execute(job)
        post = copy.deepcopy(state)
        post['gpo'] = self.gpo(job)
        post = self.linked_state(job, post, kind='domain' if root else 'ou')
        artifact, artifact_hash = security_gpo_exchange(self.agent, self.envelope(
            'artifact', job_id=job['job_id'], input_digest=job['input_digest']), artifact=True)
        self.assertEqual(artifact, self.bundle)
        self.assertEqual(artifact_hash, job['artifact_sha256'])
        self.report_success(job, post)
        self.managed.refresh_from_db()
        return job, post

    def test_combined_initial_import_links_with_one_approval_and_separate_activation(self):
        job, state = self.combined()
        self.assertEqual(len(job), 28)
        self.assertEqual(self.managed.state, 'linked')
        self.assertEqual(str(self.managed.origin_job_id), job['job_id'])
        self.assertEqual(str(self.managed.staged_job_id), job['job_id'])
        self.assertIsNone(self.managed.active_job_id)
        self.assertEqual(GpoImportJob.objects.filter(approved_at__isnull=False).count(), 1)
        self.assertEqual(GpoImportJob.objects.count(), 2)
        self.assertFalse(state['gpo']['computer_enabled'])
        self.assertTrue(all(not link['enabled'] for link in state['gpo']['links']))
        self.assertIsNone(active_binding(self.managed, timezone.now()))
        inspected = self.inspect(ACTIVATE)
        self.report_success(inspected, state)
        activation = self.change(inspected)
        self.execute(activation)
        active = self.linked_state(activation, state, enabled=True)
        active['gpo']['computer_enabled'] = True
        self.report_success(activation, active, backup=True)
        self.managed.refresh_from_db()
        self.assertIsNotNone(active_binding(self.managed, timezone.now()))
        self.assertEqual(GpoImportJob.objects.filter(approved_at__isnull=False).count(), 2)

    def test_combined_root_import_preserves_default_domain_policy(self):
        self.use_domain_component()
        self.agent_036()
        config = DomainSecuritySettings.objects.get(pk=self.config['id'])
        config.tier_ous['0'] = []
        config.save(update_fields=('tier_ous',))
        inspected = self.root_inspection(IMPORT_LINK)
        state = self.root_snapshot(inspected, None)
        default = {'guid': '31b2f340-016d-11d2-945f-00c04fb984f9', 'domain': DOMAIN,
                   'dn': state['ous'][0]['dn'], 'kind': 'domain', 'enabled': True, 'enforced': False, 'order': 1}
        state['ous'][0]['links'] = [default]
        self.report_success(inspected, state)
        job = self.change(inspected)
        self.assertEqual(job['link_orders'], [1])
        self.execute(job)
        post = copy.deepcopy(state)
        post['gpo'] = self.gpo(job)
        post = self.linked_state(job, post, kind='domain')
        self.report_success(job, post)
        self.managed.refresh_from_db()
        self.assertEqual(post['ous'][0]['links'][-1], {**default, 'order': 2})
        self.assertEqual(self.managed.state, 'linked')
        self.assertIsNone(self.managed.active_job_id)

    def test_combined_partial_receipt_does_not_advance_policy(self):
        self.agent_036()
        inspected = self.inspect(IMPORT_LINK)
        state = self.snapshot(inspected)
        self.report_success(inspected, state)
        job = self.change(inspected)
        self.execute(job)
        initial = self.snapshot(job, self.gpo(job))
        post = self.linked_state(job, initial)
        mutations = [lambda s: s['gpo'].update(links=[]), lambda s: s['ous'][0].update(links=[]),
                     lambda s: s['gpo'].update(computer_enabled=True), lambda s: s['gpo'].update(name='Wrong'),
                     lambda s: s['gpo'].update(description='Unmanaged')]
        for mutation in mutations:
            malformed = copy.deepcopy(post)
            mutation(malformed)
            with self.assertRaises(ValidationError), transaction.atomic():
                self.report_success(job, malformed)
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, post, backup=True)
        for artifact in ('', '0' * 64):
            evidence = {'schema': 3, 'operation': IMPORT_LINK, 'managed_id': job['managed_id'], 'state': post,
                        'prepared_artifact_sha256': artifact, 'backup_id': '', 'backup_manifest_sha256': ''}
            with self.assertRaises(ValidationError), transaction.atomic():
                self.report_success(job, post, evidence=evidence)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.revision, 1)
        self.assertEqual(self.managed.gpo_guid, '')
        self.assertIsNone(self.managed.staged_job_id)
        self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).status, 'running')
        self.report_success(job, post)

    def test_combined_existing_disabled_policy_prepares_revision_without_importing_it(self):
        previous, state = self.combined()
        inspected = self.inspect(IMPORT_LINK, version='2.0.0')
        self.report_success(inspected, state)
        job = self.change(inspected)
        self.execute(job)
        post = self.linked_state(job, state)
        changed_content = copy.deepcopy(post)
        changed_content['gpo'].update(name=job['pilot_display_name'], computer_ds=2, computer_sysvol=2)
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, changed_content)
        self.report_success(job, post)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)
        self.assertEqual(self.managed.version, '2.0.0')
        self.assertEqual(self.managed.display_name, job['pilot_display_name'])
        self.assertEqual(post['gpo']['name'], previous['pilot_display_name'])
        self.assertEqual(str(self.managed.staged_job_id), job['job_id'])
        self.assertEqual(str(self.managed.origin_job_id), previous['job_id'])

    def test_combined_rejects_active_gpo_before_creating_write_job(self):
        self.agent_036()
        active, state = self.activated()
        inspected = self.inspect(IMPORT_LINK)
        self.report_success(inspected, state)
        count = GpoImportJob.objects.count()
        response = self.client.post(self.base + 'managed-gpos/', {'preflight_id': inspected['job_id'],
            'idempotency_key': str(uuid.uuid4()), 'safety_review': {'management_access': False, 'recovery_access': False}}, format='json')
        self.assertEqual(response.status_code, 409)
        self.assertEqual(GpoImportJob.objects.count(), count)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'active')

    def test_all_managed_operations_require_agent_047(self):
        self.system.agent_version = '0.2.46'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.46')
        response = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
            'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT_LINK, 'managed_id': None, 'adopt_job_id': None}, format='json')
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.data['error']['code'], 'security_gpo_executor_unavailable')
        self.assertFalse(GpoImportJob.objects.exists())
        self.agent_036()
        self.imported()

    def test_combined_links_only_the_selected_configured_ou_and_persists_scope(self):
        self.agent_036()
        selected = [self.config['tier_ous']['1'][1]]
        inspected = self.inspect(IMPORT_LINK, target_ous=selected)
        self.assertEqual(inspected['target_ous'], selected)
        self.assertEqual(self.managed.target_ous, selected)
        self.assertEqual(self.snapshot(inspected)['ous'][0]['dn'], selected[0])

    def test_target_ous_reject_empty_duplicates_and_cross_tier_values(self):
        self.agent_036()
        for targets in ([], [self.config['tier_ous']['1'][0]] * 2, self.config['tier_ous']['2']):
            with self.subTest(targets=targets):
                response = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
                    'target_ous': targets, 'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT_LINK,
                    'managed_id': None, 'adopt_job_id': None}, format='json')
                self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(ManagedGpoPolicy.objects.exists())

    def test_combined_adopts_only_exact_legacy_receipt_then_links_same_guid(self):
        legacy = self.legacy_queue()
        self.assertEqual(self.approve(legacy).status_code, 200)
        self.assertTrue(self.exchange(legacy, 'claim')['gpo_claim']['authorized'])
        self.result(legacy, status='staged', code='gpo_staged_unlinked', guid=PILOT_GUID, evidence={
            'computer_enabled': False, 'user_enabled': False, 'unlinked': True,
            'domain_dns_name': DOMAIN, 'domain_guid': DOMAIN_GUID, 'dc_fqdn': self.system.fqdn})
        self.agent_036()
        inspected = self.inspect(IMPORT_LINK, adopt_job_id=legacy['job_id'])
        gpo = self.gpo(inspected)
        gpo.update(name=legacy['pilot_display_name'], description=inspected['owner_marker'])
        before = self.snapshot(inspected, gpo)
        self.report_success(inspected, before)
        job = self.change(inspected)
        self.execute(job)
        post = self.linked_state(job, before)
        post['gpo'].update(name=job['pilot_display_name'], description='IPMS managed GPO; id=' + job['managed_id'])
        self.report_success(job, post)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)
        self.assertEqual(str(self.managed.origin_job_id), legacy['job_id'])
        self.assertEqual(str(self.managed.staged_job_id), job['job_id'])
        self.assertEqual(self.managed.state, 'linked')

    def test_nonactivation_receipts_reject_recovery_backup_metadata(self):
        state = None
        for operation in (IMPORT, LINK, DEACTIVATE):
            with self.subTest(operation=operation):
                inspected = self.inspect(operation)
                observed = self.snapshot(inspected) if state is None else (
                    self.snapshot(inspected, state['gpo']) if operation == LINK else state)
                with self.assertRaises(ValidationError), transaction.atomic():
                    self.report_success(inspected, observed, backup=True)
                self.report_success(inspected, observed)
                job = self.change(inspected)
                self.execute(job)
                state = (self.snapshot(job, self.gpo(job)) if operation == IMPORT else
                         self.linked_state(job, observed) if operation == LINK else copy.deepcopy(observed))
                revision = self.managed.revision
                with self.assertRaises(ValidationError), transaction.atomic():
                    self.report_success(job, state, backup=True)
                self.managed.refresh_from_db()
                self.assertEqual(self.managed.revision, revision)
                self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).status, 'running')
                self.report_success(job, state)
                self.managed.refresh_from_db()

    def test_inspection_snapshot_cannot_be_replaced_in_write_request(self):
        inspected = self.inspect()
        self.report_success(inspected, self.snapshot(inspected))
        response = self.client.post(self.base + 'managed-gpos/', {'preflight_id': inspected['job_id'],
            'idempotency_key': str(uuid.uuid4()), 'safety_review': {'management_access': False, 'recovery_access': False},
            'expected_state': self.snapshot(inspected, self.gpo(inspected))}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertEqual(GpoImportJob.objects.count(), 1)

    def test_expired_inspection_requires_new_read(self):
        inspected = self.inspect()
        self.report_success(inspected, self.snapshot(inspected))
        GpoImportJob.objects.filter(pk=inspected['job_id']).update(expires_at=timezone.now() - timedelta(seconds=1))
        listing = self.client.get(self.base + 'managed-gpos/')
        projected = next(job for job in listing.data['jobs'] if job['id'] == inspected['job_id'])
        self.assertIsNone(projected['preflight_state'])
        self.assertFalse(projected['can_prepare'])
        response = self.client.post(self.base + 'managed-gpos/', {'preflight_id': inspected['job_id'],
            'idempotency_key': str(uuid.uuid4()), 'safety_review': {'management_access': False, 'recovery_access': False}}, format='json')
        self.assertEqual(response.status_code, 409)

    def test_scope_withdrawal_invalidates_unclaimed_inspection(self):
        inspected = self.inspect()
        self.assertEqual(self.grants([]).status_code, 200)
        row = GpoImportJob.objects.get(pk=inspected['job_id'])
        self.assertEqual(row.status, 'failed')
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(inspected, self.snapshot(inspected))

    def test_changed_ou_configuration_invalidates_inspection(self):
        inspected = self.inspect()
        self.report_success(inspected, self.snapshot(inspected))
        DomainSecuritySettings.objects.filter(pk=self.config['id']).update(revision=2)
        detail = self.client.get('/api/v1/security/gpo-imports/' + inspected['job_id'] + '/').data
        self.assertFalse(detail['can_prepare'])

    def test_four_eyes_remains_optional_and_enforced_for_writes(self):
        self.assertEqual(self.policy(True).status_code, 200)
        self.assertEqual(self.grants().status_code, 200)
        inspected = self.inspect()
        self.report_success(inspected, self.snapshot(inspected))
        job = self.change(inspected)
        self.assertEqual(self.approve(job).status_code, 403)
        self.client.force_authenticate(self.approver)
        self.assertEqual(self.approve(job).status_code, 200)

    def test_read_only_jobs_share_domain_fence_with_legacy_and_production(self):
        job = self.inspect()
        legacy_selection = {key: value for key, value in self.selection.items() if key != 'target_ous'}
        response = self.client.post(self.import_url, {**legacy_selection, 'idempotency_key': str(uuid.uuid4())}, format='json')
        self.assertEqual(response.status_code, 409)
        self.assertEqual(GpoImportJob.objects.count(), 1)
        self.assertEqual(GpoImportJob.objects.get().assignment['job_id'], job['job_id'])

    def test_successful_inspection_retry_is_idempotent(self):
        job = self.inspect()
        snapshot = self.snapshot(job)
        self.report_success(job, snapshot)
        self.report_success(job, snapshot)
        snapshot['name_available'] = False
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, snapshot)

    def test_linking_preserves_unrelated_order_flags_and_guid(self):
        imported, gpo = self.imported()
        inspection = self.inspect(LINK)
        snapshot = self.snapshot(inspection, gpo)
        for ou in snapshot['ous']:
            ou['links'] = [{'guid': OTHER_GUID, 'domain': DOMAIN, 'dn': ou['dn'], 'kind': 'ou',
                            'enabled': True, 'enforced': True, 'order': 1}]
        self.report_success(inspection, snapshot)
        job = self.change(inspection)
        self.assertEqual(job['link_orders'], [2, 2])
        self.execute(job)
        post = self.linked_state(job, snapshot)
        tampered = copy.deepcopy(post)
        tampered['ous'][0]['links'][0]['enabled'] = False
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, tampered)
        self.report_success(job, post)

    def test_activation_requires_explicit_access_review_and_backup(self):
        linked, state = self.linked()
        inspection = self.inspect(ACTIVATE)
        self.report_success(inspection, state)
        response = self.client.post(self.base + 'managed-gpos/', {'preflight_id': inspection['job_id'],
            'idempotency_key': str(uuid.uuid4()), 'safety_review': {'management_access': True, 'recovery_access': False}}, format='json')
        self.assertEqual(response.status_code, 400)
        job = self.change(inspection)
        self.execute(job)
        post = self.linked_state(job, state, enabled=True)
        post['gpo']['computer_enabled'] = True
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, post)
        self.managed.refresh_from_db()
        self.assertIsNone(self.managed.active_job_id)

    def test_postclaim_failure_keeps_domain_and_managed_policy_fenced(self):
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        job = self.change(inspection)
        self.execute(job)
        self.result(job, code='gpo_backup_failed')
        row = GpoImportJob.objects.get(pk=job['job_id'])
        self.managed.refresh_from_db()
        self.assertEqual(row.status, 'reconciliation_required')
        self.assertEqual(self.managed.state, 'reconciliation_required')

    def test_agent_034_cannot_receive_production_job(self):
        job = self.inspect()
        response = self.poll()
        self.assertIsNone(response)
        self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).status, 'failed')

    def test_snapshot_types_default_gpo_and_scope_are_strict(self):
        job = self.inspect(LINK) if self.managed else self.inspect()
        initial = self.snapshot(job, self.gpo(job))
        mutations = [lambda s: s.update(schema=True), lambda s: s.update(name_available=1),
            lambda s: s['gpo'].update(computer_enabled=0), lambda s: s['gpo'].update(computer_ds=True),
            lambda s: s['gpo'].update(guid='31b2f340-016d-11d2-945f-00c04fb984f9'),
            lambda s: s['gpo'].update(computer_sysvol=99), lambda s: s['gpo'].update(extra=True)]
        for mutation in mutations:
            state = copy.deepcopy(initial)
            mutation(state)
            with self.assertRaises(ValidationError):
                validate_snapshot(state, job)

    def test_subsequent_import_prepares_without_changing_active_gpo_or_guid(self):
        active, state = self.activated()
        binding = active_binding(self.managed, timezone.now())
        inspection = self.inspect(IMPORT, version='2.0.0')
        observed = self.snapshot(inspection, state['gpo'])
        self.report_success(inspection, observed)
        job = self.change(inspection)
        self.execute(job)
        wrong = copy.deepcopy(observed)
        wrong['gpo']['name'] = job['pilot_display_name']
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, wrong)
        self.report_success(job, observed)
        self.managed.refresh_from_db()
        self.assertEqual(str(self.managed.active_job_id), active['job_id'])
        self.assertEqual(str(self.managed.staged_job_id), job['job_id'])
        self.assertEqual(self.managed.state, 'active')
        self.assertEqual(self.managed.version, '2.0.0')
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)
        self.assertEqual(active_binding(self.managed, timezone.now()), binding)
        projected = self.client.get(self.base + 'managed-gpos/').data['results'][0]
        self.assertEqual(projected['display_name'], job['pilot_display_name'])
        self.assertEqual(projected['active_display_name'], active['pilot_display_name'])
        self.assertNotEqual(projected['display_name'], projected['active_display_name'])
        inspection = self.inspect(ACTIVATE, version='2.0.0')
        self.report_success(inspection, state)
        activation = self.change(inspection)
        self.execute(activation)
        updated = self.linked_state(activation, state, enabled=True)
        updated['gpo'].update(name=activation['pilot_display_name'], computer_ds=3, computer_sysvol=3)
        self.report_success(activation, updated, backup=True)
        projected = self.client.get(self.base + 'managed-gpos/').data['results'][0]
        self.assertEqual(projected['display_name'], activation['pilot_display_name'])
        self.assertEqual(projected['active_display_name'], activation['pilot_display_name'])

    def test_deactivation_disables_halves_only_then_relink_disables_own_links(self):
        active, state = self.activated()
        inspection = self.inspect(DEACTIVATE)
        self.report_success(inspection, state)
        job = self.change(inspection)
        self.execute(job)
        post = copy.deepcopy(state)
        post['gpo'].update(computer_enabled=False, user_enabled=False)
        self.report_success(job, post)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'inactive')
        self.assertIsNone(active_binding(self.managed, timezone.now()))
        self.assertTrue(all(link['enabled'] for link in post['gpo']['links']))
        inspection = self.inspect(LINK)
        self.report_success(inspection, post)
        job = self.change(inspection)
        self.execute(job)
        relinked = self.linked_state(job, post)
        self.report_success(job, relinked)
        self.assertTrue(all(not link['enabled'] for link in relinked['gpo']['links']))

    def test_link_and_activation_reject_outside_ou_or_enforced_targets(self):
        imported, gpo = self.imported()
        inspection = self.inspect(LINK)
        snapshot = self.snapshot(inspection, gpo)
        snapshot['gpo']['links'] = [{'guid': PILOT_GUID, 'domain': DOMAIN, 'dn': 'DC=example,DC=invalid',
                                  'kind': 'domain', 'enabled': False, 'enforced': False, 'order': 1}]
        self.report_success(inspection, snapshot)
        response = self.client.post(self.base + 'managed-gpos/', {'preflight_id': inspection['job_id'],
            'idempotency_key': str(uuid.uuid4()), 'safety_review': {'management_access': False, 'recovery_access': False}}, format='json')
        self.assertEqual(response.status_code, 409)

    def test_snapshot_receipt_tampering_cannot_become_approved_intent(self):
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        job = GpoImportJob.objects.get(pk=inspection['job_id'])
        changed = copy.deepcopy(job.result_evidence)
        changed['state']['name_available'] = False
        GpoImportJob.objects.filter(pk=job.pk).update(result_evidence=changed)
        self.assertFalse(self.client.get('/api/v1/security/gpo-imports/' + str(job.pk) + '/').data['can_prepare'])

    def test_expired_claimed_change_fences_active_identity(self):
        active, state = self.activated()
        inspection = self.inspect(DEACTIVATE)
        self.report_success(inspection, state)
        job = self.change(inspection)
        self.execute(job)
        GpoImportJob.objects.filter(pk=job['job_id']).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.client.get(self.base + 'managed-gpos/')
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'reconciliation_required')
        self.assertIsNone(active_binding(self.managed, timezone.now()))

    def test_additive_migration_keeps_old_model_insert_and_legacy_name_uniqueness(self):
        from django.db.migrations.executor import MigrationExecutor
        old_apps = MigrationExecutor(connection).loader.project_state([
            ('security', '0005_gpoapprovalpolicy_gpodomainauthorization_and_more')]).apps
        old_model = old_apps.get_model('security', 'GpoImportJob')
        legacy = self.legacy_queue()
        row = GpoImportJob.objects.get(pk=legacy['job_id'])
        row.status = 'failed'
        row.save(update_fields=('status',))
        values = {field.attname: getattr(row, field.attname) for field in old_model._meta.concrete_fields}
        values.update(id=uuid.uuid4(), pilot_name_key='old-model-insert', pilot_display_name='Old model insert')
        old_model.objects.create(**values)
        self.assertEqual(GpoImportJob.objects.count(), 2)
        values['id'] = uuid.uuid4()
        with self.assertRaises(IntegrityError), transaction.atomic():
            old_model.objects.create(**values)
        self.assertEqual(ManagedGpoPolicy.objects.count(), 0)

    def test_snapshot_and_transport_size_caps_are_explicit(self):
        job = self.inspect()
        state = self.snapshot(job, self.gpo(job))
        state['gpo']['links'] = [{'guid': str(uuid.UUID(int=i+100)), 'domain': DOMAIN,
            'dn': 'OU=' + ('x' * 1000) + str(i) + ',DC=example,DC=invalid',
            'kind': 'ou', 'enabled': False, 'enforced': False, 'order': i+1} for i in range(20)]
        with self.assertRaisesMessage(ValidationError, 'transport budget'):
            validate_snapshot(state, job)

    def test_explicit_legacy_receipt_adoption_preserves_guid_and_removes_old_name(self):
        legacy = self.legacy_queue()
        self.assertEqual(self.approve(legacy).status_code, 200)
        self.assertTrue(self.exchange(legacy, 'claim')['gpo_claim']['authorized'])
        self.result(legacy, status='staged', code='gpo_staged_unlinked', guid=PILOT_GUID, evidence={
            'computer_enabled': False, 'user_enabled': False, 'unlinked': True,
            'domain_dns_name': DOMAIN, 'domain_guid': DOMAIN_GUID, 'dc_fqdn': self.system.fqdn})
        inspected = self.inspect(adopt_job_id=legacy['job_id'])
        self.assertEqual(inspected['gpo_guid'], PILOT_GUID)
        before = self.gpo(inspected)
        before.update(name=legacy['pilot_display_name'], description=inspected['owner_marker'])
        self.report_success(inspected, self.snapshot(inspected, before))
        job = self.change(inspected)
        self.execute(job)
        after = copy.deepcopy(before)
        after.update(name=job['pilot_display_name'], description='IPMS managed GPO; id=' + job['managed_id'])
        self.report_success(job, self.snapshot(job, after))
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)
        self.assertEqual(str(self.managed.origin_job_id), legacy['job_id'])
        self.assertNotIn('Pilot', self.managed.display_name)

    def test_nested_target_ou_inheritance_changes_only_the_managed_guid(self):
        config = DomainSecuritySettings.objects.get(pk=self.config['id'])
        config.tier_ous['1'] = ['OU=Servers,DC=example,DC=invalid', 'OU=Apps,OU=Servers,DC=example,DC=invalid']
        config.save(update_fields=('tier_ous',))
        self.selection['target_ous'] = list(config.tier_ous['1'])
        imported, gpo = self.imported()
        inspection = self.inspect(LINK)
        state = self.snapshot(inspection, gpo)
        self.report_success(inspection, state)
        job = self.change(inspection)
        self.execute(job)
        post = self.linked_state(job, state)
        post['ous'][1]['inherited_links'] = [copy.deepcopy(post['ous'][0]['links'][0])]
        bad = copy.deepcopy(post)
        bad['ous'][0]['inherited_links'] = [copy.deepcopy(post['ous'][1]['links'][0])]
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(job, bad)
        self.report_success(job, post)

    def test_native_canonical_ou_case_is_bound_by_identity_then_exact_snapshot(self):
        config = DomainSecuritySettings.objects.get(pk=self.config['id'])
        config.tier_ous['1'] = [dn.lower() for dn in config.tier_ous['1']]
        config.save(update_fields=('tier_ous',))
        self.selection['target_ous'] = list(config.tier_ous['1'])
        imported, gpo = self.imported()
        inspected = self.inspect(LINK)
        state = self.snapshot(inspected, gpo)
        for ou in state['ous']:
            ou['dn'] = ou['dn'].upper()
        self.report_success(inspected, state)
        job = self.change(inspected)
        self.assertEqual(job['target_ous'], config.tier_ous['1'])
        self.assertEqual(job['expected_state'], state)
        self.execute(job)
        linked = self.linked_state(job, state)
        self.report_success(job, linked)
        self.managed.refresh_from_db()
        inspected = self.inspect(ACTIVATE)
        self.report_success(inspected, linked)
        job = self.change(inspected)
        self.assertEqual(job['target_ous'], config.tier_ous['1'])
        self.assertEqual(job['expected_state'], linked)
        self.execute(job)
        activated = self.linked_state(job, linked, enabled=True)
        activated['gpo']['computer_enabled'] = True
        self.report_success(job, activated, backup=True)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'active')

    def test_production_logs_are_filterable_and_csv_reports_concrete_operation(self):
        job = self.inspect()
        self.report_success(job, self.snapshot(job))
        url = '/api/v1/logs/baselines/'
        response = self.client.get(url, {'kind': 'gpo_import', 'status': 'inspected'})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['results'][0]['action'], INSPECT)
        self.assertEqual(response.data['results'][0]['target'], job['pilot_display_name'])
        exported = self.client.get(url + 'export/', {'kind': 'gpo_import', 'status': 'inspected'})
        self.assertEqual(exported.status_code, 200, exported.content)
        self.assertIn(INSPECT.encode(), exported.content)

    def use_domain_component(self):
        from .gpo_jobs import _content
        components, profiles = _content()
        domain_backup = next(backup for (baseline, backup), component in components.items()
                             if baseline == self.selection['baseline_id'] and component['scope'] == 'domain')
        domain_component = copy.deepcopy(components[(self.selection['baseline_id'], domain_backup)])
        domain_component.update({key: self.component[key] for key in ('artifact_sha256', 'artifact_size', 'files')})
        content = {**components, (self.selection['baseline_id'], domain_backup): domain_component}
        patch('ipms.apps.security.gpo_jobs._content', return_value=(content, profiles)).start()
        patch('ipms.apps.security.gpo_production._content', return_value=(content, profiles)).start()
        self.selection.update(backup_id=domain_backup, tier='0', target_ous=['DC=example,DC=invalid'])

    def root_inspection(self, operation):
        job = self.inspect(operation, domain_root_confirmed=True)
        self.assertEqual(job['target_tier'], 0)
        self.assertEqual(job['target_ous'], ['DC=example,DC=invalid'])
        self.assertEqual(len(job), 28)
        return job

    def root_snapshot(self, job, gpo):
        state = self.snapshot(job, gpo)
        state['ous'][0]['guid'] = DOMAIN_GUID
        return state

    def test_domain_root_import_link_activate_deactivate_are_separately_approved(self):
        self.use_domain_component()
        # A domain-root policy does not depend on a configured Tier 0 OU.
        config = DomainSecuritySettings.objects.get(pk=self.config['id'])
        config.tier_ous['0'] = []
        config.save(update_fields=('tier_ous',))
        imported, gpo = self.imported()
        self.assertEqual(imported['target_ous'], [])
        inspected = self.root_inspection(LINK)
        state = self.root_snapshot(inspected, gpo)
        default_guid = '31b2f340-016d-11d2-945f-00c04fb984f9'
        root = state['ous'][0]
        root['links'] = [{'guid': guid, 'domain': DOMAIN, 'dn': root['dn'], 'kind': 'domain',
                          'enabled': True, 'enforced': guid == OTHER_GUID, 'order': index}
                         for index, guid in enumerate((OTHER_GUID, default_guid), 1)]
        self.report_success(inspected, state)
        link = self.change(inspected)
        self.assertEqual(link['link_orders'], [2])
        self.execute(link)
        linked = self.linked_state(link, state, kind='domain')
        self.report_success(link, linked)
        self.managed.refresh_from_db()
        inspected = self.root_inspection(ACTIVATE)
        self.report_success(inspected, linked)
        activation = self.change(inspected)
        self.execute(activation)
        active = self.linked_state(activation, linked, kind='domain', enabled=True)
        active['gpo'].update(computer_enabled=True, computer_ds=2, computer_sysvol=2)
        corrupted = copy.deepcopy(active)
        corrupted['ous'][0]['links'][-1]['enabled'] = False
        with self.assertRaises(ValidationError), transaction.atomic():
            self.report_success(activation, corrupted, backup=True)
        self.report_success(activation, active, backup=True)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'active')
        self.assertIsNone(active_binding(self.managed, timezone.now()))  # Domain security is not RSOP computer assignment.
        self.assertFalse(active['gpo']['user_enabled'])
        self.assertEqual(active['ous'][0]['links'][-1], {**root['links'][-1], 'order': 3})
        inspected = self.root_inspection(DEACTIVATE)
        self.report_success(inspected, active)
        deactivation = self.change(inspected)
        self.execute(deactivation)
        disabled = copy.deepcopy(active)
        disabled['gpo']['computer_enabled'] = False
        self.report_success(deactivation, disabled)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'inactive')
        self.assertEqual(disabled['ous'], active['ous'])

    def test_domain_nonimport_requires_explicit_confirmation_before_inspection(self):
        self.use_domain_component()
        self.imported()
        before = GpoImportJob.objects.count()
        for operation in (IMPORT_LINK, LINK, ACTIVATE, DEACTIVATE):
            for flag in ({}, {'domain_root_confirmed': False}):
                response = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
                    'idempotency_key': str(uuid.uuid4()), 'operation': operation,
                    'managed_id': str(self.managed.pk), 'adopt_job_id': None, **flag}, format='json')
                self.assertEqual(response.status_code, 409, response.data)
                self.assertEqual(response.data['error']['code'], 'security_gpo_domain_root_confirmation_required')
        self.assertEqual(GpoImportJob.objects.count(), before)

    def test_root_confirmation_wrong_types_or_unexpected_true_are_rejected(self):
        for flag in (True, 1, 'true', None):
            response = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
                'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT,
                'managed_id': None, 'adopt_job_id': None, 'domain_root_confirmed': flag}, format='json')
            self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(GpoImportJob.objects.exists())

    def test_domain_scope_requires_tier_zero_even_with_root_confirmation(self):
        self.use_domain_component()
        for tier in ('1', '2'):
            response = self.client.post(self.base + 'gpo-preflights/', {**self.selection, 'tier': tier,
                'idempotency_key': str(uuid.uuid4()), 'operation': LINK,
                'managed_id': None, 'adopt_job_id': None, 'domain_root_confirmed': True}, format='json')
            self.assertEqual(response.status_code, 400, response.data)
        self.assertFalse(GpoImportJob.objects.exists())

    def test_root_snapshot_rejects_foreign_domain_ou_wrong_guid_and_inheritance(self):
        self.use_domain_component()
        imported, gpo = self.imported()
        job = self.root_inspection(LINK)
        valid = self.root_snapshot(job, gpo)
        mutations = [lambda s: s['ous'][0].update(dn='DC=other,DC=invalid'),
            lambda s: s['ous'][0].update(dn='OU=Tier0,DC=example,DC=invalid'),
            lambda s: s['ous'][0].update(guid=OTHER_GUID),
            lambda s: s['gpo'].update(guid='31b2f340-016d-11d2-945f-00c04fb984f9')]
        for mutation in mutations:
            state = copy.deepcopy(valid)
            mutation(state)
            with self.assertRaises(ValidationError), transaction.atomic():
                self.report_success(job, state)
        for kind in ('ou', 'site'):
            state = copy.deepcopy(valid)
            state['ous'][0]['links'] = [{'guid': OTHER_GUID, 'domain': DOMAIN, 'dn': state['ous'][0]['dn'],
                'kind': kind, 'order': 1, 'enabled': True, 'enforced': False}]
            with self.assertRaises(ValidationError):
                validate_snapshot(state, job)

    def test_machine_component_can_target_only_the_confirmed_tier_zero_domain_root(self):
        root = 'DC=example,DC=invalid'
        config = DomainSecuritySettings.objects.get(pk=self.config['id'])
        config.tier_ous['0'] = [root, *config.tier_ous['0']]
        config.save(update_fields=('tier_ous',))
        self.selection.update(tier='0', target_ous=[root])

        self.system.agent_version = '0.2.46'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.46')
        old_agent = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
            'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT_LINK,
            'managed_id': None, 'adopt_job_id': None, 'domain_root_confirmed': True}, format='json')
        self.assertEqual(old_agent.status_code, 409, old_agent.data)
        self.assertEqual(old_agent.data['error']['code'], 'security_gpo_executor_unavailable')

        self.agent_046()
        missing_confirmation = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
            'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT_LINK,
            'managed_id': None, 'adopt_job_id': None}, format='json')
        self.assertEqual(missing_confirmation.status_code, 409, missing_confirmation.data)
        self.assertEqual(missing_confirmation.data['error']['code'], 'security_gpo_domain_root_confirmation_required')

        mixed = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
            'target_ous': config.tier_ous['0'], 'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT_LINK,
            'managed_id': None, 'adopt_job_id': None, 'domain_root_confirmed': True}, format='json')
        self.assertEqual(mixed.status_code, 400, mixed.data)

        job = self.inspect(IMPORT_LINK, domain_root_confirmed=True)
        self.assertEqual(job['target_tier'], 0)
        self.assertEqual(job['target_ous'], [root])
        state = self.snapshot(job)
        state['ous'][0]['guid'] = DOMAIN_GUID
        self.assertEqual(validate_snapshot(state, job), state)


@skipUnlessDBFeature('has_select_for_update')
class ProductionGpoRaceTests(TransactionTestCase):
    setUp = ProductionGpoTests.setUp
    draft = ProductionGpoTests.draft
    create = ProductionGpoTests.create
    envelope = ProductionGpoTests.envelope
    poll = ProductionGpoTests.poll
    exchange = ProductionGpoTests.exchange
    inspect = ProductionGpoTests.inspect
    snapshot = ProductionGpoTests.snapshot
    report_success = ProductionGpoTests.report_success
    change = ProductionGpoTests.change
    approve = ProductionGpoTests.approve
    execute = ProductionGpoTests.execute
    _parallel = approval_tests.PortalApprovalRaceTests._parallel

    def test_concurrent_approved_claims_still_grant_one_write(self):
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        job = self.change(inspection)
        self.assertIsNotNone(GpoImportJob.objects.get(pk=job['job_id']).approved_at)
        def claim():
            return self.exchange(job, 'claim')['gpo_claim']['mode']
        self.assertEqual(sorted(self._parallel(claim, claim)), ['execute', 'observe'])

    def test_concurrent_mutation_requests_from_one_inspection_have_one_domain_fence(self):
        from rest_framework.test import APIClient
        from django.contrib.auth import get_user_model
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        def prepare():
            client = APIClient()
            client.force_authenticate(get_user_model().objects.get(pk=self.user.pk))
            client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
            return client.post(self.base + 'managed-gpos/', {'preflight_id': inspection['job_id'],
                'idempotency_key': str(uuid.uuid4()), 'safety_review': {'management_access': False, 'recovery_access': False}},
                format='json').status_code
        self.assertEqual(sorted(self._parallel(prepare, prepare)), [202, 409])


class CompactNamesTests(SimpleTestCase):
    def test_vendor_component_aliases_are_unique_within_scope_and_baseline(self):
        from .gpo_content import COMPONENTS
        seen = set()
        for (baseline, _), component in COMPONENTS.items():
            alias = compact_purpose(baseline, component)
            identity = (baseline, component['scope'], alias)
            self.assertNotIn(identity, seen, identity)
            seen.add(identity)
            self.assertNotIn('Pilot', alias)
            self.assertLessEqual(len(alias), 80)
