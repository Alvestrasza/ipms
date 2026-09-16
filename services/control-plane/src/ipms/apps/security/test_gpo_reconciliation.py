# File Name: test_gpo_reconciliation.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Public reconciliation authority, immutable evidence, fence release and recovery upgrades.
import copy
import hashlib
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase, TransactionTestCase, skipUnlessDBFeature
from django.utils import timezone

from ipms.apps.agent_pki.lifecycle import create_lifecycle_job, lifecycle_artifact, offer_lifecycle_job, record_lifecycle_result
from ipms.apps.agent_pki.models import AgentEnrollment, AgentLifecycleJob
from . import test_gpo_production as production_tests
from .gpo_jobs import digest, security_gpo_exchange
from .gpo_production import IMPORT, IMPORT_LINK
from .models import DomainSecuritySettings, GpoApprovalPolicy, GpoExecutorReport, GpoImportJob, GpoReconciliation, ManagedGpoPolicy
from .test_gpo_jobs import PILOT_GUID

JOURNAL = 'a' * 64


class GpoReconciliationTests(TestCase):
    # Reuse only fixture helpers, never inherit the unrelated production test cases.
    for _name in ('setUp', 'draft', 'create', 'envelope', 'exchange', 'result', 'approve', 'grants', 'policy',
                  'poll', 'inspect', 'legacy_queue', 'snapshot', 'gpo', 'report_success', 'change', 'execute', 'linked_state', 'agent_036'):
        locals()[_name] = getattr(production_tests.ProductionGpoTests, _name)
    del _name

    def failed_gpo(self, *, known=True):
        self.agent_036()
        inspection = self.inspect(IMPORT_LINK)
        self.report_success(inspection, self.snapshot(inspection))
        assignment = self.change(inspection)
        self.execute(assignment)
        self.result(assignment, status='requires_reconciliation', guid=PILOT_GUID if known else None)
        self.system.agent_version = '0.2.37'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.37')
        self.job = GpoImportJob.objects.get(pk=assignment['job_id'])
        self.url = '/api/v1/security/gpo-imports/' + str(self.job.pk) + '/reconciliations/'
        self.observation = {'schema': 1, 'state': self.snapshot(assignment, self.gpo(assignment)), 'forest_links': [],
            'forest_complete': True, 'acl_consistent': True, 'gpo_presence': 'present', 'issues': [],
            'gpo_guid': PILOT_GUID, 'quiescent': True}
        return assignment

    def request_reconciliation(self):
        identifier = str(uuid.uuid4())
        response = self.client.post(self.url, {'idempotency_key': identifier, 'input_digest': self.job.input_digest}, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(response.data['latest']['id'], identifier)
        self.record = GpoReconciliation.objects.get(pk=identifier)
        return response

    def wire(self, action, **changes):
        fields = {'job_id': str(self.job.pk), 'input_digest': self.job.input_digest, 'journal_sha256': JOURNAL}
        if action == 'reconciliation_poll':
            fields.update(agent_version='0.2.37', executor=self.report)
        else:
            fields.update(reconciliation_id=str(self.record.pk), observation_digest=digest(self.observation))
            if action == 'reconciliation_result':
                fields['observation'] = self.observation
        return security_gpo_exchange(self.agent, self.envelope(action, **{**fields, **changes}))['reconciliation']

    def observed(self):
        self.request_reconciliation()
        control = self.wire('reconciliation_poll')
        self.assertEqual(control['mode'], 'observe')
        self.assertEqual(control['observation_digest'], '')
        self.assertIsNone(self.wire('reconciliation_result'))
        self.record.refresh_from_db()

    def accept(self):
        return self.client.post(self.url + str(self.record.pk) + '/accept/',
            {'observation_digest': digest(self.observation)}, format='json')

    def test_one_observation_explicit_accept_and_ack_release_preserve_original_receipt(self):
        assignment = self.failed_gpo()
        original = {field: getattr(self.job, field) for field in ('assignment', 'input_digest', 'gpo_guid', 'result_digest', 'error_code', 'result_evidence')}
        self.observed()
        self.assertIsNone(self.wire('reconciliation_poll'))
        self.assertTrue(self.client.get(self.url).data['latest']['can_accept'])
        self.assertEqual(self.accept().status_code, 202)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')
        control = self.wire('reconciliation_poll')
        self.assertEqual(control['mode'], 'accept')
        self.assertEqual(control['observation_digest'], digest(self.observation))
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        self.job.refresh_from_db()
        self.managed.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciled')
        self.assertEqual({field: getattr(self.job, field) for field in original}, original)
        self.assertEqual(self.managed.state, 'new')
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)
        self.assertIsNone(self.managed.staged_job_id)
        self.assertIsNone(self.managed.active_job_id)
        self.assertFalse(self.client.get(self.url).data['can_request'])
        self.result(assignment, status='requires_reconciliation', guid=PILOT_GUID)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciled')
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        next_inspection = self.inspect(IMPORT)
        self.assertEqual(next_inspection['gpo_guid'], PILOT_GUID)
        self.assertEqual(ManagedGpoPolicy.objects.count(), 1)
        logs = self.client.get('/api/v1/logs/baselines/', {'kind': 'gpo_import', 'status': 'reconciled'})
        self.assertEqual(logs.status_code, 200)
        self.assertEqual(logs.data['count'], 1)

    def test_partial_create_guid_is_derived_from_original_enrollment_journal_only(self):
        self.failed_gpo(known=False)
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.gpo_guid, PILOT_GUID)

    def test_unknown_guid_active_unowned_incomplete_and_inconsistent_states_are_not_accepted(self):
        self.failed_gpo()
        original = copy.deepcopy(self.observation)
        mutations = [(lambda v: v.update(quiescent=False), 'observation_unverifiable'),
            (lambda v: v.update(forest_complete=False), 'forest_incomplete'),
            (lambda v: v.update(acl_consistent=False), 'acl_inconsistent'),
            (lambda v: v['state']['gpo'].update(description='Foreign'), 'ownership_unverified'),
            (lambda v: v['state']['gpo'].update(computer_enabled=True), 'gpo_not_disabled'),
            (lambda v: v['state']['gpo'].update(computer_sysvol=2), 'state_inconsistent'),
            (lambda v: v.update(issues=['gpo_preflight_required']), 'observation_issues')]
        for mutate, reason in mutations:
            with self.subTest(reason=reason):
                self.observation = copy.deepcopy(original)
                mutate(self.observation)
                self.observed()
                state = self.client.get(self.url).data['latest']
                self.assertEqual(state['accept_blocked_reason'], reason)
                self.assertFalse(state['can_accept'])
                self.assertEqual(self.accept().status_code, 409)
                GpoReconciliation.objects.filter(pk=self.record.pk).update(status='stale')
        self.observation = {**original, 'gpo_guid': '', 'state': None, 'gpo_presence': 'unknown',
                            'issues': ['gpo_reconciliation_guid_unknown']}
        self.observed()
        self.assertEqual(self.client.get(self.url).data['latest']['accept_blocked_reason'], 'unknown_guid')
        self.assertEqual(self.accept().status_code, 409)

    def test_bounded_diagnostics_remain_visible_without_releasing_fence(self):
        self.failed_gpo()
        self.observation['issues'] = ['gpo_reconciliation_gpo_open_failed', 'gpo_reconciliation_hresult_80070005']
        self.observed()
        state = self.client.get(self.url).data['latest']
        self.assertEqual(state['issues'], self.observation['issues'])
        self.assertFalse(state['can_accept'])
        self.assertEqual(self.accept().status_code, 409)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_diagnostic_codes_reject_free_text_success_and_malformed_hresult(self):
        from .gpo_reconciliation import validate_observation
        self.failed_gpo()
        for code in ('gpo_reconciliation_hresult_80070005 extra', 'gpo_reconciliation_hresult_00000000',
                     'gpo_reconciliation_hresult_8007000g', 'gpo_reconciliation_hresult_800700050', 'arbitrary'):
            with self.subTest(code=code), self.assertRaises(ValidationError):
                validate_observation({**self.observation, 'issues': [code]}, self.job)

    def test_foreign_links_or_target_guid_change_cannot_release_fence(self):
        self.failed_gpo()
        foreign = {'guid': PILOT_GUID, 'domain': 'example.invalid', 'dn': 'OU=Foreign,DC=example,DC=invalid',
                   'kind': 'ou', 'enabled': False, 'enforced': False, 'order': 1}
        self.observation['forest_links'] = [foreign]
        self.observation['state']['gpo']['links'] = [foreign]
        self.observed()
        self.assertEqual(self.client.get(self.url).data['latest']['accept_blocked_reason'], 'link_scope_conflict')
        self.assertEqual(self.accept().status_code, 409)

    def test_native_drift_after_accept_is_stale_without_overwriting_original_observation(self):
        self.failed_gpo()
        self.observed()
        original = copy.deepcopy(self.observation)
        self.assertEqual(self.accept().status_code, 202)
        self.observation['state']['ous'][0]['usn'] = '999'
        self.assertIsNone(self.wire('reconciliation_result'))
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, 'stale')
        self.assertEqual(self.record.observation, original)
        self.assertEqual(self.record.drift_observation, self.observation)
        self.assertIsNone(self.wire('reconciliation_ack'))
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_digest_journal_and_extra_fields_cannot_be_substituted(self):
        self.failed_gpo()
        self.request_reconciliation()
        self.wire('reconciliation_poll')
        for changes in ({'journal_sha256': 'b' * 64}, {'observation_digest': 'b' * 64}, {'unexpected': True}):
            with self.assertRaises(ValidationError), transaction.atomic():
                self.wire('reconciliation_result', **changes)
        self.wire('reconciliation_result')
        with self.assertRaises(ValidationError), transaction.atomic():
            self.wire('reconciliation_ack')
        self.assertEqual(self.client.post(self.url + str(self.record.pk) + '/accept/',
            {'observation_digest': 'b' * 64}, format='json').status_code, 409)

    def test_idempotent_requests_and_accepts_create_one_record(self):
        self.failed_gpo()
        self.observed()
        response = self.client.post(self.url, {'idempotency_key': str(self.record.pk), 'input_digest': self.job.input_digest}, format='json')
        self.assertEqual(response.status_code, 202)
        self.assertEqual(GpoReconciliation.objects.count(), 1)
        self.assertEqual(self.accept().status_code, 202)
        decision = GpoReconciliation.objects.get(pk=self.record.pk).decision_digest
        self.assertEqual(self.accept().status_code, 202)
        self.assertEqual(GpoReconciliation.objects.get(pk=self.record.pk).decision_digest, decision)

    def test_optional_four_eyes_and_revocation_are_checked_again_before_ack(self):
        self.failed_gpo()
        self.assertEqual(self.policy(True).status_code, 200)
        self.assertEqual(self.grants().status_code, 200)
        self.observed()
        self.assertEqual(self.accept().status_code, 403)
        self.client.force_authenticate(self.approver)
        self.assertEqual(self.accept().status_code, 202)
        self.client.force_authenticate(self.user)
        self.assertEqual(self.grants([{'user_id': str(self.user.pk), 'tiers': ['1']}]).status_code, 200)
        self.assertIsNone(self.wire('reconciliation_ack'))
        self.job.refresh_from_db()
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, 'stale')
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_expired_original_job_does_not_expire_fresh_reconciliation(self):
        self.failed_gpo()
        self.observed()
        future = timezone.now() + timedelta(hours=1)
        # Only the source deadline is expired; the new authority is independently bounded.
        with patch('ipms.apps.security.gpo_jobs.timezone.now', return_value=future):
            GpoReconciliation.objects.filter(pk=self.record.pk).update(expires_at=future + timedelta(minutes=10))
            self.system.last_seen_at = future
            self.agent.last_heartbeat_at = future
            self.agent.save(update_fields=('last_heartbeat_at',))
            GpoExecutorReport.objects.filter(enrollment=self.agent).update(observed_at=future)
            self.assertEqual(self.accept().status_code, 202)

    def test_expiry_prevents_ack_but_released_receipt_survives_expiry_and_revocation(self):
        self.failed_gpo()
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        GpoReconciliation.objects.filter(pk=self.record.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.grants([]).status_code, 200)
        self.assertEqual(self.wire('reconciliation_poll')['mode'], 'released')

    def test_forward_update_bootstrap_requires_native_terminal_receipt_and_pinned_artifact(self):
        self.failed_gpo()
        self.system.agent_version = '0.2.36'
        self.system.save(update_fields=('agent_version',))
        binary = b'bounded signed-package fixture'
        artifact = hashlib.sha256(binary).hexdigest()
        with patch('ipms.apps.agent_pki.lifecycle.current_windows_agent_artifact', return_value=('0.2.37', binary, artifact)):
            lifecycle = create_lifecycle_job(enrollment=self.agent, action='update', actor=self.user.username)
            self.assertEqual(offer_lifecycle_job(self.agent)['job_id'], str(lifecycle.pk))
            self.assertEqual(lifecycle_artifact(self.agent, job_id=str(lifecycle.pk)), (binary, artifact))
            original = self.job.result_digest
            for invalid in ('', 'c' * 64):
                GpoImportJob.objects.filter(pk=self.job.pk).update(result_digest=invalid)
                self.assertIsNone(offer_lifecycle_job(self.agent))
                with self.assertRaises(ValidationError), transaction.atomic():
                    lifecycle_artifact(self.agent, job_id=str(lifecycle.pk))
                with self.assertRaises(ValidationError), transaction.atomic():
                    record_lifecycle_result(self.agent, job_id=str(lifecycle.pk), result='running', result_code='started')
            GpoImportJob.objects.filter(pk=self.job.pk).update(result_digest=original)
            # A later server withdrawal reason must not erase proof that the old Agent stopped writing.
            GpoImportJob.objects.filter(pk=self.job.pk).update(error_code='approval_configuration_changed')
            self.assertEqual(record_lifecycle_result(self.agent, job_id=str(lifecycle.pk), result='running', result_code='started').status, 'running')
            with patch('ipms.apps.agent_pki.lifecycle.current_windows_agent_artifact', return_value=('0.2.38', binary, artifact)):
                with self.assertRaises(ValidationError), transaction.atomic():
                    lifecycle_artifact(self.agent, job_id=str(lifecycle.pk))
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_update_exception_never_allows_uninstall_running_write_or_server_only_timeout(self):
        self.failed_gpo()
        self.system.agent_version = '0.2.36'
        self.system.save(update_fields=('agent_version',))
        binary = b'bounded artifact'
        with patch('ipms.apps.agent_pki.lifecycle.current_windows_agent_artifact', return_value=('0.2.37', binary, hashlib.sha256(binary).hexdigest())):
            with self.assertRaises(ValidationError), transaction.atomic():
                create_lifecycle_job(enrollment=self.agent, action='uninstall', actor=self.user.username)
            for values in ({'status': 'running'}, {'status': 'reconciliation_required', 'result_digest': ''}):
                GpoImportJob.objects.filter(pk=self.job.pk).update(**values)
                with self.assertRaises(ValidationError), transaction.atomic():
                    create_lifecycle_job(enrollment=self.agent, action='update', actor=self.user.username)

    def test_explicit_new_read_supersedes_observed_but_not_accept_requested(self):
        self.failed_gpo()
        self.observed()
        previous = self.record
        self.assertTrue(self.client.get(self.url).data['can_request'])
        self.observed()
        previous.refresh_from_db()
        self.assertEqual(previous.status, 'stale')
        self.assertEqual(previous.observation, self.observation)
        self.assertNotEqual(previous.pk, self.record.pk)
        self.assertEqual(self.accept().status_code, 202)
        self.assertFalse(self.client.get(self.url).data['can_request'])
        response = self.client.post(self.url, {'idempotency_key': str(uuid.uuid4()), 'input_digest': self.job.input_digest}, format='json')
        self.assertEqual(response.status_code, 409)

    def test_expired_acceptance_is_stale_and_keeps_original_domain_fence(self):
        self.failed_gpo()
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        GpoReconciliation.objects.filter(pk=self.record.pk).update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(self.wire('reconciliation_ack'))
        self.job.refresh_from_db()
        self.record.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')
        self.assertEqual(self.record.status, 'stale')
        self.assertTrue(self.client.get(self.url).data['can_request'])

    def test_authority_withdrawal_reason_is_not_erased_by_original_agent_replay(self):
        assignment = self.failed_gpo()
        self.observed()
        GpoImportJob.objects.filter(pk=self.job.pk).update(error_code='password_changed')
        self.result(assignment, status='requires_reconciliation', guid=PILOT_GUID)
        self.job.refresh_from_db()
        self.assertEqual(self.job.error_code, 'password_changed')
        self.assertIsNone(self.wire('reconciliation_poll'))
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, 'stale')
        self.assertFalse(AgentLifecycleJob.objects.exists())

    def test_pending_database_constraint_prevents_two_observation_authorities(self):
        self.failed_gpo()
        self.observed()
        values = {field.attname: getattr(self.record, field.attname) for field in GpoReconciliation._meta.concrete_fields}
        values['id'] = uuid.uuid4()
        with self.assertRaises(IntegrityError), transaction.atomic():
            GpoReconciliation.objects.create(**values)
        self.assertEqual(GpoReconciliation.objects.count(), 1)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_changed_acceptance_digest_becomes_stale_before_native_release(self):
        self.failed_gpo()
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        GpoReconciliation.objects.filter(pk=self.record.pk).update(decision_digest='f' * 64)
        self.assertIsNone(self.wire('reconciliation_poll'))
        self.record.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(self.record.status, 'stale')
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_another_enrollment_cannot_observe_the_original_journal(self):
        self.failed_gpo()
        self.request_reconciliation()
        other = AgentEnrollment.objects.create(tenant=self.tenant, platform='windows', status='active',
            device_uri='urn:ipms:agent:' + str(uuid.uuid4()))
        document = self.envelope('reconciliation_poll', job_id=str(self.job.pk), input_digest=self.job.input_digest,
            journal_sha256=JOURNAL, agent_version='0.2.37', executor=self.report)
        document['device_uri'] = other.device_uri
        with self.assertRaises(ValidationError), transaction.atomic():
            security_gpo_exchange(other, document)
        self.record.refresh_from_db()
        self.assertEqual(self.record.journal_sha256, '')

    def test_original_four_eyes_cannot_be_weakened_by_current_single_admin_rule(self):
        self.failed_gpo()
        GpoImportJob.objects.filter(pk=self.job.pk).update(four_eyes_required=True)
        self.assertFalse(GpoApprovalPolicy.objects.filter(tenant=self.tenant, four_eyes_required=True).exists())
        self.observed()
        self.record.refresh_from_db()
        self.assertTrue(self.record.four_eyes_required)
        self.assertEqual(self.accept().status_code, 403)

    def test_reconciled_legacy_adoption_reuses_managed_marker_and_guid(self):
        legacy = self.legacy_queue()
        self.assertEqual(self.approve(legacy).status_code, 200)
        self.assertTrue(self.exchange(legacy, 'claim')['gpo_claim']['authorized'])
        self.result(legacy, status='staged', code='gpo_staged_unlinked', guid=PILOT_GUID, evidence={
            'computer_enabled': False, 'user_enabled': False, 'unlinked': True,
            'domain_dns_name': 'example.invalid', 'domain_guid': self.report['domain_guid'], 'dc_fqdn': self.system.fqdn})
        self.agent_036()
        inspected = self.inspect(IMPORT_LINK, adopt_job_id=legacy['job_id'])
        old = self.gpo(inspected)
        old.update(name=legacy['pilot_display_name'], description=inspected['owner_marker'])
        self.report_success(inspected, self.snapshot(inspected, old))
        assignment = self.change(inspected)
        self.execute(assignment)
        self.result(assignment, status='requires_reconciliation', guid=PILOT_GUID)
        self.system.agent_version = '0.2.37'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.37')
        self.job = GpoImportJob.objects.get(pk=assignment['job_id'])
        self.url = '/api/v1/security/gpo-imports/' + str(self.job.pk) + '/reconciliations/'
        self.observation = {'schema': 1, 'state': self.snapshot(assignment, self.gpo(assignment)), 'forest_links': [],
            'forest_complete': True, 'acl_consistent': True, 'gpo_presence': 'present', 'issues': [],
            'gpo_guid': PILOT_GUID, 'quiescent': True}
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        self.managed.refresh_from_db()
        self.assertEqual(str(self.managed.origin_job_id), legacy['job_id'])
        next_request = self.inspect(IMPORT)
        self.assertEqual(next_request['gpo_guid'], PILOT_GUID)
        self.assertEqual(next_request['owner_marker'], 'IPMS managed GPO; id=' + str(self.managed.pk))

    def test_recovery_update_does_not_allow_downgrade_or_nonterminal_failure_receipt(self):
        self.failed_gpo()
        binary = b'bounded artifact'
        for target in ('0.2.36', '0.2.37'):
            with patch('ipms.apps.agent_pki.lifecycle.current_windows_agent_artifact', return_value=(target, binary, hashlib.sha256(binary).hexdigest())):
                with self.assertRaises(ValidationError), transaction.atomic():
                    create_lifecycle_job(enrollment=self.agent, action='update', actor=self.user.username)
        self.system.agent_version = '0.2.36'
        self.system.save(update_fields=('agent_version',))
        GpoImportJob.objects.filter(pk=self.job.pk).update(result_digest=digest({
            'status': 'failed', 'result_code': self.job.error_code, 'gpo_guid': self.job.gpo_guid, 'evidence': None}))
        with patch('ipms.apps.agent_pki.lifecycle.current_windows_agent_artifact', return_value=('0.2.37', binary, hashlib.sha256(binary).hexdigest())):
            with self.assertRaises(ValidationError), transaction.atomic():
                create_lifecycle_job(enrollment=self.agent, action='update', actor=self.user.username)

    def test_accepting_user_deleted_before_ack_cannot_release_fence(self):
        self.failed_gpo()
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        identity = str(self.user.pk)
        self.user.delete()
        self.assertIsNone(self.wire('reconciliation_ack'))
        self.record.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(self.record.accepted_actor, identity)
        self.assertIsNone(self.record.accepted_by_id)
        self.assertEqual(self.record.status, 'stale')
        self.assertEqual(self.job.status, 'reconciliation_required')

    def test_accepting_user_deleted_after_ack_does_not_break_released_recovery(self):
        self.failed_gpo()
        self.observed()
        self.assertEqual(self.accept().status_code, 202)
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        identity = str(self.user.pk)
        self.user.delete()
        self.assertEqual(self.wire('reconciliation_poll')['mode'], 'released')
        self.assertEqual(self.wire('reconciliation_ack')['mode'], 'released')
        self.record.refresh_from_db()
        self.assertEqual(self.record.accepted_actor, identity)
        self.assertIsNone(self.record.accepted_by_id)
        self.assertEqual(self.record.status, 'accepted')


@skipUnlessDBFeature('has_select_for_update')
class GpoReconciliationRaceTests(TransactionTestCase):
    for _name, _value in GpoReconciliationTests.__dict__.items():
        if callable(_value) and not _name.startswith(('test_', '_')):
            locals()[_name] = _value
    del _name, _value

    def test_accept_and_new_observation_cannot_both_acquire_authority(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from django.contrib.auth import get_user_model
        from django.db import connections
        from rest_framework.test import APIClient
        self.failed_gpo()
        self.observed()
        barrier = Barrier(2)

        def post(accepting):
            try:
                client = APIClient()
                client.force_authenticate(get_user_model().objects.get(pk=self.user.pk))
                client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
                barrier.wait(timeout=15)
                path = self.url + str(self.record.pk) + '/accept/' if accepting else self.url
                body = {'observation_digest': digest(self.observation)} if accepting else {
                    'idempotency_key': str(uuid.uuid4()), 'input_digest': self.job.input_digest}
                response = client.post(path, body, format='json')
                return response.status_code, response.data
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(post, (True, False)))
        self.assertEqual(sorted(status for status, _ in results), [202, 409], results)
        self.assertEqual(GpoReconciliation.objects.filter(status__in=('requested', 'observed', 'accept_requested')).count(), 1)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, 'reconciliation_required')
