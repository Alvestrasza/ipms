# File Name: test_gpo_overrides.py
# Version: v0.1.0 | Created: 2026-09-16 | Last Modified: 2026-09-16
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant isolation, sparse value validation and complete managed override lifecycle.
import copy
import uuid
from unittest.mock import patch

from django.test import TestCase, SimpleTestCase
from rest_framework.test import APIClient

from .gpo_jobs import digest
from .gpo_production import ACTIVATE, DEACTIVATE, DELETE, IMPORT, IMPORT_LINK, LINK, SUCCESS, _orders, owner_marker
from .models import GpoImportJob, GpoOverride, GpoExecutorReport, ManagedGpoPolicy
from . import test_gpo_production as production_tests
from .gpo_override_content import OVERRIDE_COMPONENTS

URL = '/api/v1/security/overrides/'
CATALOG_URL = '/api/v1/security/override-catalog/'
CUSTOM_URL = '/api/v1/security/custom-gpos/'
CUSTOM_CATALOG_URL = '/api/v1/security/custom-gpo-catalog/'


class OverrideTests(TestCase):
    def setUp(self):
        for name in ('draft', 'create', 'envelope', 'exchange', 'result', 'approve', 'grants', 'policy', 'poll',
                     'snapshot', 'change', 'execute', 'imported', 'linked', 'linked_state', 'activated'):
            setattr(self, name, getattr(production_tests.ProductionGpoTests, name).__get__(self))
        production_tests.ProductionGpoTests.setUp(self)
        self.selection['target'] = 'OVRD'
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        self.override_component = copy.deepcopy(OVERRIDE_COMPONENTS[(self.selection['baseline_id'], self.selection['backup_id'])])
        self.override_component['artifact_sha256'] = self.component['artifact_sha256']
        patch('ipms.apps.security.gpo_override_content.OVERRIDE_COMPONENTS', {
            **OVERRIDE_COMPONENTS, (self.selection['baseline_id'], self.selection['backup_id']): self.override_component}).start()
        self.setting = next(row for row in self.override_component['settings'] if row['editable'] and row['value_type'] == 'integer')
        self.entries = [{'setting_id': self.setting['setting_id'], 'value': 1 if self.setting['baseline_value'] == 0 else 0}]
        self.override = self.create_override()

    def create_override(self, **changes):
        response = self.client.post(URL, {'name': 'Operations', 'baseline_id': self.selection['baseline_id'],
            'backup_id': self.selection['backup_id'], 'entries': self.entries, 'enabled': True, **changes}, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        return response.data

    def update_override(self, **changes):
        response = self.client.patch(URL + self.override['id'] + '/', {'expected_revision': self.override['revision'],
            'name': self.override['name'], 'enabled': self.override['enabled'], 'entries': self.override['entries'], **changes}, format='json')
        if response.status_code == 200:
            self.override = response.data
        return response

    def inspect(self, operation=IMPORT, **changes):
        if operation == DELETE:
            selection = {'revision': self.config['revision'], 'system_id': self.selection['system_id'],
                         'idempotency_key': str(uuid.uuid4()), 'operation': DELETE,
                         'managed_id': str(self.managed.pk), 'domain_root_confirmed': False, **changes}
            response = self.client.post(self.base + 'gpo-preflights/', selection, format='json')
            self.assertEqual(response.status_code, 202, response.data)
            return GpoImportJob.objects.get(pk=response.data['id']).assignment
        selection = {'override_id': self.override['id'], 'override_revision': self.override['revision'],
                     'override_sha256': self.override['sha256'], **changes}
        return production_tests.ProductionGpoTests.inspect(self, operation, **selection)

    def gpo(self, job):
        result = production_tests.ProductionGpoTests.gpo(self, job)
        result['description'] = owner_marker(job)
        return result

    def report_success(self, job, state, *, backup=False, **changes):
        operation = job['operation']
        evidence = {'schema': job['schema'], 'operation': operation, 'managed_id': job['managed_id'], 'state': state,
                    'prepared_artifact_sha256': job['artifact_sha256'] if operation in (IMPORT, IMPORT_LINK, ACTIVATE) else '',
                    'backup_id': str(uuid.UUID(int=50)) if backup else '', 'backup_manifest_sha256': 'b' * 64 if backup else ''}
        if job['schema'] == 4:
            evidence['override_sha256'] = job['override_sha256']
        return self.exchange(job, 'result', status=SUCCESS[operation][0], result_code=SUCCESS[operation][1],
                             gpo_guid=state['gpo']['guid'] if state['gpo'] else None, evidence=evidence, **changes)

    def test_sparse_config_catalog_and_revision_are_tenant_scoped(self):
        catalog = self.client.get(CATALOG_URL, {'baseline_id': self.selection['baseline_id'], 'backup_id': self.selection['backup_id']})
        self.assertEqual(catalog.status_code, 200)
        self.assertEqual(catalog.data['artifact_sha256'], self.component['artifact_sha256'])
        self.assertEqual(self.client.get(URL).data['results'], [self.override])
        body = {key: self.override[key] for key in ('id', 'revision', 'baseline_id', 'backup_id', 'artifact_sha256', 'entries')}
        self.assertEqual(self.override['sha256'], digest(body))
        response = self.update_override(entries=[{'setting_id': self.setting['setting_id'], 'value': self.setting['baseline_value']}])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['entries'], [])
        self.assertEqual(response.data['revision'], 2)
        self.assertFalse(GpoImportJob.objects.exists())
        from ipms.apps.tenancy.models import TenantMembership
        TenantMembership.objects.update_or_create(tenant=self.other, user=self.user, defaults={'role': 'tenant_admin', 'is_active': True})
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.pk))
        self.assertEqual(self.client.get(URL).data['results'], [])
        self.assertEqual(self.client.get(URL + self.override['id'] + '/').status_code, 404)

    def test_strict_values_duplicate_keys_and_cross_component_ids_rejected(self):
        for entries in ([{'setting_id': self.setting['setting_id'], 'value': True}], self.entries * 2,
                        [{'setting_id': 'a' * 64, 'value': 0}], [{'setting_id': self.setting['setting_id'], 'value': -1}],
                        [{'setting_id': self.setting['setting_id'], 'value': 2**32}],
                        [{'setting_id': self.setting['setting_id'], 'value': '1', 'value_type': 'string'}]):
            with self.subTest(entries=entries):
                self.assertEqual(self.update_override(entries=entries).status_code, 400)
        self.assertEqual(self.update_override(expected_revision=99).status_code, 409)
        self.assertEqual(self.update_override(name='').status_code, 400)
        self.assertEqual(self.update_override(name='0-C-OVRD-MS-WS2025-Defender_V1.0.0').status_code, 400)
        self.assertEqual(self.update_override(name='Contains spaces').status_code, 400)
        self.assertEqual(self.client.patch(URL + self.override['id'] + '/', {'enabled': False}, format='json').status_code, 400)
        reader = self.client
        reader.force_authenticate(self.approver)
        self.assertEqual(reader.get(URL).status_code, 403)
        self.assertEqual(reader.get(CATALOG_URL, {'baseline_id': self.selection['baseline_id'], 'backup_id': self.selection['backup_id']}).status_code, 403)

    def test_same_component_override_uses_separate_identity_and_cannot_adopt_baseline(self):
        inspected = production_tests.ProductionGpoTests.inspect(self)
        self.report_success(inspected, self.snapshot(inspected))
        baseline_policy = self.managed
        self.managed = None
        override = self.inspect()
        self.assertEqual(override['schema'], 4)
        self.assertNotEqual(override['managed_id'], inspected['managed_id'])
        self.assertEqual(override['pilot_display_name'], '1-C-OVRD-Operations_V1.0.0')
        self.assertNotEqual(self.managed.logical_key, baseline_policy.logical_key)
        self.report_success(override, self.snapshot(override))
        self.managed = baseline_policy
        response = self.client.post(self.base + 'gpo-preflights/', {**self.selection, 'idempotency_key': str(uuid.uuid4()),
            'operation': IMPORT, 'managed_id': str(baseline_policy.pk), 'adopt_job_id': None, 'override_id': self.override['id'], 'override_revision': self.override['revision'], 'override_sha256': self.override['sha256']}, format='json')
        self.assertEqual(response.status_code, 409, response.data)

    def test_full_override_lifecycle_binds_evidence_without_extra_approval(self):
        job, state = self.activated()
        self.assertEqual(job['schema'], 4)
        self.assertEqual(job['override_sha256'], self.override['sha256'])
        self.assertEqual(state['gpo']['description'], 'IPMS managed override; id=' + job['managed_id'] + '; definition=' + self.override['id'])
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'active')
        self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).approved_by_id, self.user.pk)
        self.assertEqual(self.update_override(enabled=False).status_code, 200)
        inspection = self.inspect(DEACTIVATE)
        self.assertEqual(inspection['override_sha256'], job['override_sha256'])
        self.report_success(inspection, state)
        change = self.change(inspection)
        self.execute(change)
        post = copy.deepcopy(state)
        post['gpo'].update(computer_enabled=False, user_enabled=False)
        self.report_success(change, post)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'inactive')

    def test_delete_override_gpo_removes_managed_projection_then_definition(self):
        _, state = self.activated()
        managed_id = self.managed.pk
        self.assertEqual(self.update_override(entries=[]).status_code, 200)
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        inspection = self.inspect(DELETE)
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
        response = self.client.delete(URL + self.override['id'] + '/',
            {'expected_revision': self.override['revision']}, format='json')
        self.assertEqual(response.status_code, 204, getattr(response, 'data', None))
        self.assertEqual(self.client.get(URL + self.override['id'] + '/').status_code, 404)

    def test_delete_definition_requires_current_revision_and_no_managed_gpo(self):
        self.assertEqual(self.client.delete(URL + self.override['id'] + '/',
            {'expected_revision': self.override['revision'] + 1}, format='json').status_code, 409)
        self.inspect()
        blocked = self.client.delete(URL + self.override['id'] + '/',
            {'expected_revision': self.override['revision']}, format='json')
        self.assertEqual(blocked.status_code, 409)
        self.assertEqual(blocked.data['error']['code'], 'security_override_in_use')

    def test_delete_requires_agent_0247(self):
        self.linked()
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.46')
        self.system.agent_version = '0.2.46'
        self.system.save(update_fields=('agent_version',))
        response = self.client.post(self.base + 'gpo-preflights/', {'revision': self.config['revision'],
            'system_id': self.selection['system_id'], 'idempotency_key': str(uuid.uuid4()),
            'operation': DELETE, 'managed_id': str(self.managed.pk), 'domain_root_confirmed': False}, format='json')
        self.assertEqual(response.status_code, 409)
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        response = self.client.post(self.base + 'gpo-preflights/', {'revision': self.config['revision'],
            'system_id': self.selection['system_id'], 'idempotency_key': str(uuid.uuid4()),
            'operation': DELETE, 'managed_id': str(self.managed.pk), 'domain_root_confirmed': False}, format='json')
        self.assertEqual(response.status_code, 202, response.data)

    def test_changed_override_withdraws_pending_authority_and_blocks_old_activation(self):
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        job = self.change(inspection)
        self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).status, 'queued')
        self.assertEqual(self.update_override(name='Operations-v2').status_code, 200)
        self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).status, 'failed')
        self.assertFalse(self.exchange(job, 'claim')['gpo_claim']['authorized'])

    def test_old_agents_and_empty_or_disabled_override_never_receive_jobs(self):
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.42')
        data = {**self.selection, 'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT, 'managed_id': None,
                'adopt_job_id': None, 'override_id': self.override['id'], 'override_revision': self.override['revision'], 'override_sha256': self.override['sha256']}
        self.assertEqual(self.client.post(self.base + 'gpo-preflights/', data, format='json').status_code, 409)
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        self.update_override(enabled=False)
        self.assertEqual(self.client.post(self.base + 'gpo-preflights/', data, format='json').status_code, 409)
        self.update_override(enabled=True, entries=[])
        self.assertEqual(self.client.post(self.base + 'gpo-preflights/', data, format='json').status_code, 409)
        self.assertFalse(GpoImportJob.objects.exists())

    def test_four_eyes_remains_required_for_override(self):
        self.grants()
        self.policy(True)
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        job = self.change(inspection)
        row = GpoImportJob.objects.get(pk=job['job_id'])
        self.assertEqual(row.status, 'awaiting_approval')
        detail = self.client.get('/api/v1/security/gpo-imports/' + str(row.pk) + '/').data
        self.assertEqual(detail['review']['override']['settings'][0], {
            'setting_id': self.setting['setting_id'], 'label': self.setting['label'], 'category': self.setting['category'],
            'baseline_value': self.setting['baseline_value'], 'value': self.entries[0]['value']})
        self.assertIsNone(row.approved_at)
        self.assertEqual(self.approve(job).status_code, 403)
        self.client.force_authenticate(self.approver)
        self.assertEqual(self.approve(job).status_code, 200)
        self.assertTrue(self.exchange(job, 'claim')['gpo_claim']['authorized'])

    def test_reimport_revision_stages_same_guid_then_activation_uses_exact_new_patch(self):
        _, state = self.activated()
        original_guid, original_policy = self.managed.gpo_guid, self.managed.pk
        self.update_override(name='Operations-Revised')
        inspection = self.inspect(IMPORT, version='1.1.0')
        self.report_success(inspection, self.snapshot(inspection, state['gpo']))
        job = self.change(inspection)
        self.execute(job)
        self.report_success(job, self.snapshot(job, state['gpo']))
        self.managed.refresh_from_db()
        self.assertEqual((self.managed.pk, self.managed.gpo_guid), (original_policy, original_guid))
        inspection = self.inspect(ACTIVATE, version='1.1.0')
        self.report_success(inspection, state)
        activation = self.change(inspection)
        self.assertEqual(activation['override_sha256'], self.override['sha256'])
        self.execute(activation)
        post = self.linked_state(activation, state, enabled=True)
        post['gpo'].update(name=activation['pilot_display_name'], computer_ds=3, computer_sysvol=3)
        self.report_success(activation, post, backup=True)
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'active')

    def test_changed_revision_requires_preparation_before_activation(self):
        self.linked()
        self.update_override(name='Revised')
        response = self.client.post(self.base + 'gpo-preflights/', {**self.selection, 'idempotency_key': str(uuid.uuid4()),
            'operation': ACTIVATE, 'managed_id': str(self.managed.pk), 'adopt_job_id': None, 'override_id': self.override['id'], 'override_revision': self.override['revision'], 'override_sha256': self.override['sha256']}, format='json')
        self.assertEqual(response.status_code, 409, response.data)

    def baseline_policy(self):
        return ManagedGpoPolicy.objects.create(tenant=self.tenant, domain=self.managed.domain, domain_guid=self.managed.domain_guid,
            logical_key='c'*64, tier=self.managed.tier, baseline_id=self.managed.baseline_id, profile=self.managed.profile,
            purpose=self.managed.purpose, target='ALL', gpo_guid=str(uuid.UUID(int=87)), display_name='Original baseline',
            name_key='original baseline', version='1.0.0', backup_id=self.managed.backup_id)

    def test_preflight_rejects_stale_editor_revision_or_digest(self):
        original = copy.deepcopy(self.override)
        self.update_override(name='Updated-name')
        for revision, sha in ((original['revision'], original['sha256']),
                              (self.override['revision'], original['sha256'])):
            response = self.client.post(self.base + 'gpo-preflights/', {**self.selection,
                'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT, 'managed_id': None,
                'adopt_job_id': None, 'override_id': self.override['id'],
                'override_revision': revision, 'override_sha256': sha}, format='json')
            self.assertEqual(response.status_code, 409, response.data)
            self.assertEqual(response.data['error']['code'], 'security_override_revision_changed')
        self.assertFalse(GpoImportJob.objects.exists())

    def test_priority_in_both_insertion_directions_and_activation_repair(self):
        _, state = self.linked()
        baseline = self.baseline_policy()
        own = state['ous'][0]['links'][0]
        other = {**own, 'guid': baseline.gpo_guid, 'order': 1}
        own['order'] = 2
        state['gpo']['links'][0]['order'] = 2
        state['ous'][0]['links'].insert(0, other)
        config = self.managed.domain
        self.assertEqual(_orders(self.managed, config, state), [1] * len(state['ous']))
        self.assertEqual(_orders(baseline, config, {'ous': [{'links': [own]}]}), [2])
        inspection = self.inspect(ACTIVATE)
        self.report_success(inspection, state)
        activation = self.change(inspection)
        self.assertEqual(activation['link_orders'], [1] * len(state['ous']))
        self.execute(activation)
        post = self.linked_state(activation, state, enabled=True)
        post['gpo'].update(computer_enabled=True, computer_ds=2, computer_sysvol=2)
        self.report_success(activation, post, backup=True)
        self.assertEqual(post['ous'][0]['links'][1]['guid'], baseline.gpo_guid)

    def test_sparse_override_does_not_count_as_full_baseline_assignment(self):
        from django.utils import timezone
        from .applications import BaselineApplications
        self.activated()
        applications = BaselineApplications(self.tenant, [self.system], timezone.now())
        self.assertFalse(any(applications._bindings(self.tenant).values()))

    def test_baseline_insertion_rejects_conflicting_override_precedence(self):
        from ipms.apps.core.exceptions import PublicApiError
        _, state = self.linked()
        baseline = self.baseline_policy()
        other = ManagedGpoPolicy.objects.create(tenant=self.tenant, domain=baseline.domain,
            domain_guid=baseline.domain_guid, logical_key='d' * 64, tier=baseline.tier,
            baseline_id=baseline.baseline_id, profile=baseline.profile, purpose=baseline.purpose,
            target='OTHER', gpo_guid=str(uuid.UUID(int=89)), display_name='Other baseline',
            name_key='other baseline', version='1.0.0', backup_id=baseline.backup_id)
        own = state['ous'][0]['links'][0]
        conflicting = {'ous': [{'links': [{**own, 'guid': other.gpo_guid, 'order': 1},
                                        {**own, 'order': 2}]}]}
        with self.assertRaises(PublicApiError) as raised:
            _orders(baseline, baseline.domain, conflicting)
        self.assertEqual(raised.exception.public_code, 'security_gpo_link_conflict')

    def test_baseline_activation_cannot_preserve_precedence_above_an_override(self):
        self.inspect = production_tests.ProductionGpoTests.inspect.__get__(self)
        _, state = self.linked()
        baseline = self.managed
        override = ManagedGpoPolicy.objects.create(tenant=self.tenant, domain=baseline.domain,
            domain_guid=baseline.domain_guid, logical_key='d' * 64, tier=baseline.tier,
            override_id=self.override['id'], baseline_id=baseline.baseline_id, profile=baseline.profile,
            purpose=baseline.purpose, target='ALL', gpo_guid=str(uuid.UUID(int=89)),
            display_name='Operations override', name_key='operations override', version='1.0.0',
            backup_id=baseline.backup_id)
        for ou in state['ous']:
            ou['links'].append({**ou['links'][0], 'guid': override.gpo_guid, 'order': 2})
        inspection = self.inspect(ACTIVATE)
        self.report_success(inspection, state)
        count = GpoImportJob.objects.count()
        response = self.client.post(self.base + 'managed-gpos/', {
            'preflight_id': inspection['job_id'], 'idempotency_key': str(uuid.uuid4()),
            'safety_review': {'management_access': True, 'recovery_access': True}}, format='json')
        self.assertEqual(response.status_code, 409, response.data)
        self.assertEqual(response.data['error']['code'], 'security_gpo_link_conflict')
        self.assertEqual(GpoImportJob.objects.count(), count)

    def test_override_result_requires_exact_patch_digest_and_owner(self):
        from .gpo_production import _postcondition
        from django.core.exceptions import ValidationError
        inspection = self.inspect()
        state = self.snapshot(inspection)
        row = GpoImportJob.objects.get(pk=inspection['job_id'])
        evidence = {'schema': 4, 'operation': inspection['operation'], 'managed_id': inspection['managed_id'], 'state': state,
                    'prepared_artifact_sha256': '', 'backup_id': '', 'backup_manifest_sha256': '', 'override_sha256': 'a'*64}
        with self.assertRaises(ValidationError):
            _postcondition(row, evidence, None)
        evidence['override_sha256'] = inspection['override_sha256']
        _postcondition(row, evidence, None)

    def test_claimed_edit_retains_reconciliation_fence_and_immutable_patch(self):
        from .gpo_reconciliation import _job_integrity
        inspection = self.inspect()
        self.report_success(inspection, self.snapshot(inspection))
        job = self.change(inspection)
        self.assertTrue(self.exchange(job, 'claim')['gpo_claim']['authorized'])
        self.assertEqual(self.update_override(enabled=False).status_code, 200)
        row = GpoImportJob.objects.get(pk=job['job_id'])
        self.assertEqual(row.status, 'reconciliation_required')
        self.assertEqual(row.assignment, job)
        self.assertTrue(_job_integrity(row))
        row.assignment = {**row.assignment, 'override_sha256': '0' * 64}
        self.assertFalse(_job_integrity(row))
        self.managed.refresh_from_db()
        self.assertEqual(self.managed.state, 'reconciliation_required')

    def test_configuration_permission_never_grants_domain_deployment_rights(self):
        self.grants([])
        self.create_override(name='Another-allowed-definition')
        data = {**self.selection, 'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT, 'managed_id': None,
                'adopt_job_id': None, 'override_id': self.override['id'], 'override_revision': self.override['revision'], 'override_sha256': self.override['sha256']}
        self.assertEqual(self.client.post(self.base + 'gpo-preflights/', data, format='json').status_code, 403)
        self.assertFalse(ManagedGpoPolicy.objects.exists())

    def test_activation_does_not_reorder_other_overrides_implicitly(self):
        from ipms.apps.core.exceptions import PublicApiError
        _, state = self.linked()
        baseline = self.baseline_policy()
        other_definition = GpoOverride.objects.create(tenant=self.tenant, name='Earlier override',
            baseline_id=self.override['baseline_id'], backup_id=self.override['backup_id'],
            artifact_sha256=self.override['artifact_sha256'], entries=self.entries)
        earlier = ManagedGpoPolicy.objects.create(tenant=self.tenant, domain=self.managed.domain, domain_guid=self.managed.domain_guid,
            override=other_definition, logical_key='e'*64, tier=self.managed.tier, baseline_id=self.managed.baseline_id,
            profile=self.managed.profile, purpose=self.managed.purpose, target='ALL', gpo_guid=str(uuid.UUID(int=88)),
            display_name='Earlier override', name_key='earlier override', version='1.0.0', backup_id=self.managed.backup_id)
        own = state['ous'][0]['links'][0]
        state['ous'][0]['links'] = [{**own, 'guid': baseline.gpo_guid, 'order': 1},
                                    {**own, 'guid': earlier.gpo_guid, 'order': 2}, {**own, 'order': 3}]
        with self.assertRaises(PublicApiError):
            _orders(self.managed, self.managed.domain, state, preserve_override_order=True)

    def test_session_csrf_required_for_override_mutations(self):
        client = APIClient(enforce_csrf_checks=True)
        client.force_login(self.user)
        client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
        self.assertEqual(client.post(URL, {}, format='json').status_code, 403)
        self.assertEqual(client.patch(URL + self.override['id'] + '/', {}, format='json').status_code, 403)

    def test_custom_gpo_keeps_explicit_source_value_and_is_separate_from_overrides(self):
        entry = {'setting_id': self.setting['setting_id'], 'value': self.setting['baseline_value']}
        response = self.client.post(CUSTOM_URL, {
            'name': 'Operations-Custom', 'baseline_id': self.selection['baseline_id'],
            'backup_id': self.selection['backup_id'], 'entries': [entry], 'enabled': True,
        }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        custom = response.data
        self.assertEqual(custom['kind'], GpoOverride.CUSTOM)
        self.assertEqual(custom['entries'], [entry])
        self.assertEqual(self.client.get(CUSTOM_URL).data['results'], [custom])
        self.assertEqual(self.client.get(URL).data['results'], [self.override])
        self.assertEqual(self.client.get(CUSTOM_CATALOG_URL, {
            'baseline_id': custom['baseline_id'], 'backup_id': custom['backup_id'],
        }).status_code, 200)
        self.assertFalse(GpoImportJob.objects.exists())
        updated = self.client.patch(CUSTOM_URL + custom['id'] + '/', {
            'expected_revision': custom['revision'], 'name': custom['name'],
            'entries': custom['entries'], 'enabled': False,
        }, format='json')
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data['revision'], 2)
        self.assertEqual(self.client.delete(CUSTOM_URL + custom['id'] + '/', {
            'expected_revision': 2,
        }, format='json').status_code, 204)

    def test_custom_gpo_requires_new_agent_and_uses_managed_sparse_lifecycle(self):
        entry = {'setting_id': self.setting['setting_id'], 'value': self.setting['baseline_value']}
        response = self.client.post(CUSTOM_URL, {
            'name': 'Operations-Custom', 'baseline_id': self.selection['baseline_id'],
            'backup_id': self.selection['backup_id'], 'entries': [entry], 'enabled': True,
        }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        original = self.override
        self.override = response.data
        blocked = self.client.post(self.base + 'gpo-preflights/', {
            **self.selection, 'idempotency_key': str(uuid.uuid4()), 'operation': IMPORT_LINK,
            'managed_id': None, 'adopt_job_id': None, 'override_id': self.override['id'],
            'override_revision': self.override['revision'], 'override_sha256': self.override['sha256'],
        }, format='json')
        self.assertEqual(blocked.status_code, 409, blocked.data)
        self.system.agent_version = '0.2.48'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.48')
        job = self.inspect(IMPORT_LINK)
        self.assertEqual(job['schema'], 4)
        self.assertEqual(job['override_entries'], [entry])
        self.assertEqual(self.client.delete(CUSTOM_URL + self.override['id'] + '/', {
            'expected_revision': self.override['revision'],
        }, format='json').status_code, 409)
        self.override = original


class OverrideValueTests(SimpleTestCase):
    def test_entry_count_is_bounded_before_equal_values_are_removed(self):
        from rest_framework.exceptions import ParseError
        from .gpo_overrides import normalize_entries
        settings = [{'setting_id': f'{index:064x}', 'editable': True, 'value_type': 'integer',
                     'kind': 'registry', 'baseline_value': 0} for index in range(129)]
        entries = [{'setting_id': setting['setting_id'], 'value': 0} for setting in settings]
        self.assertEqual(normalize_entries({'settings': settings}, entries[:128]), [])
        with self.assertRaises(ParseError):
            normalize_entries({'settings': settings}, entries)

    def test_transport_budget_counts_utf8_bytes_and_accepts_exact_limit(self):
        from rest_framework.exceptions import ParseError
        from .gpo_jobs import canonical
        from .gpo_overrides import normalize_entries
        settings = [{'setting_id': f'{index:064x}', 'editable': True, 'value_type': 'string',
                     'kind': 'registry', 'baseline_value': '', 'max_length': 2048} for index in range(4)]
        entries = [{'setting_id': setting['setting_id'], 'value': '\u00e9' * 900} for setting in settings]
        entries[-1]['value'] += 'x' * (8192 - len(canonical(entries)))
        self.assertEqual(len(canonical(entries)), 8192)
        self.assertEqual(normalize_entries({'settings': settings}, entries), entries)
        entries[-1]['value'] += '\u00e9'
        with self.assertRaises(ParseError):
            normalize_entries({'settings': settings}, entries)

    def test_every_editable_catalog_baseline_value_normalizes_to_no_override(self):
        from .gpo_overrides import normalize_entries
        for component in OVERRIDE_COMPONENTS.values():
            for setting in component['settings']:
                if setting['editable']:
                    with self.subTest(baseline=component['baseline_id'], setting=setting['setting_id']):
                        self.assertEqual(normalize_entries(component, [{'setting_id': setting['setting_id'],
                            'value': setting['baseline_value']}]), [])

    def test_privilege_principals_and_text_have_bounded_canonical_types(self):
        from rest_framework.exceptions import ParseError
        from .gpo_overrides import normalize_entries
        component = next(c for c in OVERRIDE_COMPONENTS.values() if any(s['kind'] == 'privilege_right' for s in c['settings']))
        setting = next(s for s in component['settings'] if s['kind'] == 'privilege_right')
        for value in (['Administrator'], ['*S-1-5-32-544'], ['S-1-5-4294967296'], ['S-1-5-32-544'] * 2, ['S-1-5-32-544\nInjected=1']):
            with self.subTest(value=value), self.assertRaises(ParseError):
                normalize_entries(component, [{'setting_id': setting['setting_id'], 'value': value}])
        component = next(c for c in OVERRIDE_COMPONENTS.values() if any(s['editable'] and s['value_type'] == 'string' for s in c['settings']))
        setting = next(s for s in component['settings'] if s['editable'] and s['value_type'] == 'string')
        for value in ('line\nInjected=1', 'nul\x00', 'X' * (setting['max_length'] + 1), 1):
            with self.subTest(value=str(value)[:30]), self.assertRaises(ParseError):
                normalize_entries(component, [{'setting_id': setting['setting_id'], 'value': value}])

    def test_special_commands_and_excess_payload_are_rejected(self):
        from rest_framework.exceptions import ParseError
        from .gpo_overrides import normalize_entries
        component = next(c for c in OVERRIDE_COMPONENTS.values() if any(not s['editable'] for s in c['settings']))
        setting = next(s for s in component['settings'] if not s['editable'])
        with self.assertRaises(ParseError):
            normalize_entries(component, [{'setting_id': setting['setting_id'], 'value': setting['baseline_value']}])
        settings = [{'setting_id': str(index), 'editable': True, 'value_type': 'string', 'kind': 'registry',
                     'baseline_value': '', 'max_length': 2048, 'enum_options': []} for index in range(10)]
        with self.assertRaises(ParseError):
            normalize_entries({'settings': settings}, [{'setting_id': s['setting_id'], 'value': 'x' * 2048} for s in settings])
