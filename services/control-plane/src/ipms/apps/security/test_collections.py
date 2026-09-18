# File Name: test_collections.py
# Version: v0.1.0 | Created: 2026-09-18 | Last Modified: 2026-09-18
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Device membership and ordered multi-domain policy collection contracts.
import copy
import uuid
from unittest.mock import patch

from django.test import TestCase

from .collections import refresh_deployment
from .gpo_content import COMPONENTS, PROFILE_COMPONENTS
from .gpo_jobs import security_gpo_exchange
from .gpo_production import IMPORT_LINK, SUCCESS
from .models import GpoDomainAuthorization, GpoExecutorReport, GpoImportJob, GpoOverride, PolicyCollectionDeployment
from . import test_domains, test_gpo_approvals, test_gpo_jobs
from .test_gpo_jobs import DOMAIN_GUID, PILOT_GUID, SERVER


class CollectionTests(TestCase):
    draft = test_domains.DomainSettingsTests.draft
    create = test_domains.DomainSettingsTests.create
    envelope = test_gpo_jobs.GpoJobTests.envelope
    poll = test_gpo_jobs.GpoJobTests.poll
    exchange = test_gpo_jobs.GpoJobTests.exchange

    def setUp(self):
        test_gpo_approvals.PortalApprovalTests.setUp(self)
        components = {**COMPONENTS, (SERVER, self.selection['backup_id']): self.component}
        for target, value in (
            ('ipms.apps.security.collections._content', (components, PROFILE_COMPONENTS)),
            ('ipms.apps.security.gpo_production._content', (components, PROFILE_COMPONENTS)),
            ('ipms.apps.security.gpo_production.artifact_bytes', self.bundle),
        ):
            mock = patch(target, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)
        self.system.agent_version = '0.2.47'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.47')
        self.grants()

    def grants(self):
        GpoDomainAuthorization.objects.filter(domain_id=self.config['id']).update(
            grants=[{'user_id': str(self.user.pk), 'tiers': ['0', '1', '2']}])

    def test_device_collection_unions_direct_members_and_bounded_inventory_rules(self):
        response = self.client.post('/api/v1/security/device-collections/', {
            'name': 'Windows servers', 'description': 'Managed server estate',
            'static_system_ids': [str(self.system.pk)],
            'rules': [{'domain_name': 'example.invalid', 'operating_system_role': 'domain-controller'}],
        }, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        self.assertEqual(response.data['member_count'], 1)
        self.assertEqual(response.data['members'][0]['id'], str(self.system.pk))
        collection_id = response.data['id']
        update = {
            'name': 'Domain controllers', 'description': '', 'static_system_ids': [],
            'rules': [{'operating_system_role': 'domain-controller'}], 'expected_revision': 1,
        }
        saved = self.client.put(f'/api/v1/security/device-collections/{collection_id}/', update, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        self.assertEqual(saved.data['revision'], 2)
        self.assertEqual(saved.data['member_count'], 1)
        self.assertEqual(self.client.put(f'/api/v1/security/device-collections/{collection_id}/', update, format='json').status_code, 409)

    def snapshot(self, assignment, gpo=None):
        return {'schema': 1, 'domain_admins_sid': 'S-1-5-21-1-2-3-512',
                'gpo': copy.deepcopy(gpo), 'name_available': True, 'ous': [
            {'dn': dn, 'guid': str(uuid.UUID(int=index + 10)), 'usn': '10', 'blocked': False,
             'links': [], 'inherited_links': []} for index, dn in enumerate(assignment['target_ous'])]}

    def report_success(self, assignment, state):
        evidence = {'schema': 3, 'operation': assignment['operation'], 'managed_id': assignment['managed_id'],
                    'state': state,
                    'prepared_artifact_sha256': assignment['artifact_sha256'] if assignment['operation'] == IMPORT_LINK else '',
                    'backup_id': '', 'backup_manifest_sha256': ''}
        return self.exchange(assignment, 'result', status=SUCCESS[assignment['operation']][0],
                             result_code=SUCCESS[assignment['operation']][1],
                             gpo_guid=state['gpo']['guid'] if state['gpo'] else None, evidence=evidence)

    def gpo(self, assignment):
        return {'guid': PILOT_GUID, 'name': assignment['pilot_display_name'],
                'description': 'IPMS managed GPO; id=' + assignment['managed_id'],
                'computer_enabled': False, 'user_enabled': False,
                'computer_ds': 1, 'computer_sysvol': 1, 'user_ds': 0, 'user_sysvol': 0,
                'owner_sid': 'S-1-5-21-1-2-3-512', 'security_digest': 'a' * 64,
                'wmi_filter': '', 'links': []}

    def linked_state(self, assignment, before):
        state = copy.deepcopy(before)
        state['gpo'] = self.gpo(assignment)
        for index, ou in enumerate(state['ous']):
            link = {'guid': PILOT_GUID, 'domain': 'example.invalid', 'dn': ou['dn'], 'kind': 'ou',
                    'enabled': False, 'enforced': False, 'order': assignment['link_orders'][index]}
            ou['links'] = [link]
            ou['usn'] = '11'
            state['gpo']['links'].append(link)
        return state

    def test_policy_collection_runs_one_click_inspection_and_write_then_advances_order(self):
        machine_ids = [value for value in PROFILE_COMPONENTS[(SERVER, 'server')]
                       if COMPONENTS[(SERVER, value)]['scope'] == 'machine']
        self.assertGreaterEqual(len(machine_ids), 2)
        # The test's pinned synthetic component covers the first selected package.
        second = copy.deepcopy(COMPONENTS[(SERVER, machine_ids[1])])
        second.update(artifact_sha256=self.component['artifact_sha256'], artifact_size=len(self.bundle), files=self.component['files'])
        components = {**COMPONENTS, (SERVER, self.selection['backup_id']): self.component,
                      (SERVER, machine_ids[1]): second}
        for target in ('ipms.apps.security.collections._content', 'ipms.apps.security.gpo_production._content'):
            mock = patch(target, return_value=(components, PROFILE_COMPONENTS))
            mock.start()
            self.addCleanup(mock.stop)
        entries = [{
            'source': 'baseline', 'baseline_id': SERVER, 'backup_id': backup_id,
            'target': 'ALL', 'version': '1.0.0', 'override_id': None,
        } for backup_id in (self.selection['backup_id'], machine_ids[1])]
        created = self.client.post('/api/v1/security/policy-collections/', {
            'name': 'Tier 1 server standard', 'description': 'Ordered server policies', 'entries': entries,
            'bindings': [{'domain_id': self.config['id'], 'tier': '1',
                          'target_ous': [self.config['tier_ous']['1'][0]]}],
        }, format='json')
        self.assertEqual(created.status_code, 201, created.data)
        collection_id = created.data['id']
        preview = self.client.get(f'/api/v1/security/policy-collections/{collection_id}/preview/')
        self.assertEqual(preview.status_code, 200)
        self.assertTrue(preview.data['ready'])
        self.assertEqual(len(preview.data['items']), 2)

        request_id = str(uuid.uuid4())
        deployed = self.client.post(f'/api/v1/security/policy-collections/{collection_id}/deployments/', {
            'expected_revision': 1, 'idempotency_key': request_id,
        }, format='json')
        self.assertEqual(deployed.status_code, 202, deployed.data)
        self.assertEqual([row['status'] for row in deployed.data['items']], ['preparing', 'pending'])
        self.assertEqual(GpoImportJob.objects.count(), 1)

        deployment = PolicyCollectionDeployment.objects.get(pk=request_id)
        first = deployment.items.get(policy_index=0)
        inspection = first.preflight_job.assignment
        self.report_success(inspection, self.snapshot(inspection))
        first.refresh_from_db()
        self.assertIsNotNone(first.write_job_id)
        self.assertEqual(first.status, 'running')

        write = first.write_job.assignment
        self.assertTrue(self.exchange(write, 'claim')['gpo_claim']['authorized'])
        self.report_success(write, self.linked_state(write, self.snapshot(write)))
        first.refresh_from_db()
        second_item = deployment.items.get(policy_index=1)
        second_item.refresh_from_db()
        self.assertEqual(first.status, 'succeeded')
        self.assertEqual(second_item.status, 'preparing')
        self.assertIsNotNone(second_item.preflight_job_id)

        retry = self.client.post(f'/api/v1/security/policy-collections/{collection_id}/deployments/', {
            'expected_revision': 1, 'idempotency_key': request_id,
        }, format='json')
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.data['id'], request_id)

    def test_policy_collection_rejects_cross_tenant_device_and_unconfigured_targets(self):
        device = self.client.post('/api/v1/security/device-collections/', {
            'name': 'Invalid', 'description': '', 'static_system_ids': [str(uuid.uuid4())], 'rules': [],
        }, format='json')
        self.assertEqual(device.status_code, 400)
        entry = {'source': 'baseline', 'baseline_id': SERVER, 'backup_id': self.selection['backup_id'],
                 'target': 'ALL', 'version': '1.0.0', 'override_id': None}
        response = self.client.post('/api/v1/security/policy-collections/', {
            'name': 'Invalid target', 'description': '', 'entries': [entry],
            'bindings': [{'domain_id': self.config['id'], 'tier': '1',
                          'target_ous': ['OU=Foreign,DC=example,DC=invalid']}],
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_policy_collection_accepts_enabled_custom_gpo_as_distinct_source(self):
        custom = GpoOverride.objects.create(
            tenant=self.tenant, kind=GpoOverride.CUSTOM, name='Operations-Custom',
            baseline_id=SERVER, backup_id=self.selection['backup_id'],
            artifact_sha256=self.component['artifact_sha256'],
            entries=[{'setting_id': 'a' * 64, 'value': 1}],
        )
        self.system.agent_version = '0.2.48'
        self.system.save(update_fields=('agent_version',))
        GpoExecutorReport.objects.filter(enrollment=self.agent).update(agent_version='0.2.48')
        created = self.client.post('/api/v1/security/policy-collections/', {
            'name': 'Custom security policy', 'description': '',
            'entries': [{
                'source': 'custom', 'baseline_id': SERVER,
                'backup_id': self.selection['backup_id'], 'target': 'CUST',
                'version': '1.0.0', 'override_id': str(custom.pk),
            }],
            'bindings': [{
                'domain_id': self.config['id'], 'tier': '1',
                'target_ous': [self.config['tier_ous']['1'][0]],
            }],
        }, format='json')
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data['entries'][0]['source'], 'custom')
        preview = self.client.get(f"/api/v1/security/policy-collections/{created.data['id']}/preview/")
        self.assertEqual(preview.status_code, 200)
        self.assertTrue(preview.data['ready'])

    def test_policy_collection_blocks_later_policies_after_domain_failure(self):
        entry = {
            'source': 'baseline', 'baseline_id': SERVER,
            'backup_id': self.selection['backup_id'], 'target': 'ALL',
            'version': '1.0.0', 'override_id': None,
        }
        created = self.client.post('/api/v1/security/policy-collections/', {
            'name': 'Failure boundary', 'description': '',
            'entries': [entry, entry],
            'bindings': [{
                'domain_id': self.config['id'], 'tier': '1',
                'target_ous': [self.config['tier_ous']['1'][0]],
            }],
        }, format='json')
        self.assertEqual(created.status_code, 201, created.data)
        deployment_id = str(uuid.uuid4())
        deployed = self.client.post(
            f"/api/v1/security/policy-collections/{created.data['id']}/deployments/",
            {'expected_revision': 1, 'idempotency_key': deployment_id},
            format='json',
        )
        self.assertEqual(deployed.status_code, 202, deployed.data)
        deployment = PolicyCollectionDeployment.objects.get(pk=deployment_id)
        first = deployment.items.get(policy_index=0)
        first.preflight_job.status = 'failed'
        first.preflight_job.error_code = 'inspection_failed'
        first.preflight_job.save(update_fields=('status', 'error_code'))

        refresh_deployment(deployment)

        first.refresh_from_db()
        second = deployment.items.get(policy_index=1)
        deployment.refresh_from_db()
        self.assertEqual(first.status, 'failed')
        self.assertEqual(second.status, 'blocked')
        self.assertEqual(second.error_code, 'previous_policy_failed')
        self.assertEqual(deployment.status, 'failed')
