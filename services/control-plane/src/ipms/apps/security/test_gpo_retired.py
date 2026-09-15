# File Name: test_gpo_retired.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Bounded, non-executing settlement of explicitly retired unclaimed legacy GPO journals.
import uuid
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import Tenant
from .gpo_jobs import security_gpo_exchange
from .models import GpoExecutorReport, GpoImportJob


class RetiredGpoJobTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug='retired-gpo', display_name='Retired GPO fixture')
        self.enrollment = AgentEnrollment.objects.create(tenant=self.tenant, platform='windows', status='active',
            device_uri=f'urn:ipms:agent:{uuid.uuid4()}', display_name='retired-journal-dc')
        self.job_id = str(uuid.uuid4())
        self.input_digest = 'a' * 64
        self.executor = {'schema': 1, 'domain_dns_name': 'example.invalid',
            'domain_guid': 'd845611c-adf3-42a4-8039-79568bdbd8bf', 'forest_dns_name': 'example.invalid',
            'dc_fqdn': 'dc.example.invalid', 'role': 'writable-domain-controller',
            'gpmc_available': True, 'result_code': 'ready_for_approval'}
        GpoExecutorReport.objects.create(enrollment=self.enrollment, agent_version='0.2.32',
            **{key: value for key, value in self.executor.items() if key != 'schema'},
            observed_at=timezone.now() - timedelta(hours=2))
        self.details = {'schema': 1, 'job_schema': 1, 'enrollment_id': str(self.enrollment.pk),
            'device_uri': self.enrollment.device_uri, 'input_digest': self.input_digest,
            'operation': 'create_unlinked_pilot', 'unclaimed': True}

    def retire(self, *, details=None, **changes):
        values = {'tenant': self.tenant, 'actor': 'explicit-retirement-fixture',
            'action': 'security.gpo_import_retired', 'object_type': 'security_gpo_import',
            'object_id': self.job_id, 'outcome': 'succeeded', 'details': self.details if details is None else details}
        return AuditEvent.objects.create(**{**values, **changes})

    def document(self, action='lookup', **changes):
        result = {'type': 'security_gpo', 'schema_version': '1', 'device_uri': self.enrollment.device_uri,
            'correlation_id': 'retired-gpo-fixture', 'action': action,
            'job_id': self.job_id, 'input_digest': self.input_digest}
        if action == 'lookup':
            result.update(agent_version='0.2.34', executor=self.executor)
        elif action == 'result':
            result.update(status='failed', result_code='gpo_job_expired', gpo_guid=None, evidence=None)
        return {**result, **changes}

    def exchange(self, action='lookup', **changes):
        return security_gpo_exchange(self.enrollment, self.document(action, **changes), artifact=action == 'artifact')

    def test_retired_lookup_closes_missing_journal_and_commits_executor_report(self):
        self.retire()
        before = GpoExecutorReport.objects.get().observed_at
        response = self.exchange()
        self.assertEqual(response, {'status': 'accepted', 'correlation_id': 'retired-gpo-fixture',
            'gpo_job': None, 'gpo_approval': None})
        report = GpoExecutorReport.objects.get()
        self.assertGreater(report.observed_at, before)
        self.assertEqual(report.agent_version, '0.2.34')
        self.assertFalse(GpoImportJob.objects.exists())
        self.assertEqual(AuditEvent.objects.count(), 1)

    def test_retired_terminal_failure_is_idempotent_without_creating_jobs_or_grants(self):
        self.retire()
        for code in ('gpo_job_expired', 'gpo_authority_expired', 'gpo_enrollment_changed'):
            for _ in range(2):
                self.assertEqual(self.exchange('result', result_code=code),
                    {'status': 'accepted', 'correlation_id': 'retired-gpo-fixture'})
        poll = self.document()
        poll['action'] = 'poll'
        del poll['job_id']
        del poll['input_digest']
        self.assertIsNone(security_gpo_exchange(self.enrollment, poll)['gpo_job'])
        self.assertEqual(GpoExecutorReport.objects.get().agent_version, '0.2.34')
        self.assertFalse(GpoImportJob.objects.exists())
        self.assertEqual(AuditEvent.objects.count(), 1)

    def test_no_execution_or_success_path_exists_for_a_retired_job(self):
        self.retire()
        for action in ('claim', 'artifact'):
            with self.subTest(action=action), self.assertRaises(ValidationError):
                self.exchange(action)
        for changes in ({'status': 'staged', 'result_code': 'gpo_staged_unlinked'},
                        {'status': 'requires_reconciliation'}, {'status': 'awaiting_local_approval'},
                        {'result_code': 'gpo_provider_failed'}, {'result_code': []},
                        {'gpo_guid': str(uuid.uuid4())}, {'evidence': {}}, {'evidence': False}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.exchange('result', **changes)
        self.assertFalse(GpoImportJob.objects.exists())

    def test_unknown_job_still_rejects_and_does_not_refresh_executor(self):
        before = GpoExecutorReport.objects.get().observed_at
        for action in ('lookup', 'result', 'claim', 'artifact'):
            with self.subTest(action=action), self.assertRaises(ValidationError):
                self.exchange(action)
        self.assertEqual(GpoExecutorReport.objects.get().observed_at, before)

    def test_tombstone_binds_tenant_enrollment_device_digest_and_legacy_operation(self):
        bad = ({'schema': True}, {'schema': 2}, {'job_schema': True}, {'job_schema': 2},
               {'unclaimed': 1}, {'unclaimed': False}, {'enrollment_id': str(uuid.uuid4())},
               {'device_uri': 'urn:ipms:agent:foreign'}, {'input_digest': 'b' * 64},
               {'input_digest': 'A' * 64}, {'operation': 'activate'}, {'extra': 'value'})
        for changes in bad:
            with self.subTest(changes=changes):
                self.job_id = str(uuid.uuid4())
                self.retire(details={**self.details, **changes})
                with self.assertRaises(ValidationError):
                    self.exchange()
                with self.assertRaises(ValidationError):
                    self.exchange('result')
        for value in (None, [], 'retired', {}, {key: value for key, value in self.details.items() if key != 'unclaimed'}):
            with self.subTest(value=value):
                self.job_id = str(uuid.uuid4())
                # JSON null is not accepted by the model field; malformed JSON shapes are otherwise possible.
                self.retire(details=value if value is not None else {'schema': None})
                with self.assertRaises(ValidationError):
                    self.exchange()
        other = Tenant.objects.create(slug='other-retired-gpo', display_name='Other')
        self.job_id = str(uuid.uuid4())
        self.retire(tenant=other)
        with self.assertRaises(ValidationError):
            self.exchange()
        self.job_id = str(uuid.uuid4())
        self.retire()
        for changes in ({'input_digest': 'b' * 64}, {'input_digest': []},
                        {'device_uri': 'urn:ipms:agent:foreign'}, {'job_id': str(uuid.uuid4())}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                self.exchange(**changes)

    def test_wrong_metadata_or_duplicate_events_are_not_a_retirement_authority(self):
        for changes in ({'action': 'security.gpo_import_requested'}, {'object_type': 'other'},
                        {'outcome': 'failed'}, {'outcome': 'denied'}):
            with self.subTest(changes=changes):
                self.job_id = str(uuid.uuid4())
                self.retire(**changes)
                with self.assertRaises(ValidationError):
                    self.exchange()
        self.job_id = str(uuid.uuid4())
        self.retire()
        self.retire()
        with self.assertRaises(ValidationError):
            self.exchange()
        with self.assertRaises(ValidationError):
            self.exchange('result')

    def test_valid_retirement_never_masks_an_existing_job(self):
        # Build a genuine current legacy job through the existing fixture helper,
        # then give another enrollment a matching tombstone: existence wins.
        from . import test_gpo_jobs as legacy
        fixture = legacy.GpoJobTests(methodName='test_queue_pins_exact_assignment_and_retries_do_not_duplicate_it')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        job = fixture.queue()
        self.job_id = job['job_id']
        self.input_digest = job['input_digest']
        self.details = {**self.details, 'input_digest': self.input_digest}
        self.retire()
        with self.assertRaises(ValidationError):
            self.exchange()
        with self.assertRaises(ValidationError):
            self.exchange('result')
        self.assertEqual(GpoImportJob.objects.get(pk=self.job_id).status, 'queued')
