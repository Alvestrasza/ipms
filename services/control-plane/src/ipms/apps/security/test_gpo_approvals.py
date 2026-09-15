# File Name: test_gpo_approvals.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Public approval policy, domain scopes, immutable reviews and one-use authority.
import copy
import hashlib
import struct
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase, skipUnlessDBFeature
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import TenantMembership, PlatformAdministrator
from ipms.apps.tenancy.operations import withdraw_identity_operations
from .gpo_approvals import approval_object, review_document
from .gpo_content import COMPONENTS, PROFILE_COMPONENTS
from .gpo_jobs import digest, security_gpo_exchange
from .models import DomainSecuritySettings, GpoApprovalPolicy, GpoDomainAuthorization, GpoImportJob, GpoExecutorReport
from . import test_gpo_jobs as legacy_tests
from .test_gpo_jobs import SERVER, PILOT_GUID
from . import test_domains
from .test_domains import URL

POLICY_URL = '/api/v1/security/gpo-approval-policy/'


class PortalApprovalTests(TestCase):
    draft = test_domains.DomainSettingsTests.draft
    create = test_domains.DomainSettingsTests.create
    envelope = legacy_tests.GpoJobTests.envelope
    poll = legacy_tests.GpoJobTests.poll
    exchange = legacy_tests.GpoJobTests.exchange
    result = legacy_tests.GpoJobTests.result
    staged_evidence = legacy_tests.GpoJobTests.staged_evidence

    def setUp(self):
        legacy_tests.GpoJobTests.setUp(self)
        self.authorization_url = URL + self.config['id'] + '/gpo-authorization/'
        self.approver = get_user_model().objects.create_user(username='tier-approver', password='test')
        self.approver_membership = TenantMembership.objects.create(tenant=self.tenant, user=self.approver, role='approver')
        # Independently build a tiny pinned binary package, with an inert XML payload.
        report = '<GPO><Name>&lt;script&gt;review only&lt;/script&gt;</Name></GPO>'.encode('utf-16')
        payloads = [('Backup.xml', b'<Backup/>'), ('gpreport.xml', report)]
        self.bundle = b'IPMSGPO1' + struct.pack('<I', 2) + b''.join(struct.pack('<I', len(data)) + data for _, data in payloads)
        self.component = copy.deepcopy(COMPONENTS[(SERVER, self.selection['backup_id'])])
        self.component.update(artifact_sha256=hashlib.sha256(self.bundle).hexdigest(), artifact_size=len(self.bundle),
            files=[{'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in payloads])
        components = {**COMPONENTS, (SERVER, self.selection['backup_id']): self.component}
        self.artifact_mock = patch('ipms.apps.security.gpo_jobs.artifact_bytes', return_value=self.bundle).start()
        self.addCleanup(patch.stopall)
        patch('ipms.apps.security.gpo_jobs._content', return_value=(components, PROFILE_COMPONENTS)).start()

    def grants(self, rows=None):
        current = self.client.get(self.authorization_url).data
        return self.client.put(self.authorization_url, {'expected_revision': current['revision'], 'grants': rows if rows is not None else [
            {'user_id': str(self.user.pk), 'tiers': ['1']}, {'user_id': str(self.approver.pk), 'tiers': ['1']}]}, format='json')

    def policy(self, four_eyes):
        current = self.client.get(POLICY_URL).data
        return self.client.put(POLICY_URL, {'expected_revision': current['revision'], 'four_eyes_required': four_eyes}, format='json')

    def queue(self, **changes):
        response = self.client.post(self.import_url, {**self.selection, **changes}, format='json')
        self.assertEqual(response.status_code, 202, response.data)
        self.assertEqual(response.data['status'], 'awaiting_approval')
        self.assertIsNone(response.data['approved_at'])
        return response.data['approval_document']

    def approve(self, job, **changes):
        row = GpoImportJob.objects.get(pk=job['job_id'])
        return self.client.post(f"/api/v1/security/gpo-imports/{row.pk}/approve/",
                               {'input_digest': job['input_digest'], 'policy_revision': row.policy_revision, **changes}, format='json')

    def test_defaults_are_read_only_and_no_implicit_admin_scope(self):
        GpoDomainAuthorization.objects.all().delete()
        with CaptureQueriesContext(connection) as queries:
            policy = self.client.get(POLICY_URL)
            grants = self.client.get(self.authorization_url)
        self.assertEqual(policy.data, {'four_eyes_required': False, 'revision': 1})
        self.assertEqual(grants.data['grants'], [])
        self.assertEqual(grants.data['revision'], 1)
        self.assertEqual({item['user_id'] for item in grants.data['members']}, {str(self.user.pk), str(self.approver.pk)})
        self.assertFalse(any(item['sql'].lstrip().upper().startswith(('INSERT', 'UPDATE', 'DELETE')) for item in queries))
        self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 403)
        self.assertFalse(GpoImportJob.objects.exists())
        self.assertEqual(self.grants().status_code, 200)
        self.assertEqual(self.queue()['schema'], 2)

    def test_self_approval_is_explicit_bound_and_claimed_once(self):
        job = self.queue()
        self.assertEqual(set(job), {'schema', 'job_id', 'operation', 'domain_dns_name', 'domain_guid', 'forest_dns_name',
            'executor_dc_fqdn', 'scope_id', 'scope_revision', 'target_tier', 'baseline_id', 'profile', 'backup_id',
            'artifact_sha256', 'pilot_display_name', 'expires_at', 'input_digest', 'approval_mode'})
        pending = security_gpo_exchange(self.agent, self.envelope(agent_version='0.2.34', executor=self.report))
        self.assertIsNone(pending['gpo_approval'])
        detail = self.client.get(f"/api/v1/logs/gpo-imports/{job['job_id']}/")
        self.assertEqual(detail.status_code, 200)
        self.assertTrue(detail.data['can_approve'])
        self.assertIn('&lt;script&gt;', detail.data['review']['report_xml'])
        self.assertEqual(detail.data['review']['changes'], ['create_disabled_unlinked_pilot'])
        self.assertIsNone(GpoImportJob.objects.get().approved_at)
        with self.assertRaises(ValidationError):
            security_gpo_exchange(self.agent, self.envelope('artifact', job_id=job['job_id'], input_digest=job['input_digest']), artifact=True)
        self.result(job, 'awaiting_portal_approval', 'gpo_portal_approval_required')
        response = self.approve(job)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data['status'], 'queued')
        approved = GpoImportJob.objects.get()
        self.assertEqual(approved.requested_by_id, approved.approved_by_id)
        self.assertIsNone(approved.claimed_at)
        offered = security_gpo_exchange(self.agent, self.envelope(agent_version='0.2.34', executor=self.report))['gpo_approval']
        self.assertEqual(len(offered), 13)
        self.assertEqual(offered['requested_by'], str(self.user.pk))
        self.assertFalse(offered['four_eyes_required'])
        self.result(job, 'awaiting_portal_approval', 'gpo_portal_approval_required')
        self.assertEqual(GpoImportJob.objects.get().approval_digest, approved.approval_digest)
        self.assertEqual(GpoImportJob.objects.get().status, 'queued')
        claim = self.exchange(job, 'claim')['gpo_claim']
        self.assertEqual(set(claim), {'authorized', 'mode', 'job', 'approval'})
        self.assertEqual(claim['approval'], offered)
        self.assertEqual(claim['job'], job)
        self.assertTrue(claim['authorized'])
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim'], {'authorized': False, 'mode': 'observe', 'job': job})
        self.result(job, 'staged', 'gpo_staged_unlinked', PILOT_GUID, self.staged_evidence())
        self.assertEqual(GpoImportJob.objects.get().status, 'staged')
        self.assertEqual(AuditEvent.objects.get(action='security.gpo_import_approved').actor, str(self.user.pk))

    def test_four_eyes_requires_distinct_scoped_actor_and_audits_actual_approver(self):
        self.grants()
        self.policy(True)
        job = self.queue()
        response = self.approve(job)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data['error']['code'], 'security_gpo_four_eyes_required')
        self.client.force_authenticate(self.approver)
        self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 403)
        self.assertEqual(self.approve(job).status_code, 200)
        self.assertEqual(AuditEvent.objects.get(action='security.gpo_import_approved').actor, str(self.approver.pk))
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['approval']['approved_by'], str(self.approver.pk))

    def test_wrong_tier_domain_tenant_and_role_cannot_review_or_approve(self):
        self.grants([{'user_id': str(self.user.pk), 'tiers': ['1']}, {'user_id': str(self.approver.pk), 'tiers': ['0']}])
        job = self.queue()
        self.client.force_authenticate(self.approver)
        self.assertEqual(self.approve(job).status_code, 404)
        self.assertEqual(self.client.get(f"/api/v1/logs/gpo-imports/{job['job_id']}/").status_code, 404)
        self.assertEqual(self.client.get('/api/v1/logs/baselines/', {'kind': 'gpo_import'}).data['count'], 0)
        self.assertNotIn(job['job_id'], self.client.get('/api/v1/logs/baselines/export/').content.decode())
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.pk))
        self.assertEqual(self.approve(job).status_code, 404)

    def test_scoped_approver_only_sees_granted_jobs_and_csv(self):
        self.grants()
        job = self.queue()
        self.client.force_authenticate(self.approver)
        detail = self.client.get(f"/api/v1/logs/gpo-imports/{job['job_id']}/")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(self.client.get('/api/v1/logs/baselines/', {'kind': 'gpo_import'}).data['count'], 1)
        self.assertIn(job['job_id'], self.client.get('/api/v1/logs/baselines/export/').content.decode())
        for endpoint in (POLICY_URL, self.authorization_url):
            self.assertEqual(self.client.get(endpoint).status_code, 403)
        self.approver_membership.expires_at = timezone.now() - timedelta(seconds=1)
        self.approver_membership.save()
        self.assertEqual(self.approve(job).status_code, 404)

    def test_changed_policy_grants_or_settings_withdraw_before_claim(self):
        for change in ('policy', 'grant', 'settings'):
            with self.subTest(change=change):
                self.grants()
                job = self.queue(idempotency_key=str(uuid.uuid4()), version=f'1.0.{len(GpoImportJob.objects.all())}')
                self.assertEqual(self.approve(job).status_code, 200)
                if change == 'policy':
                    self.policy(False)
                elif change == 'grant':
                    self.grants([{'user_id': str(self.user.pk), 'tiers': ['1']}])
                else:
                    self.client.put(URL + self.config['id'] + '/', {**self.draft(), 'expected_revision': 1}, format='json')
                self.assertEqual(GpoImportJob.objects.get(pk=job['job_id']).status, 'failed')
                self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')

    def test_claimed_revocation_retains_reconciliation_fence(self):
        job = self.queue()
        self.approve(job)
        self.exchange(job, 'claim')
        self.policy(True)
        self.assertEqual(GpoImportJob.objects.get().status, 'reconciliation_required')
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'reconcile')
        self.assertEqual(self.client.post(self.import_url, {**self.selection, 'version': '2.0.0', 'idempotency_key': str(uuid.uuid4())}, format='json').status_code, 409)

    def test_approver_identity_withdrawal_never_revives_after_reactivation(self):
        self.grants()
        job = self.queue()
        self.client.force_authenticate(self.approver)
        self.approve(job)
        with transaction.atomic():
            withdraw_identity_operations(self.approver, reason='password_reset')
        self.assertEqual(GpoImportJob.objects.get().status, 'failed')
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')
        self.assertEqual(self.approve(job).status_code, 409)

    def test_tampered_assignment_receipt_and_expired_job_are_never_claimed(self):
        for change in ('assignment', 'approval', 'expiry', 'membership'):
            with self.subTest(change=change):
                job = self.queue(idempotency_key=str(uuid.uuid4()), version=f'1.0.{GpoImportJob.objects.count()}')
                self.approve(job)
                row = GpoImportJob.objects.get(pk=job['job_id'])
                if change == 'assignment':
                    row.assignment['pilot_display_name'] += '-changed'
                    row.save(update_fields=('assignment',))
                elif change == 'approval':
                    row.approval_digest = 'a' * 64
                    row.save(update_fields=('approval_digest',))
                elif change == 'expiry':
                    row.expires_at = timezone.now() - timedelta(seconds=1)
                    row.save(update_fields=('expires_at',))
                else:
                    self.membership.is_active = False
                    self.membership.save()
                self.assertFalse(self.exchange(job, 'claim')['gpo_claim']['authorized'])
        self.assertFalse(GpoImportJob.objects.filter(status='running').exists())

    def test_strict_inputs_revisions_missing_review_and_old_executor(self):
        for data in ({'expected_revision': True, 'four_eyes_required': False}, {'expected_revision': 1, 'four_eyes_required': 1}):
            self.assertEqual(self.client.put(POLICY_URL, data, format='json').status_code, 400)
        self.assertEqual(self.policy(False).status_code, 200)
        self.assertEqual(self.client.put(POLICY_URL, {'expected_revision': 1, 'four_eyes_required': True}, format='json').status_code, 409)
        self.assertEqual(self.grants([{'user_id': str(self.approver.pk), 'tiers': ['1', '1']}]).status_code, 400)
        GpoExecutorReport.objects.update(agent_version='0.2.33')
        self.assertEqual(self.client.post(self.import_url, self.selection, format='json').status_code, 409)
        self.poll()
        job = self.queue()
        self.assertEqual(self.approve(job, policy_revision=True).status_code, 400)
        self.assertEqual(self.approve(job, input_digest='b' * 64).status_code, 409)
        self.artifact_mock.return_value = self.bundle + b'changed'
        self.assertEqual(self.approve(job).status_code, 409)
        self.assertFalse(self.client.get(f"/api/v1/logs/gpo-imports/{job['job_id']}/").data['can_approve'])
        self.assertIsNone(GpoImportJob.objects.get().approved_at)

    def test_legacy_job_cannot_be_approved_centrally(self):
        job = legacy_tests.GpoJobTests.queue(self)
        self.assertEqual(job['schema'], 1)
        self.assertEqual(self.approve(job).status_code, 409)
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'execute')

    def test_no_link_or_activation_operation_is_accepted(self):
        for operation in ('link', 'activate', 'enable', 'replace'):
            self.assertEqual(self.client.post(self.import_url, {**self.selection, 'operation': operation}, format='json').status_code, 400)
        job = self.queue()
        self.assertEqual(self.approve(job, operation='activate').status_code, 400)
        self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')

    def test_session_csrf_required_for_every_mutation(self):
        session = APIClient(enforce_csrf_checks=True)
        session.force_login(self.user)
        session.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
        job = self.queue()
        for endpoint, data, method in ((POLICY_URL, {'expected_revision': 1, 'four_eyes_required': True}, 'put'),
                (self.authorization_url, {'expected_revision': 1, 'grants': []}, 'put'),
                (f"/api/v1/security/gpo-imports/{job['job_id']}/approve/", {'input_digest': job['input_digest'], 'policy_revision': 1}, 'post')):
            self.assertEqual(getattr(session, method)(endpoint, data, format='json').status_code, 403)

    def test_approved_actor_membership_is_rechecked_at_claim(self):
        self.grants()
        for mode in ('expired', 'inactive', 'role', 'platform'):
            with self.subTest(mode=mode):
                self.client.force_authenticate(self.user)
                job = self.queue(idempotency_key=str(uuid.uuid4()), version=f'2.0.{GpoImportJob.objects.count()}')
                self.client.force_authenticate(self.approver)
                self.assertEqual(self.approve(job).status_code, 200)
                if mode == 'expired':
                    self.approver_membership.expires_at = timezone.now() - timedelta(seconds=1)
                elif mode == 'inactive':
                    self.approver_membership.is_active = False
                elif mode == 'role':
                    self.approver_membership.role = 'reader'
                else:
                    get_user_model().objects.filter(pk=self.approver.pk).update(is_staff=True)
                if mode != 'platform':
                    self.approver_membership.save()
                self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')
                self.approver_membership.expires_at = None
                self.approver_membership.is_active = True
                self.approver_membership.role = 'approver'
                get_user_model().objects.filter(pk=self.approver.pk).update(is_staff=False)
                self.approver_membership.save()
                self.assertEqual(self.exchange(job, 'claim')['gpo_claim']['mode'], 'cancelled')

    def test_grant_in_another_domain_does_not_authorize_this_job(self):
        other_domain = DomainSecuritySettings.objects.create(tenant=self.tenant, domain_name='other.example.invalid',
            tier_ous={'0': [], '1': [], '2': []}, gpo_name_template=self.draft()['gpo_name_template'], baseline_order=[])
        GpoDomainAuthorization.objects.create(domain=other_domain,
            grants=[{'user_id': str(self.approver.pk), 'tiers': ['0', '1', '2']}])
        job = self.queue()
        self.client.force_authenticate(self.approver)
        self.assertEqual(self.approve(job).status_code, 404)
        self.assertEqual(self.client.get('/api/v1/logs/baselines/', {'kind': 'gpo_import'}).data['count'], 0)

    def test_review_rejects_invalid_counts_lengths_hashes_and_trailing_bytes(self):
        job = self.queue()
        row = GpoImportJob.objects.get()
        for content in (b'badmagic' + self.bundle[8:], self.bundle[:8] + struct.pack('<I', 1) + self.bundle[12:],
                        self.bundle[:12] + struct.pack('<I', 9999) + self.bundle[16:],
                        self.bundle[:-1], self.bundle + b'extra', self.bundle[:-1] + b'X'):
            with self.subTest(length=len(content)):
                self.artifact_mock.return_value = content
                with self.assertRaises(ValidationError):
                    review_document(row)
                self.assertEqual(self.approve(job).status_code, 409)
        self.assertIsNone(GpoImportJob.objects.get().approved_at)

    def test_expiry_crossed_during_review_cannot_persist_an_approval(self):
        job = self.queue()
        clock = [timezone.now()]
        def reviewed_then_expired(row):
            result = review_document(row)
            clock[0] = row.expires_at
            return result
        with patch('ipms.apps.security.gpo_approvals.review_document', side_effect=reviewed_then_expired), \
                patch('ipms.apps.security.gpo_approvals.timezone.now', side_effect=lambda: clock[0]):
            response = self.approve(job)
        self.assertEqual(response.status_code, 409)
        self.assertIsNone(GpoImportJob.objects.get().approved_at)

    def test_authentication_reset_while_waiting_for_tenant_lock_is_rejected(self):
        from types import SimpleNamespace
        from ipms.apps.tenancy.models import Tenant
        self.grants()
        job = self.queue()
        for kind in ('approve', 'policy', 'grants', 'queue'):
            with self.subTest(kind=kind):
                actor = self.approver if kind == 'approve' else self.user
                session = APIClient()
                session.force_login(actor)
                session.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
                original_lock = Tenant.objects.select_for_update
                def locked_then_reset(*args, **kwargs):
                    queryset = original_lock(*args, **kwargs)
                    def get(**filters):
                        tenant = queryset.get(**filters)
                        # Reproduce a committed identity reset between session
                        # authentication and admission to this tenant's lock.
                        reset = get_user_model().objects.get(pk=actor.pk)
                        reset.set_password('fresh-replacement-password')
                        reset.save(update_fields=('password',))
                        return tenant
                    return SimpleNamespace(get=get)
                with patch.object(Tenant.objects, 'select_for_update', side_effect=locked_then_reset):
                    if kind == 'approve':
                        response = session.post(f"/api/v1/security/gpo-imports/{job['job_id']}/approve/",
                            {'input_digest': job['input_digest'], 'policy_revision': 1}, format='json')
                    elif kind == 'policy':
                        response = session.put(POLICY_URL, {'expected_revision': 1, 'four_eyes_required': True}, format='json')
                    elif kind == 'grants':
                        response = session.put(self.authorization_url, {'expected_revision': 2, 'grants': []}, format='json')
                    else:
                        response = session.post(self.import_url, {**self.selection, 'idempotency_key': str(uuid.uuid4()),
                            'version': '5.0.0'}, format='json')
                self.assertEqual(response.status_code, 403, response.data)
                self.assertEqual(response.data['error']['code'], 'security_gpo_authentication_changed')
        self.assertEqual(GpoImportJob.objects.count(), 1)
        self.assertIsNone(GpoImportJob.objects.get().approved_at)
        self.assertFalse(GpoApprovalPolicy.objects.exists())
        self.assertEqual(GpoDomainAuthorization.objects.get().revision, 2)

    def test_current_cookie_session_can_approve_without_password_entry(self):
        job = self.queue()
        session = APIClient()
        session.force_login(self.user)
        session.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
        response = session.post(f"/api/v1/security/gpo-imports/{job['job_id']}/approve/",
            {'input_digest': job['input_digest'], 'policy_revision': 1}, format='json')
        self.assertEqual(response.status_code, 200, response.data)

    def test_legacy_database_model_can_insert_after_additive_migration(self):
        from django.db.migrations.executor import MigrationExecutor
        job = legacy_tests.GpoJobTests.queue(self)
        row = GpoImportJob.objects.get()
        row.status = 'failed'
        row.save(update_fields=('status',))
        old_apps = MigrationExecutor(connection).loader.project_state([('security', '0004_domain_gpo_pilots')]).apps
        old_job = old_apps.get_model('security', 'GpoImportJob')
        self.assertEqual(old_job.objects.get(pk=row.pk).assignment, job)
        values = {field.attname: getattr(row, field.attname) for field in old_job._meta.concrete_fields}
        values.update(id=uuid.uuid4(), pilot_display_name='Legacy rollback fixture', pilot_name_key='legacy-rollback-fixture')
        inserted = old_job.objects.create(**values)
        current = GpoImportJob.objects.get(pk=inserted.pk)
        self.assertEqual(current.assignment, job)
        self.assertEqual((current.policy_revision, current.authorization_revision, current.four_eyes_required,
                          current.approval_digest, current.approved_by_id, current.approved_at), (1, 1, False, '', None, None))


@skipUnlessDBFeature('has_select_for_update')
class PortalApprovalRaceTests(TransactionTestCase):
    """Use independent PostgreSQL connections to exercise the tenant lock order."""
    draft = PortalApprovalTests.draft
    create = PortalApprovalTests.create
    envelope = PortalApprovalTests.envelope
    poll = PortalApprovalTests.poll
    queue = PortalApprovalTests.queue
    approve = PortalApprovalTests.approve
    grants = PortalApprovalTests.grants
    policy = PortalApprovalTests.policy
    setUp = PortalApprovalTests.setUp

    def _parallel(self, first, second):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from django.db import close_old_connections
        start = Barrier(2)
        def invoke(action):
            close_old_connections()
            try:
                start.wait(timeout=10)
                return action()
            finally:
                connection.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(invoke, action) for action in (first, second)]
            return [future.result(timeout=20) for future in futures]

    def test_two_concurrent_claims_grant_one_execution(self):
        job = self.queue()
        self.assertEqual(self.approve(job).status_code, 200)
        def claim():
            from ipms.apps.agent_pki.models import AgentEnrollment
            agent = AgentEnrollment.objects.get(pk=self.agent.pk)
            return security_gpo_exchange(agent, self.envelope('claim', job_id=job['job_id'], input_digest=job['input_digest']))['gpo_claim']['mode']
        self.assertEqual(sorted(self._parallel(claim, claim)), ['execute', 'observe'])
        self.assertEqual(AuditEvent.objects.filter(action='security.gpo_import_claimed').count(), 1)

    def test_concurrent_policy_change_always_withdraws_approval(self):
        job = self.queue()
        def request(kind):
            client = APIClient()
            client.force_authenticate(get_user_model().objects.get(pk=self.user.pk))
            client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.pk))
            if kind == 'approve':
                return client.post(f"/api/v1/security/gpo-imports/{job['job_id']}/approve/",
                    {'input_digest': job['input_digest'], 'policy_revision': 1}, format='json').status_code
            return client.put(POLICY_URL, {'expected_revision': 1, 'four_eyes_required': True}, format='json').status_code
        approval, changed = self._parallel(lambda: request('approve'), lambda: request('policy'))
        self.assertIn(approval, (200, 409))
        self.assertEqual(changed, 200)
        self.assertEqual(GpoImportJob.objects.get().status, 'failed')
