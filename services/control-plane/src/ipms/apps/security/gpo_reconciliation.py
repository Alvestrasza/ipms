# File Name: gpo_reconciliation.py
# Version: v0.1.1 | Created: 2026-09-15 | Last Modified: 2026-09-17
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Read-only directory reconciliation and scoped, acknowledged fence release.
from datetime import timedelta
import re

from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ParseError
from rest_framework.response import Response

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.tenancy.models import Tenant
from .domains import DomainJSONParser
from .gpo_approvals import authorization_for, fresh_actor, policy_for, scoped, visible_jobs
from .gpo_jobs import DEFAULT_GPO_IDS, _ready, canonical, digest, uuid_text
from .gpo_production import assignment_fields, domain_root, owner_marker, _domain_component, _domain_target, _links, _same_target, _sha, policy_for_job, production, validate_snapshot
from .models import DomainSecuritySettings, GpoExecutorReport, GpoImportJob, GpoReconciliation, ManagedGpoPolicy
from .views import SecurityReadView, query

PENDING = ('requested', 'observed', 'accept_requested')
ISSUES = frozenset(('gpo_reconciliation_quiescence_unavailable', 'gpo_reconciliation_guid_unknown',
    'gpo_reconciliation_domain_open_failed', 'gpo_reconciliation_gpo_open_failed', 'gpo_reconciliation_metadata_failed',
    'gpo_reconciliation_worker_failed', 'gpo_reconciliation_worker_timeout', 'gpo_reconciliation_result_invalid', 'gpo_permission_denied',
    'gpo_reconciliation_state_unavailable', 'gpo_reconciliation_acl_inconsistent',
    'gpo_preflight_required', 'gpo_identity_mismatch', 'gpo_state_changed', 'gpo_target_invalid'))
OBSERVATION_FIELDS = {'schema', 'state', 'forest_links', 'forest_complete', 'acl_consistent',
                      'gpo_presence', 'issues', 'gpo_guid', 'quiescent'}
ACTION_FIELDS = {
    'reconciliation_poll': {'job_id', 'input_digest', 'journal_sha256', 'agent_version', 'executor'},
    'reconciliation_result': {'job_id', 'input_digest', 'journal_sha256', 'reconciliation_id', 'observation_digest', 'observation'},
    'reconciliation_ack': {'job_id', 'input_digest', 'journal_sha256', 'reconciliation_id', 'observation_digest'},
}


def _reject():
    raise ValidationError('Invalid GPO reconciliation exchange.')


def _audit(record, action, actor=None):
    AuditEvent.objects.create(tenant=record.tenant, actor=str(actor.pk if actor else 'agent'), action=action,
        object_type='security_gpo_reconciliation', object_id=str(record.pk), outcome='succeeded',
        details={'job_id': str(record.job_id), 'status': record.status, 'input_digest': record.job.input_digest,
                 'observation_digest': record.observation_digest, 'decision_digest': record.decision_digest})


def _job_integrity(job):
    a = job.assignment
    try:
        from .gpo_overrides import patch_valid
        if a.get('schema') == 4 and not patch_valid(a):
            return False
        return (production(job) and set(a) == assignment_fields(a) and a['approval_mode'] == 'portal'
                and a['job_id'] == str(job.pk) and a['scope_id'] == str(job.domain_id)
                and a['domain_guid'] == job.domain_guid and a['domain_dns_name'] == job.domain.domain_name
                and a['input_digest'] == job.input_digest
                and digest({key: value for key, value in a.items() if key != 'input_digest'}) == job.input_digest)
    except (KeyError, TypeError, ValueError):
        return False


def _executor_blocker(job):
    report = GpoExecutorReport.objects.filter(enrollment=job.enrollment).first()
    try:
        minimum = ((0, 2, 46) if _domain_target(job.assignment) and not _domain_component(job.assignment)
                   else (0, 2, 43) if job.assignment.get('schema') == 4 else (0, 2, 37))
        if (not report or tuple(map(int, report.agent_version.split('.'))) < minimum
                or tuple(map(int, job.system.agent_version.split('.'))) < minimum):
            return 'agent_update_required'
        if (job.tenant.status != 'active' or not _ready(job.system, job.enrollment, report, job.domain.domain_name, portal=True)
                or report.domain_guid != job.domain_guid or report.forest_dns_name != job.assignment['forest_dns_name']
                or report.dc_fqdn != job.assignment['executor_dc_fqdn']):
            return 'executor_unavailable'
    except (KeyError, ValueError, AttributeError):
        return 'executor_unavailable'
    return None


def _expire(record):
    if record and record.status in PENDING and timezone.now() >= record.expires_at:
        record.status = 'stale'
        record.save(update_fields=('status',))
        _audit(record, 'security.gpo_reconciliation_expired')


def request_blocker(job, user, latest=None):
    if not production(job):
        return 'legacy_journal_unsupported'
    if job.status == 'reconciled':
        return 'already_reconciled'
    if job.status != 'reconciliation_required':
        return 'job_not_reconcilable'
    if not scoped(user, job.tenant, job.domain, job.assignment.get('target_tier')):
        return 'domain_tier_not_authorized'
    if not _job_integrity(job):
        return 'original_job_changed'
    policy = policy_for_job(job)
    if not policy or policy.state != 'reconciliation_required':
        return 'policy_unavailable'
    if latest and latest.status in ('requested', 'accept_requested'):
        return 'reconciliation_pending'
    return _executor_blocker(job)


def _authority(record, *, accepted=False):
    job = record.job
    if (record.tenant_id != job.tenant_id or not _job_integrity(job)
            or _original_result_identity(job) != record.job_result_digest or job.status != 'reconciliation_required'):
        return 'original_job_changed'
    policy = policy_for_job(job)
    if not policy or policy.state != 'reconciliation_required' or policy.revision != record.managed_revision:
        return 'policy_unavailable'
    rule, auth = policy_for(job.tenant), authorization_for(job.domain)
    if (job.domain.revision != record.scope_revision or rule.revision != record.policy_revision
            or auth.revision != record.authorization_revision
            or record.four_eyes_required != (job.four_eyes_required or rule.four_eyes_required)):
        return 'configuration_changed'
    if not scoped(record.requested_by, job.tenant, job.domain, job.assignment['target_tier']):
        return 'domain_tier_not_authorized'
    if accepted and (not scoped(record.accepted_by, job.tenant, job.domain, job.assignment['target_tier'], approve=True)
            or record.four_eyes_required and record.accepted_by_id in (job.requested_by_id, record.requested_by_id)):
        return 'domain_tier_not_authorized'
    return _executor_blocker(job)


def _original_result_identity(job):
    # Authority withdrawal changes the server reason without rewriting the Agent receipt.
    return digest({'result_digest': job.result_digest, 'error_code': job.error_code, 'gpo_guid': job.gpo_guid})


def validate_observation(value, job):
    try:
        if (not isinstance(value, dict) or set(value) != OBSERVATION_FIELDS or len(canonical(value)) > 32768
                or type(value['schema']) is not int or value['schema'] != 1
                or type(value['quiescent']) is not bool or type(value['forest_complete']) is not bool
                or value['acl_consistent'] is not None and type(value['acl_consistent']) is not bool
                or value['gpo_presence'] not in ('present', 'absent', 'unknown')
                or not isinstance(value['issues'], list) or len(value['issues']) > 8
                or any(not isinstance(code, str) or (code not in ISSUES and not re.fullmatch(
                    r'gpo_reconciliation_hresult_[89a-f][0-9a-f]{7}', code)) for code in value['issues'])
                or len(set(value['issues'])) != len(value['issues'])):
            _reject()
        if value['gpo_guid'] != '':
            uuid_text(value['gpo_guid'])
        _links(value['forest_links'])
        if value['state'] is not None:
            validate_snapshot(value['state'], job.assignment, allow_inconsistent=True)
            gpo = value['state']['gpo']
            if gpo is not None and (gpo['guid'] != value['gpo_guid'] or value['gpo_presence'] != 'present'):
                _reject()
        return value
    except (KeyError, TypeError, ValueError, ParseError):
        _reject()


def observation_blocker(record):
    job, value = record.job, record.observation
    if not value or not _sha(record.journal_sha256) or digest(value) != record.observation_digest:
        return 'observation_unverifiable'
    try:
        validate_observation(value, job)
        if not value['gpo_guid'] or value['gpo_guid'] in DEFAULT_GPO_IDS:
            return 'unknown_guid'
        if not value['quiescent'] or value['gpo_presence'] != 'present' or value['state'] is None:
            return 'observation_unverifiable'
        if not value['forest_complete']:
            return 'forest_incomplete'
        if value['acl_consistent'] is not True:
            return 'acl_inconsistent'
        state = value['state']
        gpo = state['gpo']
        if not gpo:
            return 'observation_unverifiable'
        policy = policy_for_job(job)
        known = (job.gpo_guid, job.assignment['gpo_guid'], policy.gpo_guid)
        if any(guid and guid != value['gpo_guid'] for guid in known):
            return 'ownership_unverified'
        if gpo['description'] != owner_marker(job.assignment):
            return 'ownership_unverified'
        if gpo['computer_enabled'] or gpo['user_enabled']:
            return 'gpo_not_disabled'
        if (gpo['computer_ds'] != gpo['computer_sysvol'] or gpo['user_ds'] != gpo['user_sysvol'] or gpo['wmi_filter']):
            return 'state_inconsistent'
        if value['issues']:
            return 'observation_issues'
        if sorted(gpo['links'], key=canonical) != sorted(value['forest_links'], key=canonical):
            return 'link_scope_conflict'
        root = _domain_target(job.assignment)
        if root and job.assignment['target_tier'] != 0:
            return 'link_scope_conflict'
        configured = ([domain_root(job.domain.domain_name)] if root
                      else job.domain.tier_ous.get(str(job.assignment['target_tier']), []))
        for link in value['forest_links']:
            if (link['guid'] != value['gpo_guid'] or link['domain'] != job.assignment['domain_dns_name']
                    or link['kind'] != ('domain' if root else 'ou') or link['enforced']
                    or not any(_same_target(link['dn'], dn, job.assignment) for dn in configured)
                    or not any(_same_target(link['dn'], dn, job.assignment) for dn in job.assignment['target_ous'])):
                return 'link_scope_conflict'
        direct = [link for target in state['ous'] for link in target['links'] if link['guid'] == value['gpo_guid']]
        if sorted(direct, key=canonical) != sorted(value['forest_links'], key=canonical):
            return 'link_scope_conflict'
        if ManagedGpoPolicy.objects.filter(tenant=job.tenant, domain_guid=job.domain_guid,
                gpo_guid=value['gpo_guid']).exclude(pk=policy.pk).exists():
            return 'ownership_unverified'
    except (ValidationError, KeyError, TypeError, ValueError, AttributeError):
        return 'observation_unverifiable'
    return None


def accept_blocker(record, user):
    if record.status == 'accepted':
        return 'already_accepted'
    if record.status == 'accept_requested':
        return 'acceptance_pending'
    if record.status in ('stale', 'failed') or timezone.now() >= record.expires_at:
        return 'observation_stale'
    if record.status != 'observed':
        return 'observation_pending'
    reason = _authority(record)
    if reason:
        return reason
    job = record.job
    if not scoped(user, job.tenant, job.domain, job.assignment['target_tier'], approve=True):
        return 'domain_tier_not_authorized'
    if record.four_eyes_required and user.pk in (job.requested_by_id, record.requested_by_id):
        return 'four_eyes_required'
    return observation_blocker(record)


def projection(job, user):
    latest = GpoReconciliation.objects.filter(job=job).select_related('requested_by', 'accepted_by').first()
    if latest:
        latest.job = job
    _expire(latest)
    if latest and latest.status in PENDING and (_authority(latest, accepted=latest.status == 'accept_requested')
            or latest.status == 'accept_requested' and (not _decision_valid(latest) or observation_blocker(latest))):
        latest.status = 'stale'
        latest.save(update_fields=('status',))
        _audit(latest, 'security.gpo_reconciliation_authority_changed')
    reason = request_blocker(job, user, latest)
    result = {'can_request': reason is None, 'request_blocked_reason': reason, 'latest': None}
    if latest:
        blocked = accept_blocker(latest, user)
        issues = list(dict.fromkeys((latest.observation or {}).get('issues', []) + (latest.drift_observation or {}).get('issues', [])))
        result['latest'] = {'id': str(latest.pk), 'status': latest.status,
            'requested_at': latest.requested_at.isoformat(), 'expires_at': latest.expires_at.isoformat(),
            'observation': latest.observation, 'observation_digest': latest.observation_digest, 'issues': issues,
            'can_accept': blocked is None, 'accept_blocked_reason': blocked,
            'accepted_at': latest.accepted_at.isoformat() if latest.accepted_at else None}
    return result


def _decision(record):
    return digest({'id': str(record.pk), 'job_id': str(record.job_id), 'input_digest': record.job.input_digest,
        'journal_sha256': record.journal_sha256, 'observation_digest': record.observation_digest,
        'accepted_by': record.accepted_actor, 'accepted_at': record.accepted_at.isoformat(),
        'scope_revision': record.scope_revision, 'policy_revision': record.policy_revision,
        'authorization_revision': record.authorization_revision, 'managed_revision': record.managed_revision,
        'four_eyes_required': record.four_eyes_required})


def _decision_valid(record):
    return bool(record.accepted_at and record.accepted_by_id and _sha(record.decision_digest)
                and record.accepted_actor == str(record.accepted_by_id)
                and record.decision_digest == _decision(record))


def _control(record, mode):
    return {'schema': 1, 'id': str(record.pk), 'job_id': str(record.job_id), 'input_digest': record.job.input_digest,
        'journal_sha256': record.journal_sha256, 'device_uri': record.job.enrollment.device_uri,
        'expires_at': record.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ'), 'mode': mode,
        'observation_digest': record.observation_digest}


def exchange(job, document):
    """Called inside the existing tenant/enrollment/job transaction and envelope validation."""
    if not production(job) or not _sha(document['journal_sha256']):
        _reject()
    job.domain = DomainSecuritySettings.objects.select_for_update().get(pk=job.domain_id)
    if document['action'] == 'reconciliation_poll':
        record = GpoReconciliation.objects.select_for_update().filter(job=job).first()
    else:
        try:
            identifier = uuid_text(document['reconciliation_id'])
        except (TypeError, ValueError):
            _reject()
        record = GpoReconciliation.objects.select_for_update().filter(pk=identifier, job=job).first()
        if not record or not _sha(document['observation_digest']):
            _reject()
    if not record:
        return None
    record.job = job
    # Released receipts survive lost acknowledgements and expiry. They confer no AD authority.
    if record.status == 'accepted' and job.status == 'reconciled':
        if document['journal_sha256'] != record.journal_sha256 or record.decision_digest != _decision(record):
            _reject()
        if document['action'] != 'reconciliation_poll' and document['observation_digest'] != record.observation_digest:
            _reject()
        return _control(record, 'released')
    _expire(record)
    if record.status not in PENDING:
        return None
    if (_authority(record, accepted=record.status == 'accept_requested')
            or record.status == 'accept_requested' and (not _decision_valid(record) or observation_blocker(record))):
        record.status = 'stale'
        record.save(update_fields=('status',))
        _audit(record, 'security.gpo_reconciliation_authority_changed')
        return None
    if not record.journal_sha256 and document['action'] == 'reconciliation_poll':
        record.journal_sha256 = document['journal_sha256']
        record.save(update_fields=('journal_sha256',))
    if record.journal_sha256 != document['journal_sha256']:
        _reject()
    if document['action'] == 'reconciliation_poll':
        if record.status == 'observed':
            return None  # Keep the immutable observation while awaiting administrator review.
        return _control(record, 'accept' if record.status == 'accept_requested' else 'observe')
    if document['action'] == 'reconciliation_result':
        value = validate_observation(document['observation'], job)
        if digest(value) != document['observation_digest']:
            _reject()
        if record.observation is None:
            record.observation, record.observation_digest = value, document['observation_digest']
            record.observed_at, record.status = timezone.now(), 'observed'
        elif record.observation_digest != document['observation_digest']:
            record.drift_observation, record.drift_digest, record.status = value, document['observation_digest'], 'stale'
        record.save()
        _audit(record, 'security.gpo_reconciliation_observed')
        return None
    if (record.status != 'accept_requested' or document['observation_digest'] != record.observation_digest
            or not record.accepted_at or _authority(record, accepted=True)
            or record.decision_digest != _decision(record) or observation_blocker(record)):
        _reject()
    policy = policy_for_job(job, lock=True)
    policy.gpo_guid = record.observation['gpo_guid']
    policy.state, policy.staged_job, policy.active_job = 'new', None, None
    policy.revision += 1
    policy.save(update_fields=('gpo_guid', 'state', 'staged_job', 'active_job', 'revision'))
    # Preserve every original result field. Reconciliation is not import success.
    job.status = 'reconciled'
    job.save(update_fields=('status',))
    record.status, record.finalized_at = 'accepted', timezone.now()
    record.save(update_fields=('status', 'finalized_at'))
    _audit(record, 'security.gpo_reconciliation_released', record.accepted_by)
    return _control(record, 'released')


class GpoReconciliationsView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    parser_classes = (DomainJSONParser,)
    http_method_names = ('get', 'post', 'head', 'options')

    def _job(self, request, job_id, *, write=False):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if write:
            fresh_actor(request)
        self.check_permissions(request)
        job = get_object_or_404(visible_jobs(request.user, request.tenant, GpoImportJob.objects.select_for_update()),
                               pk=job_id, tenant=request.tenant)
        job.domain = DomainSecuritySettings.objects.select_for_update().get(pk=job.domain_id)
        return job

    @transaction.atomic
    def get(self, request, job_id):
        return Response(projection(self._job(request, job_id), request.user))

    @transaction.atomic
    def post(self, request, job_id):
        job = self._job(request, job_id, write=True)
        data = request.data
        if not isinstance(data, dict) or set(data) != {'idempotency_key', 'input_digest'} or data['input_digest'] != job.input_digest:
            raise ParseError('Supply the unchanged original job digest and request identifier.')
        try:
            identifier = uuid_text(data['idempotency_key'])
        except (ValueError, TypeError):
            raise ParseError('Invalid reconciliation request identifier.')
        request_digest = digest({'job_id': str(job.pk), **data})
        prior = GpoReconciliation.objects.filter(pk=identifier).first()
        if prior:
            if prior.job_id != job.pk or prior.requested_by_id != request.user.pk or prior.request_digest != request_digest:
                raise PublicApiError('security_gpo_request_conflict', status_code=409)
            return Response(projection(job, request.user), status=202)
        state = projection(job, request.user)
        if not state['can_request']:
            raise PublicApiError('security_gpo_reconciliation_' + state['request_blocked_reason'], status_code=409)
        if GpoReconciliation.objects.filter(job=job).count() >= 100:
            raise PublicApiError('security_gpo_reconciliation_limit', status_code=409)
        # An explicit new read supersedes a previous observation, never its evidence.
        for previous in GpoReconciliation.objects.select_for_update().filter(job=job, status='observed'):
            previous.status = 'stale'
            previous.save(update_fields=('status',))
            _audit(previous, 'security.gpo_reconciliation_superseded', request.user)
        rule, auth, policy = policy_for(job.tenant), authorization_for(job.domain), policy_for_job(job, lock=True)
        record = GpoReconciliation.objects.create(id=identifier, job=job, tenant=job.tenant, requested_by=request.user,
            request_digest=request_digest, job_result_digest=_original_result_identity(job), scope_revision=job.domain.revision,
            policy_revision=rule.revision, authorization_revision=auth.revision, managed_revision=policy.revision,
            four_eyes_required=job.four_eyes_required or rule.four_eyes_required,
            expires_at=(timezone.now() + timedelta(minutes=15)).replace(microsecond=0))
        _audit(record, 'security.gpo_reconciliation_requested', request.user)
        return Response(projection(job, request.user), status=202)


class GpoReconciliationAcceptView(GpoReconciliationsView):
    http_method_names = ('post', 'options')

    @transaction.atomic
    def post(self, request, job_id, reconciliation_id):
        job = self._job(request, job_id, write=True)
        record = get_object_or_404(GpoReconciliation.objects.select_for_update(), pk=reconciliation_id, job=job)
        record.job = job
        data = request.data
        if (not isinstance(data, dict) or set(data) != {'observation_digest'} or not _sha(data['observation_digest'])
                or data['observation_digest'] != record.observation_digest):
            raise PublicApiError('security_gpo_reconciliation_observation_changed', status_code=409)
        if record.status in ('accept_requested', 'accepted') and record.accepted_by_id == request.user.pk:
            return Response(projection(job, request.user), status=202)
        _expire(record)
        reason = accept_blocker(record, request.user)
        if reason:
            raise PublicApiError('security_gpo_reconciliation_' + reason, status_code=403 if reason in (
                'domain_tier_not_authorized', 'four_eyes_required') else 409)
        record.accepted_by, record.accepted_at, record.status = request.user, timezone.now(), 'accept_requested'
        record.accepted_actor = str(request.user.pk)
        record.decision_digest = _decision(record)
        record.save(update_fields=('accepted_by', 'accepted_actor', 'accepted_at', 'status', 'decision_digest'))
        _audit(record, 'security.gpo_reconciliation_accepted', request.user)
        return Response(projection(job, request.user), status=202)
