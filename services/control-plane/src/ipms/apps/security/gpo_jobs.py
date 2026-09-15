# File Name: gpo_jobs.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Immutable native GPO pilot jobs, scoped artifacts and durable domain fences.
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import NotFound, ParseError, PermissionDenied

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, has_tenant_permission
from .catalog import BASELINES, BY_ID
from .domains import domain_name, render_name, validate_settings
from .models import DomainSecuritySettings, GpoExecutorReport, GpoImportJob

ACTIVE = ('queued', 'awaiting_approval', 'running', 'reconciliation_required')
PRE_EXECUTION = ('queued', 'awaiting_approval')
TERMINAL = ('staged', 'failed', 'expired')
MAX_ARTIFACT = 1024 * 1024
DEFAULT_GPO_IDS = {'31b2f340-016d-11d2-945f-00c04fb984f9', '6ac1786c-016f-11d2-945f-00c04fb984f9'}
RESULT_CODES = set('gpo_staged_unlinked gpo_local_approval_required gpo_job_expired gpo_invalid_job '
                   'gpo_unsupported_component gpo_identity_mismatch gpo_not_writable_dc '
                   'gpo_domain_identity_unavailable gpmc_unavailable gpo_permission_denied '
                   'gpo_name_collision gpo_source_mismatch gpo_artifact_invalid gpo_local_approval_invalid '
                   'gpo_reconciliation_required gpo_provider_failed gpo_verification_failed '
                   'gpo_worker_timeout gpo_worker_failed gpo_journal_invalid gpo_claim_uncertain '
                   'gpo_authority_expired gpo_enrollment_changed gpo_portal_approval_invalid gpo_portal_approval_required'.split())
EXECUTOR_CODES = {'ready_for_approval', 'not_writable_domain_controller', 'domain_identity_unavailable',
                  'gpmc_unavailable', 'executor_probe_failed'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def uuid_text(value):
    if not isinstance(value, str):
        raise ValueError('Invalid UUID.')
    parsed = str(uuid.UUID(value))
    if parsed != value:
        raise ValueError('Use a canonical UUID.')
    return parsed


def _content():
    from .gpo_content import COMPONENTS, PROFILE_COMPONENTS
    return COMPONENTS, PROFILE_COMPONENTS


def artifact_bytes(component):
    """Read an operator-provided immutable bundle, never a received path/URL."""
    configured = getattr(settings, 'IPMS_SECURITY_GPO_ARTIFACT_DIR', '')
    if not configured:
        raise ValidationError('GPO artifact cache is unavailable.')
    try:
        directory = Path(configured).resolve(strict=True)
        filename = component['artifact_sha256'] + '.ipmsgpo'
        path = directory / filename
        before = path.lstat()
        if (not directory.is_dir() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or getattr(before, 'st_file_attributes', 0) & 0x400
                or before.st_size != component['artifact_size'] or not 0 < before.st_size <= MAX_ARTIFACT):
            raise ValueError()
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as handle:
            actual = os.fstat(handle.fileno())
            if (actual.st_nlink != 1 or not stat.S_ISREG(actual.st_mode)
                    or (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)):
                raise ValueError()
            content = handle.read(MAX_ARTIFACT + 1)
        if len(content) != component['artifact_size'] or hashlib.sha256(content).hexdigest() != component['artifact_sha256']:
            raise ValueError()
        return content
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValidationError('GPO artifact cache is unavailable or changed.') from exc


def baseline_options():
    components, profiles = _content()
    results = []
    for baseline in BASELINES:
        ids = list(dict.fromkeys(item for profile in baseline.profiles
                                for item in profiles.get((baseline.id, profile), ())))
        rows = []
        for backup_id in ids:
            component = components[(baseline.id, backup_id)]
            try:
                artifact_bytes(component)
                available = True
            except ValidationError:
                available = False
            rows.append({'id': backup_id, 'name': component['name'], 'scope': component['scope'],
                         'purpose': component['purpose'], 'artifact_sha256': component['artifact_sha256'],
                         'available': available})
        results.append({'id': baseline.id, 'name': baseline.name, 'provider': 'microsoft',
                        'revision': baseline.revision, 'profiles': list(baseline.profiles), 'components': rows})
    return results


def version_supported(value, *, portal=False):
    return bool(isinstance(value, str) and re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}', value)
                and tuple(map(int, value.split('.'))) >= ((0, 2, 34) if portal else (0, 2, 32)))


def active_gpo_jobs(tenant_id, *, enrollment_id=None):
    # Unclaimed expired offers have no execution authority. A claimed or
    # ambiguous write always remains a maintenance fence, regardless of time.
    jobs = GpoImportJob.objects.filter(tenant_id=tenant_id, status__in=ACTIVE).filter(
        Q(claimed_at__isnull=False) | Q(status='reconciliation_required') | Q(expires_at__gt=timezone.now()))
    return jobs.filter(enrollment_id=enrollment_id) if enrollment_id is not None else jobs


def maintenance_pending(enrollment, system):
    from ipms.apps.agent_pki.deployment import pending_agent_deployments
    from ipms.apps.agent_pki.lifecycle import ACTIVE_STATUSES
    from ipms.apps.agent_pki.models import AgentLifecycleJob
    return (AgentLifecycleJob.objects.filter(enrollment=enrollment, status__in=ACTIVE_STATUSES).exists()
            or pending_agent_deployments(enrollment, system).exists())


def _ready(system, enrollment, report, configured_domain, *, portal=False):
    now = timezone.now()
    return bool(system and enrollment and report and enrollment.status == 'active' and enrollment.platform == 'windows'
                and system.tenant_id == enrollment.tenant_id and system.inventory_source == 'agent'
                and system.source_id == enrollment.device_uri and system.operating_system_role == 'domain-controller'
                and system.domain_name.lower() == configured_domain and report.domain_dns_name == configured_domain
                and (not system.fqdn or system.fqdn.lower() == report.dc_fqdn)
                and version_supported(system.agent_version, portal=portal) and version_supported(report.agent_version, portal=portal)
                and report.role == 'writable-domain-controller' and report.gpmc_available
                and report.result_code == 'ready_for_approval' and report.domain_guid and report.forest_dns_name and report.dc_fqdn
                and now - timedelta(minutes=5) < report.observed_at <= now
                and enrollment.last_heartbeat_at and now - timedelta(minutes=5) < enrollment.last_heartbeat_at <= now
                and not maintenance_pending(enrollment, system))


def executor_options(tenant, config):
    enrollments = {row.device_uri: row for row in AgentEnrollment.objects.filter(tenant=tenant, platform='windows')}
    reports = {row.enrollment_id: row for row in GpoExecutorReport.objects.filter(enrollment__tenant=tenant)}
    results = []
    for system in WindowsServer.objects.filter(tenant=tenant, operating_system_role='domain-controller',
                                               domain_name__iexact=config.domain_name, inventory_source='agent').order_by('hostname')[:250]:
        enrollment = enrollments.get(system.source_id)
        report = reports.get(enrollment.id) if enrollment else None
        results.append({'system_id': str(system.id), 'hostname': system.hostname, 'agent_version': system.agent_version,
                        'state': report.result_code if report else 'not_reported', 'domain_name': system.domain_name,
                        'domain_guid': report.domain_guid if report else '', 'forest_name': report.forest_dns_name if report else '',
                        'dc_fqdn': report.dc_fqdn if report else '', 'eligible': _ready(system, enrollment, report, config.domain_name, portal=True),
                        'last_seen': report.observed_at.isoformat() if report else None})
    return results


def job_projection(job, *, user=None, include_review=False):
    from .gpo_approvals import approval_blocker, is_portal, review_document
    assigned = job.assignment
    blocker = approval_blocker(job, user)
    review = None
    if include_review:
        try:
            review = review_document(job)
        except ValidationError:
            blocker = blocker or 'artifact_unavailable'
        if blocker is None and not _scope_current(job, job.enrollment, job.tenant, lock=False):
            blocker = 'scope_changed'

    return {'id': str(job.id), 'status': job.status, 'baseline_id': assigned['baseline_id'],
            'backup_id': assigned['backup_id'], 'tier': str(assigned['target_tier']),
            'pilot_display_name': job.pilot_display_name, 'hostname': job.system.hostname,
            'requested_at': job.requested_at.isoformat(), 'completed_at': job.completed_at.isoformat() if job.completed_at else None,
            'error_code': job.error_code, 'gpo_guid': job.gpo_guid or None,
            'requested_by': str(job.requested_by_id) if job.requested_by_id else None,
            'requested_by_name': job.requested_by.username if job.requested_by else '',
            'expires_at': job.expires_at.isoformat(), 'input_digest': job.input_digest,
            'dc_fqdn': assigned.get('executor_dc_fqdn', ''),
            'approval_mode': 'portal' if is_portal(job) else 'local',
            'approved_by': str(job.approved_by_id) if job.approved_by_id else None,
            'approved_by_name': job.approved_by.username if job.approved_by else None,
            'approved_at': job.approved_at.isoformat() if job.approved_at else None,
            'four_eyes_required': job.four_eyes_required, 'policy_revision': job.policy_revision,
            'can_approve': blocker is None, 'approval_blocker': blocker, 'review': review,
            'approval_document': assigned if job.status in PRE_EXECUTION and timezone.now() < job.expires_at else None}


def _audit(job, action, outcome='succeeded'):
    AuditEvent.objects.create(tenant=job.tenant, actor=str(job.requested_by_id or 'agent'), action=action,
                             object_type='security_gpo_import', object_id=str(job.id), outcome=outcome,
                             details={'status': job.status, 'error_code': job.error_code})


def expire_jobs(tenant):
    for job in GpoImportJob.objects.select_for_update().filter(tenant=tenant, status__in=ACTIVE, expires_at__lte=timezone.now()).exclude(status='reconciliation_required'):
        if job.claimed_at:
            job.status, job.error_code = 'reconciliation_required', 'gpo_reconciliation_required'
        else:
            job.status, job.error_code = 'expired', 'gpo_job_expired'
            job.completed_at = timezone.now()
        job.save()
        _audit(job, 'security.gpo_import_expired')


def queue_job(tenant, user, config, data):
    keys = {'revision', 'system_id', 'baseline_id', 'backup_id', 'tier', 'target', 'version', 'idempotency_key'}
    if not isinstance(data, dict) or set(data) != keys or type(data['revision']) is not int:
        raise ParseError('Supply exactly the documented GPO import selection.')
    try:
        job_id, system_id = uuid_text(data['idempotency_key']), uuid_text(data['system_id'])
    except (ValueError, TypeError, AttributeError) as exc:
        raise ParseError('The GPO request identity is invalid.') from exc
    if any(not isinstance(data[key], str) for key in ('baseline_id', 'backup_id', 'tier', 'target', 'version')):
        raise ParseError('The GPO selection is invalid.')
    try:
        request_digest = digest({'domain_id': str(config.id), **data})
    except (UnicodeError, ValueError, TypeError) as exc:
        raise ParseError('The GPO selection encoding is invalid.') from exc
    from .gpo_approvals import scoped, policy_for, authorization_for
    if data['tier'] not in ('0', '1', '2'):
        raise ParseError('Select one concrete tier.')
    if not scoped(user, tenant, config, data['tier']):
        raise PermissionDenied('An explicit domain/tier grant is required.')
    existing = GpoImportJob.objects.filter(pk=job_id).select_related('system').first()
    if existing:
        if existing.tenant_id != tenant.id:
            raise NotFound('GPO request not found.')
        if existing.request_sha256 != request_digest or existing.requested_by_id != user.id:
            raise PublicApiError('security_gpo_request_conflict', status_code=409)
        return existing
    if config.revision != data['revision']:
        raise PublicApiError('security_domain_revision_changed', status_code=409)
    validate_settings({key: getattr(config, key) for key in ('domain_name', 'tier_ous', 'gpo_name_template', 'baseline_order')})
    components, profiles = _content()
    baseline = BY_ID.get(data['baseline_id'])
    component = components.get((data['baseline_id'], data['backup_id']))
    if not baseline or not component or data['tier'] not in ('0', '1', '2') or not config.tier_ous[data['tier']]:
        raise ParseError('Select an available component and a configured tier.')
    candidates = [profile for profile in baseline.profiles if data['backup_id'] in profiles.get((baseline.id, profile), ())]
    if not candidates or (candidates == ['domain-controller'] and data['tier'] != '0') or (component['scope'] == 'domain' and data['tier'] != '0'):
        raise ParseError('Domain-wide and DC-only components require a Tier 0 plan.')
    profile = candidates[0]
    name = render_name(config.gpo_name_template, data['tier'], 'U' if component['scope'] == 'user' else 'C',
                       data['target'], component['purpose'], data['version'], pilot=True, component_suffix=data['backup_id'][1:9].lower())
    system = WindowsServer.objects.select_for_update().filter(pk=system_id, tenant=tenant).first()
    enrollment = AgentEnrollment.objects.filter(tenant=tenant, device_uri=system.source_id).first() if system else None
    report = GpoExecutorReport.objects.filter(enrollment=enrollment).first() if enrollment else None
    if not _ready(system, enrollment, report, config.domain_name, portal=True):
        raise PublicApiError('security_gpo_executor_unavailable', status_code=409)
    try:
        artifact_bytes(component)
    except ValidationError as exc:
        raise PublicApiError('security_gpo_artifact_unavailable', status_code=409) from exc
    expire_jobs(tenant)
    if GpoImportJob.objects.filter(tenant=tenant, domain_guid=report.domain_guid, status__in=ACTIVE).exists():
        raise PublicApiError('security_gpo_domain_busy', status_code=409)
    if GpoImportJob.objects.filter(tenant=tenant, domain_guid=report.domain_guid, pilot_name_key=name.casefold()).exists():
        raise PublicApiError('security_gpo_pilot_exists', status_code=409)
    if GpoImportJob.objects.filter(tenant=tenant).count() >= 10000:
        raise PublicApiError('security_gpo_job_limit', status_code=409)
    expires = (timezone.now() + timedelta(hours=1)).replace(microsecond=0)
    policy, auth = policy_for(tenant), authorization_for(config)
    assignment = {'schema': 2, 'approval_mode': 'portal', 'job_id': job_id, 'operation': 'create_unlinked_pilot',
                  'domain_dns_name': config.domain_name, 'domain_guid': report.domain_guid,
                  'forest_dns_name': report.forest_dns_name, 'executor_dc_fqdn': report.dc_fqdn,
                  'scope_id': str(config.id), 'scope_revision': config.revision, 'target_tier': int(data['tier']),
                  'baseline_id': baseline.id, 'profile': profile, 'backup_id': data['backup_id'],
                  'artifact_sha256': component['artifact_sha256'], 'pilot_display_name': name,
                  'expires_at': expires.strftime('%Y-%m-%dT%H:%M:%SZ')}
    assignment['input_digest'] = digest(assignment)
    job = GpoImportJob.objects.create(id=job_id, tenant=tenant, domain=config, enrollment=enrollment, system=system,
                                      requested_by=user, domain_guid=report.domain_guid, request_sha256=request_digest,
                                      policy_revision=policy.revision, four_eyes_required=policy.four_eyes_required,
                                      authorization_revision=auth.revision, status='awaiting_approval',
                                      input_digest=assignment['input_digest'], assignment=assignment,
                                      pilot_display_name=name, pilot_name_key=name.casefold(), expires_at=expires)
    _audit(job, 'security.gpo_import_requested')
    return job


def _reject():
    raise ValidationError('The GPO exchange is invalid.')


def _executor_report(enrollment, data, version):
    fields = {'schema', 'domain_dns_name', 'domain_guid', 'forest_dns_name', 'dc_fqdn', 'role', 'gpmc_available', 'result_code'}
    if (not isinstance(data, dict) or set(data) != fields
            or any(not isinstance(data[key], str) for key in fields - {'schema', 'gpmc_available'})
            or type(data['schema']) is not int or data['schema'] != 1
            or type(data['gpmc_available']) is not bool or data['role'] not in ('writable-domain-controller', 'read-only-domain-controller', 'not-domain-controller', 'unknown')
            or data['result_code'] not in EXECUTOR_CODES or not version_supported(version)):
        _reject()
    try:
        normalized = {}
        for key in ('domain_dns_name', 'forest_dns_name', 'dc_fqdn'):
            if not isinstance(data[key], str):
                raise ValueError()
            normalized[key] = domain_name(data[key]) if data[key] else ''
            if normalized[key] != data[key]:
                raise ValueError()
        normalized['domain_guid'] = uuid_text(data['domain_guid']) if data['domain_guid'] else ''
        if data['result_code'] == 'ready_for_approval' and (data['role'] != 'writable-domain-controller'
                or not data['gpmc_available'] or not all(normalized.values())):
            raise ValueError()
    except (ValueError, TypeError, AttributeError, ParseError):
        _reject()
    GpoExecutorReport.objects.update_or_create(enrollment=enrollment, defaults={**normalized, 'agent_version': version,
                                               'role': data['role'], 'gpmc_available': data['gpmc_available'],
                                               'result_code': data['result_code'], 'observed_at': timezone.now()})


def _scope_current(job, enrollment, tenant, *, lock=True):
    from .gpo_approvals import is_portal, policy_current, approval_current
    assignment = job.assignment
    base_fields = {'schema', 'job_id', 'operation', 'domain_dns_name', 'domain_guid', 'forest_dns_name',
                   'executor_dc_fqdn', 'scope_id', 'scope_revision', 'target_tier', 'baseline_id', 'profile',
                   'backup_id', 'artifact_sha256', 'pilot_display_name', 'expires_at', 'input_digest'}
    portal = is_portal(job)
    if (not isinstance(assignment, dict) or set(assignment) != base_fields | ({'approval_mode'} if portal else set())
            or type(assignment['schema']) is not int or assignment['schema'] != (2 if portal else 1)
            or assignment['operation'] != 'create_unlinked_pilot'
            or assignment['job_id'] != str(job.pk) or assignment['scope_id'] != str(job.domain_id)
            or assignment['domain_guid'] != job.domain_guid or assignment['pilot_display_name'] != job.pilot_display_name
            or assignment['expires_at'] != job.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')
            or assignment['input_digest'] != job.input_digest
            or digest({key: value for key, value in assignment.items() if key != 'input_digest'}) != job.input_digest):
        return False
    if portal and (not policy_current(job, tenant) or (job.approved_at and not approval_current(job, tenant))):
        return False
    configs, systems = DomainSecuritySettings.objects, WindowsServer.objects
    if lock:
        configs, systems = configs.select_for_update(), systems.select_for_update()
    config = configs.get(pk=job.domain_id)
    system = systems.get(pk=job.system_id)
    report = GpoExecutorReport.objects.filter(enrollment=enrollment).first()
    components, profiles = _content()
    component = components.get((assignment['baseline_id'], assignment['backup_id']))
    return bool(tenant.status == 'active' and job.tenant_id == tenant.id and job.enrollment_id == enrollment.id
                and job.requested_by and has_tenant_permission(job.requested_by, tenant, Permission.SECURITY_GPO_IMPORTS_RUN)
                and config.revision == assignment['scope_revision'] and config.domain_name == assignment['domain_dns_name']
                and _ready(system, enrollment, report, config.domain_name, portal=portal)
                and report.domain_guid == assignment['domain_guid'] and report.forest_dns_name == assignment['forest_dns_name']
                and report.dc_fqdn == assignment['executor_dc_fqdn']
                and component and component['artifact_sha256'] == assignment['artifact_sha256']
                and assignment['backup_id'] in profiles.get((assignment['baseline_id'], assignment['profile']), ()))


def _invalidate(job, reason='scope_changed'):
    if job.status in ACTIVE and job.status != 'reconciliation_required':
        job.status = 'reconciliation_required' if job.claimed_at else 'failed'
        job.error_code = 'gpo_reconciliation_required' if job.claimed_at else reason
        if not job.claimed_at:
            job.completed_at = timezone.now()
        job.save()
        _audit(job, 'security.gpo_import_scope_changed')


def withdraw_gpo_jobs(*, tenant_id, actor_id=None, enrollment_id=None, reason):
    """Caller holds the tenant lock; withdrawal cannot revive on reactivation."""
    if not transaction.get_connection().in_atomic_block:
        raise ValidationError('GPO withdrawal requires a transaction.')
    jobs = GpoImportJob.objects.select_for_update().filter(tenant_id=tenant_id, status__in=ACTIVE)
    if actor_id is not None:
        jobs = jobs.filter(Q(requested_by_id=actor_id) | Q(approved_by_id=actor_id))
    if enrollment_id is not None:
        jobs = jobs.filter(enrollment_id=enrollment_id)
    count = 0
    for job in jobs:
        _invalidate(job, reason)
        count += 1
    return count


def _result(job, document):
    status, code, guid, evidence = (document[key] for key in ('status', 'result_code', 'gpo_guid', 'evidence'))
    if (not isinstance(status, str) or not isinstance(code, str)
            or status not in ('awaiting_local_approval', 'awaiting_portal_approval', 'staged', 'failed', 'requires_reconciliation') or code not in RESULT_CODES):
        _reject()
    if guid is not None:
        try:
            if uuid_text(guid) in DEFAULT_GPO_IDS:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            _reject()
    if job.gpo_guid and guid != job.gpo_guid:
        _reject()
    if status == 'staged':
        expected = {'computer_enabled': False, 'user_enabled': False, 'unlinked': True,
                    'domain_dns_name': job.assignment['domain_dns_name'], 'domain_guid': job.domain_guid,
                    'dc_fqdn': job.assignment['executor_dc_fqdn']}
        if (not job.claimed_at or not guid or code != 'gpo_staged_unlinked' or not isinstance(evidence, dict)
                or set(evidence) != set(expected) or evidence != expected
                or any(type(evidence[key]) is not bool for key in ('computer_enabled', 'user_enabled', 'unlinked'))):
            _reject()
    elif evidence is not None:
        _reject()
    receipt_digest = digest({key: document[key] for key in ('status', 'result_code', 'gpo_guid', 'evidence')})
    if job.status in TERMINAL:
        if (not job.result_digest and not job.claimed_at and job.status in ('expired', 'failed')
                and status == 'failed' and guid is None
                and code in ('gpo_job_expired', 'gpo_authority_expired', 'gpo_enrollment_changed')):
            # Close a prepared local journal after server-side expiry/withdrawal.
            # Preserve the server's terminal reason and never grant authority.
            job.result_digest = receipt_digest
            job.save(update_fields=('result_digest',))
            return
        if job.result_digest != receipt_digest:
            _reject()
        return
    if status in ('awaiting_local_approval', 'awaiting_portal_approval'):
        from .gpo_approvals import is_portal
        portal = is_portal(job)
        if ((status == 'awaiting_portal_approval') != portal
                or job.status not in PRE_EXECUTION or guid is not None
                or code != ('gpo_portal_approval_required' if portal else 'gpo_local_approval_required')):
            _reject()
        if job.approved_at:
            return  # An in-flight waiting report cannot replace a newer approval.
        changed = job.status != 'awaiting_approval'
        job.status, job.error_code = 'awaiting_approval', code
        job.save()
        if changed:
            _audit(job, 'security.gpo_import_awaiting_approval')
        return
    if status == 'staged':
        job.status = 'staged'
    elif status == 'requires_reconciliation' or guid or job.claimed_at:
        # A timed-out or partially reported write cannot release the domain fence.
        job.status = 'reconciliation_required'
    else:
        job.status = 'failed'
    job.error_code = '' if job.status == 'staged' else code
    job.gpo_guid = guid or job.gpo_guid
    job.result_digest = receipt_digest
    job.result_evidence = evidence or {}
    job.completed_at = timezone.now() if job.status in TERMINAL else None
    job.save()
    _audit(job, 'security.gpo_import_result')


@transaction.atomic
def security_gpo_exchange(enrollment, document, *, artifact=False):
    base = {'type', 'schema_version', 'device_uri', 'correlation_id', 'action'}
    action_fields = {'poll': {'agent_version', 'executor'}, 'lookup': {'job_id', 'input_digest', 'agent_version', 'executor'},
                     'claim': {'job_id', 'input_digest'}, 'artifact': {'job_id', 'input_digest'},
                     'result': {'job_id', 'input_digest', 'status', 'result_code', 'gpo_guid', 'evidence'}}
    if not isinstance(document, dict) or not isinstance(document.get('action'), str):
        _reject()
    action = document['action']
    if (action not in action_fields or set(document) != base | action_fields[action]
            or document['type'] != 'security_gpo' or document['schema_version'] != '1'
            or document['device_uri'] != enrollment.device_uri or artifact != (action == 'artifact')
            or not isinstance(document['correlation_id'], str) or not 1 <= len(document['correlation_id']) <= 128):
        _reject()
    tenant = Tenant.objects.select_for_update().get(pk=enrollment.tenant_id)
    enrollment = AgentEnrollment.objects.select_for_update().get(pk=enrollment.id)
    if enrollment.platform != 'windows' or enrollment.status not in ('active', 'suspended'):
        _reject()
    from .gpo_approvals import is_portal, approval_current, approval_object
    response = {'status': 'accepted', 'correlation_id': document['correlation_id']}
    if action != 'result':
        expire_jobs(tenant)
    if action in ('poll', 'lookup'):
        _executor_report(enrollment, document['executor'], document['agent_version'])
    if action == 'poll':
        job = GpoImportJob.objects.select_for_update(of=('self',)).filter(tenant=tenant, enrollment=enrollment, status__in=PRE_EXECUTION).select_related('requested_by').order_by('requested_at').first()
        if job and not _scope_current(job, enrollment, tenant):
            _invalidate(job)
            job = None
        return {**response, 'gpo_job': job.assignment if job else None,
                'gpo_approval': approval_object(job) if job and approval_current(job, tenant) else None}
    try:
        job_id = uuid_text(document['job_id'])
    except (ValueError, TypeError, AttributeError):
        _reject()
    job = GpoImportJob.objects.select_for_update(of=('self',)).filter(pk=job_id, tenant=tenant, enrollment=enrollment).select_related('requested_by').first()
    if not job or document['input_digest'] != job.input_digest:
        _reject()
    if action == 'result':
        _result(job, document)
        return response
    if action == 'lookup':
        if job.status in PRE_EXECUTION and not _scope_current(job, enrollment, tenant):
            _invalidate(job)
        return {**response, 'gpo_job': job.assignment if job.status in ACTIVE else None,
                'gpo_approval': approval_object(job) if job.status in ACTIVE and approval_current(job, tenant) else None}
    current = _scope_current(job, enrollment, tenant) and timezone.now() < job.expires_at
    if not current:
        _invalidate(job)
    if action == 'artifact':
        if not current or job.status not in (*PRE_EXECUTION, 'running') or (is_portal(job) and not approval_current(job, tenant)):
            _reject()
        components, _ = _content()
        content = artifact_bytes(components[(job.assignment['baseline_id'], job.assignment['backup_id'])])
        return content, job.assignment['artifact_sha256']
    approved = not is_portal(job) or approval_current(job, tenant)
    if current and job.status in PRE_EXECUTION and not approved:
        _invalidate(job, 'gpo_portal_approval_required')
    if current and approved and job.status in PRE_EXECUTION:
        job.status, job.claimed_at, job.error_code = 'running', timezone.now(), ''
        job.save()
        _audit(job, 'security.gpo_import_claimed')
        mode = 'execute'
    elif job.status == 'running' and current:
        mode = 'observe'
    elif job.status == 'reconciliation_required':
        mode = 'reconcile'
    else:
        mode = 'cancelled'
    claim = {'authorized': mode == 'execute', 'mode': mode, 'job': job.assignment}
    if mode == 'execute' and is_portal(job):
        claim['approval'] = approval_object(job)
    return {**response, 'gpo_claim': claim}
