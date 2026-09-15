# File Name: gpo_production.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Snapshot-bound production GPO preparation and separately approved changes.
import copy
import re
import uuid
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.exceptions import ParseError, PermissionDenied
from rest_framework.response import Response

from ipms.apps.agent_pki.models import AgentEnrollment
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from .domains import DomainSettingsView, domain_name, ou_identity, render_name, validate_settings
from .gpo_approvals import authorization_for, fresh_actor, policy_for, scoped, visible_jobs
from .gpo_jobs import (ACTIVE, DEFAULT_GPO_IDS, _audit, _content, _ready, artifact_bytes, canonical, digest,
                       executor_options, expire_jobs, job_projection, uuid_text)
from .models import DomainSecuritySettings, GpoExecutorReport, GpoImportJob, ManagedGpoPolicy
from .views import SecurityReadView, query

INSPECT = 'inspect_managed_gpo'
IMPORT = 'import_managed_gpo'
LINK = 'link_managed_gpo'
ACTIVATE = 'activate_managed_gpo'
DEACTIVATE = 'deactivate_managed_gpo'
WRITES = (IMPORT, LINK, ACTIVATE, DEACTIVATE)
SUCCESS = {INSPECT: ('inspected', 'gpo_inspected'), IMPORT: ('staged', 'gpo_prepared'),
           LINK: ('linked', 'gpo_linked'), ACTIVATE: ('activated', 'gpo_activated'),
           DEACTIVATE: ('deactivated', 'gpo_deactivated')}
FIELDS = set('schema approval_mode job_id operation domain_dns_name domain_guid forest_dns_name executor_dc_fqdn '
             'scope_id scope_revision target_tier baseline_id profile backup_id artifact_sha256 pilot_display_name '
             'expires_at input_digest managed_id managed_revision gpo_guid owner_marker target_ous link_orders '
             'preflight_id expected_state intended_operation safety_review'.split())
FALSE_REVIEW = {'management_access': False, 'recovery_access': False}
HEX = re.compile('[a-f0-9]{64}')


def production(job):
    return isinstance(job.assignment, dict) and type(job.assignment.get('schema')) is int and job.assignment['schema'] == 3


def inspecting(job):
    return production(job) and job.assignment.get('operation') == INSPECT


def _invalid(message='Invalid managed GPO state.'):
    raise ValidationError(message)


def _bounded(value, maximum, *, empty=False):
    return (isinstance(value, str) and (empty or bool(value)) and len(value) <= maximum
            and not any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value))


def _guid(value):
    try:
        return uuid_text(value)
    except (ValueError, TypeError, AttributeError):
        _invalid()


def _sha(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _integer(value, low=0, high=2**32-1):
    return type(value) is int and low <= value <= high


def domain_root(domain):
    return ','.join('DC=' + label for label in domain.split('.'))


def _domain_component(assignment):
    component = _content()[0].get((assignment.get('baseline_id'), assignment.get('backup_id')))
    return bool(component and component['scope'] == 'domain')


def _target_identity(dn, domain, *, root=False):
    if root:
        if not isinstance(dn, str) or dn.casefold() != domain_root(domain).casefold():
            raise ParseError('The domain root must match the selected DNS domain.')
        return tuple(('DC', label) for label in domain.split('.'))
    return ou_identity(dn, domain)


def _same_target(left, right, assignment):
    try:
        domain, root = assignment['domain_dns_name'], _domain_component(assignment)
        return _target_identity(left, domain, root=root) == _target_identity(right, domain, root=root)
    except ParseError:
        return False


def _target_ou(dn, assignment):
    return any(_same_target(dn, configured, assignment) for configured in assignment['target_ous'])


def compact_purpose(baseline_id, component):
    """Readable aliases retain semantic distinctions without vendor backup UUIDs."""
    base = baseline_id.removeprefix('microsoft-windows-')
    if base.startswith('server-'):
        prefix = 'MS-WS' + base.removeprefix('server-')
    else:
        prefix = 'MS-W' + base.upper()
    name = component['name'].lower()
    if 'domain security' in name:
        purpose = 'DomainSecurity'
    elif 'virtualization' in name:
        purpose = 'DC-VBS' if 'domain controller' in name else 'VBS'
    elif 'credential guard' in name:
        purpose = 'CredentialGuard'
    elif 'domain controller' in name:
        purpose = 'DC'
    elif 'member server' in name:
        purpose = 'Member'
    elif 'bitlocker' in name:
        purpose = 'BitLocker'
    elif 'defender' in name:
        purpose = 'Defender'
    elif 'internet explorer' in name:
        purpose = 'IE'
    elif 'user' in name:
        purpose = 'User'
    else:
        # Remove only known release/product prefixes; preserve the remaining
        # semantic suffix instead of silently merging different components.
        purpose = re.sub(r'^(?:MSFT|SCM) Windows .*? - ', '', component['name'])
        purpose = re.sub('[^A-Za-z0-9]', '', purpose)
        if len(purpose) > 48:
            purpose = component['purpose']
    if not purpose:
        raise ParseError('The component has no stable naming alias.')
    return prefix + '-' + purpose


def semantic_purpose(baseline_id, component):
    return ('U-' if component['scope'] == 'user' else 'C-') + compact_purpose(baseline_id, component)


def _links(value):
    if not isinstance(value, list) or len(value) > 128:
        _invalid()
    seen = set()
    for link in value:
        if (not isinstance(link, dict) or set(link) != {'guid', 'domain', 'dn', 'kind', 'enabled', 'enforced', 'order'}
                or not _bounded(link['dn'], 2048) or link['kind'] not in ('ou', 'domain', 'site')
                or type(link['enabled']) is not bool or type(link['enforced']) is not bool
                or not _integer(link['order'], 1, 128)):
            _invalid()
        _guid(link['guid'])
        try:
            if domain_name(link['domain']) != link['domain']:
                _invalid()
        except ParseError:
            _invalid()
        identity = (link['guid'], link['domain'], link['dn'], link['kind'])
        if identity in seen:
            _invalid()
        seen.add(identity)


def validate_snapshot(value, assignment):
    """Validate exact bounded wire types and directory identity; never trust browser state."""
    try:
        size = len(canonical(value))
    except (ValueError, TypeError, UnicodeError):
        _invalid()
    if size > 16384:
        _invalid('The directory snapshot exceeds the bounded GPO transport budget.')
    if (not isinstance(value, dict) or set(value) != {'schema', 'gpo', 'ous', 'name_available'}
            or type(value['schema']) is not int or value['schema'] != 1 or type(value['name_available']) is not bool
            or not isinstance(value['ous'], list) or len(value['ous']) > 32):
        _invalid()
    if len(value['ous']) != len(assignment['target_ous']) or any(
            not isinstance(ou, dict) or not _same_target(ou.get('dn'), configured, assignment)
            for ou, configured in zip(value['ous'], assignment['target_ous'], strict=True)):
        _invalid()
    guids = set()
    for ou in value['ous']:
        if (not isinstance(ou, dict) or set(ou) != {'dn', 'guid', 'usn', 'blocked', 'links', 'inherited_links'}
                or type(ou['blocked']) is not bool or not isinstance(ou['usn'], str)
                or not re.fullmatch('0|[1-9][0-9]{0,19}', ou['usn'])):
            _invalid()
        _guid(ou['guid'])
        if ou['guid'] in guids:
            _invalid()
        guids.add(ou['guid'])
        try:
            _target_identity(ou['dn'], assignment['domain_dns_name'], root=_domain_component(assignment))
        except ParseError:
            _invalid()
        _links(ou['links'])
        _links(ou['inherited_links'])
        root_target = _domain_component(assignment)
        if root_target and (assignment['target_tier'] != 0 or ou['guid'] != assignment['domain_guid'] or ou['inherited_links']):
            _invalid('The domain-root observation must bind the Tier 0 domain identity.')
        if any(link['kind'] != ('domain' if root_target else 'ou') or not _same_target(link['dn'], ou['dn'], assignment)
               or link['domain'] != assignment['domain_dns_name']
               for link in ou['links']) or [link['order'] for link in ou['links']] != list(range(1, len(ou['links']) + 1)):
            _invalid()
    gpo = value['gpo']
    if gpo is not None:
        fields = set('guid name description computer_enabled user_enabled computer_ds computer_sysvol user_ds '
                     'user_sysvol security_digest wmi_filter links'.split())
        if (not isinstance(gpo, dict) or set(gpo) != fields or not _bounded(gpo['name'], 240)
                or not _bounded(gpo['description'], 2048, empty=True) or not _bounded(gpo['wmi_filter'], 2048, empty=True)
                or type(gpo['computer_enabled']) is not bool or type(gpo['user_enabled']) is not bool
                or any(not _integer(gpo[key]) for key in ('computer_ds', 'computer_sysvol', 'user_ds', 'user_sysvol'))
                or not _sha(gpo['security_digest']) or _guid(gpo['guid']) in DEFAULT_GPO_IDS):
            _invalid()
        _links(gpo['links'])
        if gpo['computer_ds'] != gpo['computer_sysvol'] or gpo['user_ds'] != gpo['user_sysvol']:
            _invalid('Directory and SYSVOL versions disagree.')
    return value


def managed_projection(policy):
    active_name = None
    if active_binding(policy, timezone.now(), computer_only=False):
        active_name = policy.active_job.result_evidence['state']['gpo']['name']
    return {'id': str(policy.pk), 'revision': policy.revision, 'display_name': policy.display_name,
            'active_display_name': active_name,
            'gpo_guid': policy.gpo_guid or None, 'tier': str(policy.tier), 'baseline_id': policy.baseline_id,
            'backup_id': policy.backup_id, 'profile': policy.profile, 'target': policy.target, 'version': policy.version,
            'state': policy.state, 'origin_job_id': str(policy.origin_job_id) if policy.origin_job_id else None,
            'staged_job_id': str(policy.staged_job_id) if policy.staged_job_id else None,
            'active_job_id': str(policy.active_job_id) if policy.active_job_id else None}


def policy_for_job(job, *, lock=False):
    rows = ManagedGpoPolicy.objects.select_for_update() if lock else ManagedGpoPolicy.objects
    return rows.filter(pk=job.assignment.get('managed_id'), tenant_id=job.tenant_id, domain_id=job.domain_id,
                       domain_guid=job.domain_guid).first()


def _selection(tenant, user, config, data):
    fields = set('revision system_id baseline_id backup_id tier target version idempotency_key operation managed_id adopt_job_id'.split())
    if (not isinstance(data, dict) or set(data) not in (fields, fields | {'domain_root_confirmed'}) or type(data['revision']) is not int
            or any(not isinstance(data[key], str) for key in fields - {'revision', 'managed_id', 'adopt_job_id'})
            or type(data.get('domain_root_confirmed', False)) is not bool
            or data['tier'] not in ('0', '1', '2') or data['operation'] not in WRITES):
        raise ParseError('Supply exactly the documented managed GPO selection.')
    try:
        for key in ('system_id', 'idempotency_key'):
            uuid_text(data[key])
        for key in ('managed_id', 'adopt_job_id'):
            if data[key] is not None:
                uuid_text(data[key])
    except (ValueError, TypeError):
        raise ParseError('Invalid managed GPO identity.')
    if data['managed_id'] and data['adopt_job_id']:
        raise ParseError('Select one managed or historical identity.')
    if not scoped(user, tenant, config, data['tier']):
        raise PermissionDenied('An explicit domain/tier grant is required.')
    if config.revision != data['revision']:
        raise PublicApiError('security_domain_revision_changed', status_code=409)
    validate_settings({key: getattr(config, key) for key in ('domain_name', 'tier_ous', 'gpo_name_template', 'baseline_order')})
    components, profiles = _content()
    component = components.get((data['baseline_id'], data['backup_id']))
    if not component or component['scope'] != 'domain' and not config.tier_ous[data['tier']]:
        raise ParseError('Select an available component and configured tier.')
    root_operation = component['scope'] == 'domain' and data['operation'] != IMPORT
    if root_operation and not data.get('domain_root_confirmed', False):
        raise PublicApiError('security_gpo_domain_root_confirmation_required', status_code=409)
    if not root_operation and data.get('domain_root_confirmed', False):
        raise ParseError('Domain-root confirmation is valid only for an explicit domain-wide action.')
    from .catalog import BY_ID
    candidates = [profile for profile in BY_ID[data['baseline_id']].profiles
                  if data['backup_id'] in profiles.get((data['baseline_id'], profile), ())]
    if not candidates or (candidates == ['domain-controller'] or component['scope'] == 'domain') and data['tier'] != '0':
        raise ParseError('DC and domain components require Tier 0.')
    profile = candidates[0]
    name = render_name(config.gpo_name_template, data['tier'], 'U' if component['scope'] == 'user' else 'C',
                       data['target'], compact_purpose(data['baseline_id'], component), data['version'])
    system = WindowsServer.objects.select_for_update().filter(pk=data['system_id'], tenant=tenant).first()
    enrollment = AgentEnrollment.objects.filter(tenant=tenant, device_uri=system.source_id).first() if system else None
    report = GpoExecutorReport.objects.filter(enrollment=enrollment).first() if enrollment else None
    if (not _ready(system, enrollment, report, config.domain_name, portal=True)
            or tuple(map(int, system.agent_version.split('.'))) < (0, 2, 35)
            or tuple(map(int, report.agent_version.split('.'))) < (0, 2, 35)):
        raise PublicApiError('security_gpo_executor_unavailable', status_code=409)
    try:
        artifact_bytes(component)
    except ValidationError as exc:
        raise PublicApiError('security_gpo_artifact_unavailable', status_code=409) from exc
    return component, profile, name, system, enrollment, report


def _idle(tenant, domain_guid):
    expire_jobs(tenant)
    if GpoImportJob.objects.filter(tenant=tenant, domain_guid=domain_guid, status__in=ACTIVE).exists():
        raise PublicApiError('security_gpo_domain_busy', status_code=409)
    if GpoImportJob.objects.filter(tenant=tenant).count() >= 10000:
        raise PublicApiError('security_gpo_job_limit', status_code=409)


def _retry(tenant, user, job_id, request_digest):
    existing = GpoImportJob.objects.filter(pk=job_id).first()
    if existing:
        if existing.tenant_id != tenant.pk:
            raise PublicApiError('security_gpo_request_conflict', status_code=409)
        if existing.request_sha256 != request_digest or existing.requested_by_id != user.pk:
            raise PublicApiError('security_gpo_request_conflict', status_code=409)
    return existing


def _origin(tenant, config, data, report, component):
    origin = get_object_or_404(GpoImportJob, pk=data['adopt_job_id'], tenant=tenant, domain=config, domain_guid=report.domain_guid)
    assigned = origin.assignment
    from .gpo_approvals import approval_object
    expected = {'computer_enabled': False, 'user_enabled': False, 'unlinked': True,
                'domain_dns_name': config.domain_name, 'domain_guid': report.domain_guid,
                'dc_fqdn': assigned.get('executor_dc_fqdn')}
    valid_approval = assigned.get('schema') == 1 or (approval_object(origin) and
        digest(approval_object(origin)) == origin.approval_digest and origin.approved_at and origin.claimed_at
        and origin.requested_at.replace(microsecond=0) <= origin.approved_at <= origin.claimed_at
        and (not origin.four_eyes_required or origin.requested_by_id != origin.approved_by_id))
    if (not valid_approval or origin.status != 'staged' or origin.error_code or not origin.claimed_at or not origin.completed_at
            or not origin.requested_at <= origin.claimed_at <= origin.completed_at <= timezone.now()
            or origin.gpo_guid in DEFAULT_GPO_IDS or _guid(origin.gpo_guid) != origin.gpo_guid
            or origin.enrollment.tenant_id != tenant.pk or origin.system.tenant_id != tenant.pk
            or origin.system.source_id != origin.enrollment.device_uri
            or digest({key: value for key, value in assigned.items() if key != 'input_digest'}) != origin.input_digest
            or assigned.get('input_digest') != origin.input_digest or assigned.get('job_id') != str(origin.pk)
            or assigned.get('scope_id') != str(config.pk) or assigned.get('domain_guid') != report.domain_guid
            or assigned.get('operation') != 'create_unlinked_pilot' or assigned.get('schema') not in (1, 2)
            or origin.result_evidence != expected or any(type(origin.result_evidence.get(key)) is not bool
                for key in ('computer_enabled', 'user_enabled', 'unlinked'))
            or digest({'status': 'staged', 'result_code': 'gpo_staged_unlinked', 'gpo_guid': origin.gpo_guid,
                       'evidence': expected}) != origin.result_digest
            or assigned.get('target_tier') != int(data['tier']) or assigned.get('baseline_id') != data['baseline_id']
            or assigned.get('backup_id') != data['backup_id'] or assigned.get('artifact_sha256') != component['artifact_sha256']):
        raise PublicApiError('security_gpo_unmanaged_target', status_code=409)
    return origin


def create_preflight(tenant, user, config, data):
    component, profile, name, system, enrollment, report = _selection(tenant, user, config, data)
    request_digest = digest({'domain_id': str(config.pk), **data})
    retry = _retry(tenant, user, data['idempotency_key'], request_digest)
    if retry:
        return retry
    _idle(tenant, report.domain_guid)
    logical = digest({'tier': data['tier'], 'baseline': data['baseline_id'], 'profile': profile,
                      'purpose': semantic_purpose(data['baseline_id'], component), 'target': data['target'].casefold()})
    origin = None
    if data['managed_id']:
        policy = get_object_or_404(ManagedGpoPolicy.objects.select_for_update(), pk=data['managed_id'], tenant=tenant, domain=config)
        if policy.domain_guid != report.domain_guid or policy.logical_key != logical:
            raise PublicApiError('security_gpo_unmanaged_target', status_code=409)
    else:
        if data['operation'] != IMPORT:
            raise ParseError('Create or select a managed GPO before linking or activation.')
        policy = ManagedGpoPolicy.objects.select_for_update().filter(tenant=tenant, domain_guid=report.domain_guid, logical_key=logical).first()
        if policy:
            raise PublicApiError('security_gpo_managed_exists', status_code=409)
        if data['adopt_job_id']:
            origin = _origin(tenant, config, data, report, component)
        if ManagedGpoPolicy.objects.filter(tenant=tenant, domain_guid=report.domain_guid, name_key=name.casefold()).exists():
            raise PublicApiError('security_gpo_name_collision', status_code=409)
        policy = ManagedGpoPolicy.objects.create(tenant=tenant, domain=config, domain_guid=report.domain_guid,
            logical_key=logical, tier=int(data['tier']), baseline_id=data['baseline_id'], profile=profile,
            purpose=semantic_purpose(data['baseline_id'], component), target=data['target'], display_name=name, name_key=name.casefold(),
            version=data['version'], backup_id=data['backup_id'], gpo_guid=origin.gpo_guid if origin else '', origin_job=origin)
    if policy.state == 'reconciliation_required':
        raise PublicApiError('security_gpo_reconciliation_required', status_code=409)
    if data['operation'] != IMPORT and (not policy.gpo_guid or not policy.staged_job_id):
        raise PublicApiError('security_gpo_preflight_required', status_code=409)
    if data['operation'] != IMPORT and (policy.backup_id != data['backup_id'] or policy.version != data['version'] or policy.display_name != name):
        raise PublicApiError('security_gpo_prepared_content_changed', status_code=409)
    owner = 'IPMS managed GPO; id=' + str(policy.pk) if policy.gpo_guid else ''
    if policy.origin_job_id and policy.origin_job.assignment.get('schema') in (1, 2) and policy.staged_job_id is None:
        origin = policy.origin_job
        owner = 'IPMS disabled, unlinked pilot; job=' + str(origin.pk) + '; digest=' + origin.input_digest
    expires = (timezone.now() + timedelta(minutes=15)).replace(microsecond=0)
    targets = [] if data['operation'] == IMPORT else ([domain_root(config.domain_name)]
              if component['scope'] == 'domain' else list(config.tier_ous[data['tier']]))
    assignment = {'schema': 3, 'approval_mode': 'inspection', 'job_id': data['idempotency_key'], 'operation': INSPECT,
        'domain_dns_name': config.domain_name, 'domain_guid': report.domain_guid, 'forest_dns_name': report.forest_dns_name,
        'executor_dc_fqdn': report.dc_fqdn, 'scope_id': str(config.pk), 'scope_revision': config.revision,
        'target_tier': int(data['tier']), 'baseline_id': data['baseline_id'], 'profile': profile,
        'backup_id': data['backup_id'], 'artifact_sha256': component['artifact_sha256'], 'pilot_display_name': name,
        'expires_at': expires.strftime('%Y-%m-%dT%H:%M:%SZ'), 'managed_id': str(policy.pk), 'managed_revision': policy.revision,
        'gpo_guid': policy.gpo_guid, 'owner_marker': owner, 'target_ous': targets, 'link_orders': [1] * len(targets),
        'preflight_id': '', 'expected_state': None, 'intended_operation': data['operation'], 'safety_review': dict(FALSE_REVIEW)}
    assignment['input_digest'] = digest(assignment)
    if len(canonical(assignment)) > 24576:
        raise ParseError('The selected OU scope exceeds the bounded GPO transport budget.')
    rule, authorization = policy_for(tenant), authorization_for(config)
    job = GpoImportJob.objects.create(id=data['idempotency_key'], tenant=tenant, domain=config, enrollment=enrollment,
        system=system, requested_by=user, domain_guid=report.domain_guid, request_sha256=request_digest,
        input_digest=assignment['input_digest'], assignment=assignment, pilot_display_name=name, pilot_name_key=name.casefold(),
        policy_revision=rule.revision, four_eyes_required=rule.four_eyes_required, authorization_revision=authorization.revision,
        status='queued', expires_at=expires)
    _audit(job, 'security.gpo_inspection_requested')
    return job


def _safe_before(assignment, state):
    gpo, operation = state['gpo'], assignment['intended_operation']
    component = _content()[0].get((assignment['baseline_id'], assignment['backup_id']))
    if not component or component['scope'] == 'domain' and assignment['target_tier'] != 0:
        _invalid('Domain-scoped settings require Tier 0 authority.')
    if not state['name_available']:
        _invalid('The requested name is occupied.')
    if gpo is None:
        if assignment['gpo_guid'] or operation != IMPORT:
            _invalid()
        return
    if (gpo['guid'] != assignment['gpo_guid'] or gpo['description'] != assignment['owner_marker'] or gpo['wmi_filter']):
        _invalid('The target is not the inspected managed policy.')
    if assignment['owner_marker'].startswith('IPMS disabled, unlinked pilot;'):
        if operation != IMPORT or gpo['links'] or gpo['computer_enabled'] or gpo['user_enabled']:
            _invalid()
    if operation == LINK and (gpo['computer_enabled'] or gpo['user_enabled']):
        _invalid('Disable the managed GPO before changing links.')
    if operation in (LINK, ACTIVATE, DEACTIVATE):
        if any(link['kind'] != ('domain' if component['scope'] == 'domain' else 'ou') or link['domain'] != assignment['domain_dns_name']
               or not _target_ou(link['dn'], assignment) or link['enforced'] for link in gpo['links']):
            _invalid('The GPO has links outside the approved OU set.')
        own = []
        for ou in state['ous']:
            matches = [link for link in ou['links'] if link['guid'] == gpo['guid']]
            if any(link['enforced'] for link in matches):
                _invalid()
            own.extend(matches)
        if sorted(own, key=lambda item: (item['kind'], item['dn'], item['order'])) != sorted(gpo['links'], key=lambda item: (item['kind'], item['dn'], item['order'])):
            _invalid('OU and GPO link inventories disagree.')
        if operation == ACTIVATE and (len(own) != len(state['ous']) or not own):
            _invalid('Link the policy to every approved OU before activation.')


def _orders(policy, config, state):
    managed = {row.gpo_guid: row for row in ManagedGpoPolicy.objects.filter(tenant=policy.tenant, domain_guid=policy.domain_guid).exclude(gpo_guid='')}
    ranks = {baseline: index for index, baseline in enumerate(config.baseline_order)}
    selected = ranks[policy.baseline_id]
    result = []
    for ou in state['ous']:
        others = [link for link in ou['links'] if link['guid'] != policy.gpo_guid]
        # Later baseline layers take precedence (lower AD link order). Existing
        # unmanaged links keep their exact relative order, flags and identities.
        if len(others) >= 128:
            raise PublicApiError('security_gpo_link_conflict', status_code=409)
        index = next((i for i, link in enumerate(others) if link['guid'] in DEFAULT_GPO_IDS or (link['guid'] in managed
                      and ranks.get(managed[link['guid']].baseline_id, -1) <= selected)), len(others))
        result.append(index + 1)
    return result


def inspection_current(job, user):
    from .gpo_jobs import _scope_current
    current = bool(inspecting(job) and job.status == 'inspected' and job.completed_at and job.expires_at > timezone.now()
                and digest({'status': 'inspected', 'result_code': 'gpo_inspected', 'gpo_guid': job.gpo_guid or None,
                            'evidence': job.result_evidence}) == job.result_digest
                and scoped(user, job.tenant, job.domain, job.assignment['target_tier'])
                and _scope_current(job, job.enrollment, job.tenant, lock=False))
    if current:
        try:
            validate_snapshot(job.result_evidence['state'], job.assignment)
            _safe_before(job.assignment, job.result_evidence['state'])
        except (ValidationError, KeyError, TypeError):
            return False
    return current


def create_change(tenant, user, config, data):
    if (not isinstance(data, dict) or set(data) != {'preflight_id', 'idempotency_key', 'safety_review'}
            or not isinstance(data['safety_review'], dict) or set(data['safety_review']) != set(FALSE_REVIEW)
            or any(type(value) is not bool for value in data['safety_review'].values())):
        raise ParseError('Supply the inspected request and explicit safety review.')
    try:
        uuid_text(data['preflight_id'])
        uuid_text(data['idempotency_key'])
    except (ValueError, TypeError):
        raise ParseError('Invalid inspected request identity.')
    preflight = get_object_or_404(GpoImportJob.objects.select_for_update(), pk=data['preflight_id'], tenant=tenant, domain=config)
    if not scoped(user, tenant, config, preflight.assignment.get('target_tier')):
        raise PermissionDenied('An explicit domain/tier grant is required.')
    request_digest = digest({'domain_id': str(config.pk), **data})
    retry = _retry(tenant, user, data['idempotency_key'], request_digest)
    if retry:
        return retry
    if not inspection_current(preflight, user):
        raise PublicApiError('security_gpo_preflight_required', status_code=409)
    assignment = copy.deepcopy(preflight.assignment)
    operation = assignment['intended_operation']
    if data['safety_review'] != ({key: True for key in FALSE_REVIEW} if operation == ACTIVATE else FALSE_REVIEW):
        raise ParseError('Confirm management and independent recovery access before activation.')
    policy = policy_for_job(preflight, lock=True)
    state = preflight.result_evidence['state']
    try:
        validate_snapshot(state, assignment)
        _safe_before(assignment, state)
    except ValidationError as exc:
        raise PublicApiError('security_gpo_state_changed', status_code=409) from exc
    _idle(tenant, preflight.domain_guid)
    if ManagedGpoPolicy.objects.filter(tenant=tenant, domain_guid=policy.domain_guid,
            name_key=assignment['pilot_display_name'].casefold()).exclude(pk=policy.pk).exists():
        raise PublicApiError('security_gpo_name_collision', status_code=409)
    assignment.update(job_id=data['idempotency_key'], operation=operation, approval_mode='portal',
                      preflight_id=str(preflight.pk), expected_state=state, safety_review=data['safety_review'])
    if operation == LINK:
        assignment['link_orders'] = _orders(policy, config, state)
    elif operation in (ACTIVATE, DEACTIVATE):
        assignment['link_orders'] = [next(link['order'] for link in ou['links'] if link['guid'] == policy.gpo_guid)
                                     for ou in state['ous']] if operation == ACTIVATE else [
                                         next((link['order'] for link in ou['links'] if link['guid'] == policy.gpo_guid), 1)
                                         for ou in state['ous']]
    assignment['input_digest'] = digest({key: value for key, value in assignment.items() if key != 'input_digest'})
    if len(canonical(assignment)) > 24576:
        raise ParseError('The inspected scope exceeds the bounded GPO transport budget.')
    job = GpoImportJob.objects.create(id=data['idempotency_key'], tenant=tenant, domain=config,
        enrollment=preflight.enrollment, system=preflight.system, requested_by=user, domain_guid=preflight.domain_guid,
        request_sha256=request_digest, input_digest=assignment['input_digest'], assignment=assignment,
        pilot_display_name=assignment['pilot_display_name'], pilot_name_key=assignment['pilot_display_name'].casefold(),
        policy_revision=preflight.policy_revision, four_eyes_required=preflight.four_eyes_required,
        authorization_revision=preflight.authorization_revision, status='awaiting_approval', expires_at=preflight.expires_at)
    _audit(job, 'security.gpo_change_requested')
    return job


def scope_current(job, enrollment, tenant, *, lock=True):
    """Schema-3 authority is distinct from legacy pilot authorization."""
    from .gpo_approvals import approval_current, policy_current
    a = job.assignment
    try:
        if (set(a) != FIELDS or len(canonical(a)) > 24576 or type(a['schema']) is not int or a['schema'] != 3 or a['operation'] not in (INSPECT, *WRITES)
                or a['approval_mode'] != ('inspection' if a['operation'] == INSPECT else 'portal')
                or a['intended_operation'] not in WRITES or a['operation'] != INSPECT and a['intended_operation'] != a['operation']
                or a['job_id'] != str(job.pk) or a['scope_id'] != str(job.domain_id) or a['domain_guid'] != job.domain_guid
                or a['pilot_display_name'] != job.pilot_display_name or a['input_digest'] != job.input_digest
                or a['expires_at'] != job.expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')
                or digest({key: value for key, value in a.items() if key != 'input_digest'}) != job.input_digest
                or not _integer(a['managed_revision'], 1, 2**31-1) or not _integer(a['target_tier'], 0, 2)
                or not _integer(a['scope_revision'], 1, 2**31-1)
                or not isinstance(a['target_ous'], list) or len(a['target_ous']) > 32
                or not isinstance(a['link_orders'], list) or len(a['link_orders']) != len(a['target_ous'])
                or any(not _integer(order, 1, 128) for order in a['link_orders'])
                or not isinstance(a['safety_review'], dict) or set(a['safety_review']) != set(FALSE_REVIEW)
                or any(type(value) is not bool for value in a['safety_review'].values())):
            return False
        _guid(a['managed_id'])
        policy = policy_for_job(job, lock=lock)
        config = DomainSecuritySettings.objects.get(pk=job.domain_id)
        system = WindowsServer.objects.get(pk=job.system_id)
        report = GpoExecutorReport.objects.filter(enrollment=enrollment).first()
        if (not policy or policy.revision != a['managed_revision'] or policy.gpo_guid != a['gpo_guid']
                or policy.state == 'reconciliation_required' or policy.tier != a['target_tier']
                or policy.baseline_id != a['baseline_id'] or policy.profile != a['profile']
                or tenant.status != 'active' or job.tenant_id != tenant.pk or enrollment.tenant_id != tenant.pk
                or config.tenant_id != tenant.pk or job.enrollment_id != enrollment.pk
                or config.revision != a['scope_revision'] or config.domain_name != a['domain_dns_name']
                or not scoped(job.requested_by, tenant, config, a['target_tier'])
                or not _ready(system, enrollment, report, config.domain_name, portal=True)
                or tuple(map(int, system.agent_version.split('.'))) < (0, 2, 35)
                or tuple(map(int, report.agent_version.split('.'))) < (0, 2, 35)
                or report.domain_guid != a['domain_guid'] or report.forest_dns_name != a['forest_dns_name']
                or report.dc_fqdn != a['executor_dc_fqdn']):
            return False
        expected_targets = [] if a['intended_operation'] == IMPORT else ([domain_root(config.domain_name)]
                           if _domain_component(a) else config.tier_ous[str(a['target_tier'])])
        if a['target_ous'] != expected_targets:
            return False
        rule, auth = policy_for(tenant), authorization_for(config)
        if rule.revision != job.policy_revision or rule.four_eyes_required != job.four_eyes_required or auth.revision != job.authorization_revision:
            return False
        component = _content()[0].get((a['baseline_id'], a['backup_id']))
        if (not component or component['scope'] == 'domain' and a['target_tier'] != 0
                or semantic_purpose(a['baseline_id'], component) != policy.purpose or component['artifact_sha256'] != a['artifact_sha256']
                or a['backup_id'] not in _content()[1].get((a['baseline_id'], a['profile']), ())):
            return False
        if a['operation'] == INSPECT:
            return (a['preflight_id'] == '' and a['expected_state'] is None and a['safety_review'] == FALSE_REVIEW
                    and job.approved_at is None and job.approved_by_id is None and job.claimed_at is None)
        _guid(a['preflight_id'])
        preflight = GpoImportJob.objects.filter(pk=a['preflight_id'], tenant=tenant, domain=config,
            enrollment=enrollment, status='inspected').first()
        if (not preflight or not inspecting(preflight) or not preflight.completed_at
                or preflight.expires_at != job.expires_at or preflight.result_evidence.get('state') != a['expected_state']
                or any(preflight.assignment.get(key) != a[key] for key in FIELDS - {
                    'job_id', 'operation', 'approval_mode', 'preflight_id', 'expected_state', 'safety_review', 'input_digest', 'link_orders'})):
            return False
        if digest({'status': 'inspected', 'result_code': 'gpo_inspected', 'gpo_guid': preflight.gpo_guid or None,
                   'evidence': preflight.result_evidence}) != preflight.result_digest:
            return False
        validate_snapshot(a['expected_state'], a)
        _safe_before(a, a['expected_state'])
        return (policy_current(job, tenant) and (not job.approved_at or approval_current(job, tenant))
                and a['safety_review'] == ({key: True for key in FALSE_REVIEW} if a['operation'] == ACTIVATE else FALSE_REVIEW))
    except (ValidationError, ValueError, TypeError, KeyError, AttributeError, DomainSecuritySettings.DoesNotExist, WindowsServer.DoesNotExist):
        return False


def extend_projection(job, user, projection):
    if not production(job):
        return projection
    a = job.assignment
    projection.update(display_name=job.pilot_display_name, operation=a['operation'], managed_id=a['managed_id'],
        approval_mode=a['approval_mode'],
        preflight_state=job.result_evidence.get('state') if inspecting(job) and job.status == 'inspected' else None,
        can_prepare=inspection_current(job, user), inspection_expires_at=job.expires_at.isoformat() if inspecting(job) else None)
    return projection


def _fixed_gpo(before, after, *, content=False, name=False, flags=False, links=False, adoption=False):
    excluded = ({'computer_ds', 'computer_sysvol', 'user_ds', 'user_sysvol'} if content else set())
    excluded |= {'name'} if name else set()
    excluded |= {'computer_enabled', 'user_enabled'} if flags else set()
    excluded |= {'links'} if links else set()
    excluded |= {'description'} if adoption else set()
    if any(before[key] != after[key] for key in before.keys() - excluded):
        _invalid('An unrelated GPO property changed.')


def _postcondition(job, evidence, guid):
    a, operation = job.assignment, job.assignment['operation']
    component = _content()[0].get((a['baseline_id'], a['backup_id']))
    if not component or component['scope'] == 'domain' and a['target_tier'] != 0:
        _invalid('Domain-scoped settings require Tier 0 authority.')
    if (not isinstance(evidence, dict) or set(evidence) != {'schema', 'operation', 'managed_id', 'state',
            'prepared_artifact_sha256', 'backup_id', 'backup_manifest_sha256'}
            or type(evidence['schema']) is not int or evidence['schema'] != 3
            or evidence['operation'] != operation or evidence['managed_id'] != a['managed_id']):
        _invalid()
    state = validate_snapshot(evidence['state'], a)
    gpo = state['gpo']
    if guid != (gpo['guid'] if gpo else None):
        _invalid()
    if evidence['prepared_artifact_sha256'] != (a['artifact_sha256'] if operation in (IMPORT, ACTIVATE) else ''):
        _invalid()
    if evidence['backup_id'] == '' and evidence['backup_manifest_sha256'] == '':
        backed_up = False
    else:
        _guid(evidence['backup_id'])
        if not _sha(evidence['backup_manifest_sha256']):
            _invalid()
        backed_up = True
    if backed_up and operation != ACTIVATE:
        _invalid('Only activation may report a recovery backup.')
    if operation == INSPECT:
        if backed_up or a['gpo_guid'] != (guid or ''):
            _invalid()
        return
    before = a['expected_state']
    old = before['gpo']
    if not gpo or not state['name_available'] or gpo['wmi_filter']:
        _invalid()
    if gpo['description'] != 'IPMS managed GPO; id=' + a['managed_id']:
        _invalid()
    if old and gpo['guid'] != old['guid']:
        _invalid()
    if operation == IMPORT:
        if state['ous'] != before['ous']:
            _invalid()
        if not old or a['owner_marker'].startswith('IPMS disabled, unlinked pilot;'):
            if gpo['name'] != a['pilot_display_name'] or gpo['computer_enabled'] or gpo['user_enabled'] or gpo['links']:
                _invalid()
            if old:
                _fixed_gpo(old, gpo, name=True, adoption=True)
        elif gpo != old:
            _invalid('Preparing a revision must not change the live GPO.')
        return
    if not old:
        _invalid()
    if operation == DEACTIVATE:
        _fixed_gpo(old, gpo, flags=True)
        if gpo['computer_enabled'] or gpo['user_enabled'] or state['ous'] != before['ous']:
            _invalid()
        return
    if operation == ACTIVATE:
        if not backed_up:
            _invalid('Activation requires the protected backup receipt.')
        _fixed_gpo(old, gpo, content=True, name=True, flags=True, links=True)
        scope = _content()[0][(a['baseline_id'], a['backup_id'])]['scope']
        if (gpo['name'] != a['pilot_display_name'] or gpo['user_enabled'] != (scope == 'user')
                or gpo['computer_enabled'] != (scope != 'user')):
            _invalid()
    else:
        _fixed_gpo(old, gpo, links=True)
        if gpo['computer_enabled'] or gpo['user_enabled']:
            _invalid()
    expected_links = []
    for index, (prior, after) in enumerate(zip(before['ous'], state['ous'], strict=True)):
        if any(prior[key] != after[key] for key in ('dn', 'guid', 'blocked')):
            _invalid()
        if [link for link in prior['inherited_links'] if link['guid'] != guid] != [
                link for link in after['inherited_links'] if link['guid'] != guid]:
            _invalid('An unrelated inherited link changed.')
        root_target = _domain_component(a)
        child = _target_identity(after['dn'], a['domain_dns_name'], root=root_target)
        for inherited in after['inherited_links']:
            if inherited['guid'] != guid:
                continue
            if (root_target or inherited['kind'] != 'ou' or inherited['domain'] != a['domain_dns_name']
                    or not _target_ou(inherited['dn'], a) or inherited['enforced']
                    or inherited['enabled'] != (operation == ACTIVATE)):
                _invalid()
            parent = ou_identity(inherited['dn'], a['domain_dns_name'])
            if len(parent) >= len(child) or child[-len(parent):] != parent:
                _invalid('A reported inherited link is not an approved ancestor.')
        others = [copy.deepcopy(link) for link in prior['links'] if link['guid'] != guid]
        link = {'guid': guid, 'domain': a['domain_dns_name'], 'dn': after['dn'], 'kind': 'domain' if root_target else 'ou',
                'enabled': operation == ACTIVATE, 'enforced': False, 'order': a['link_orders'][index]}
        others.insert(a['link_orders'][index] - 1, link)
        for order, item in enumerate(others, 1):
            item['order'] = order
        if after['links'] != others:
            _invalid('A link changed outside the approved insertion.')
        expected_links.append(link)
    if sorted(gpo['links'], key=lambda item: (item['dn'], item['order'])) != sorted(expected_links, key=lambda item: (item['dn'], item['order'])):
        _invalid()


def receive_success(job, document):
    operation = job.assignment['operation']
    if (document['status'], document['result_code']) != SUCCESS[operation]:
        _invalid()
    receipt = digest({key: document[key] for key in ('status', 'result_code', 'gpo_guid', 'evidence')})
    if job.status in ('inspected', 'staged', 'linked', 'activated', 'deactivated'):
        if job.result_digest != receipt:
            _invalid()
        return
    if operation == INSPECT:
        if job.status != 'queued' or job.claimed_at or timezone.now() >= job.expires_at or not scope_current(job, job.enrollment, job.tenant):
            _invalid()
    elif job.status != 'running' or not job.claimed_at:
        _invalid()
    _postcondition(job, document['evidence'], document['gpo_guid'])
    policy = policy_for_job(job, lock=True)
    if not policy or policy.revision != job.assignment['managed_revision']:
        _invalid()
    job.status, job.error_code = document['status'], ''
    job.gpo_guid, job.result_evidence, job.result_digest = document['gpo_guid'] or '', document['evidence'], receipt
    job.completed_at = timezone.now()
    job.save()
    if operation != INSPECT:
        policy.gpo_guid = job.gpo_guid
        if operation == IMPORT:
            policy.origin_job = policy.origin_job or job
            policy.staged_job = job
            if policy.state != 'active':
                policy.state = 'prepared'
            policy.display_name = job.pilot_display_name
            policy.name_key = job.pilot_name_key
            policy.backup_id = job.assignment['backup_id']
            # Recover the requested version using the configured literal template;
            # version appears exactly once and only its allowed numeric grammar.
            template = job.domain.gpo_name_template
            marker = '__IPMS_VERSION__'
            component = _content()[0][(job.assignment['baseline_id'], job.assignment['backup_id'])]
            rendered = template.format(tier=str(policy.tier), scope='U' if component['scope'] == 'user' else 'C',
                target=policy.target, purpose=compact_purpose(policy.baseline_id, component), version=marker)
            left, right = rendered.split(marker)
            policy.version = job.pilot_display_name[len(left):len(job.pilot_display_name)-len(right) if right else None]
        elif operation == LINK:
            policy.state = 'linked'
        elif operation == ACTIVATE:
            policy.active_job = job
            policy.state = 'active'
        else:
            policy.state = 'inactive'
        policy.revision += 1
        policy.save()
    _audit(job, 'security.gpo_' + document['status'])


def active_binding(policy, now, *, computer_only=True):
    """Only a confirmed active production revision can identify applied content."""
    from .gpo_approvals import approval_object
    job = policy.active_job
    try:
        if not job or policy.state != 'active' or job.status != 'activated' or job.error_code or not production(job):
            return None
        a = job.assignment
        approval = approval_object(job)
        if (set(a) != FIELDS or a['operation'] != ACTIVATE or a['managed_id'] != str(policy.pk)
                or a['domain_guid'] != policy.domain_guid or job.gpo_guid != policy.gpo_guid
                or job.tenant_id != policy.tenant_id or job.domain_id != policy.domain_id
                or job.domain.tenant_id != policy.tenant_id or job.system.tenant_id != policy.tenant_id
                or job.enrollment.tenant_id != policy.tenant_id or job.system.source_id != job.enrollment.device_uri
                or a['job_id'] != str(job.pk) or a['input_digest'] != job.input_digest
                or digest({key: value for key, value in a.items() if key != 'input_digest'}) != job.input_digest
                or not approval or digest(approval) != job.approval_digest or not job.approved_at
                or not job.claimed_at or not job.completed_at
                or not job.requested_at.replace(microsecond=0) <= job.approved_at <= job.claimed_at <= job.completed_at <= now
                or job.claimed_at >= job.expires_at
                or job.four_eyes_required and job.requested_by_id == job.approved_by_id
                or digest({'status': 'activated', 'result_code': 'gpo_activated', 'gpo_guid': job.gpo_guid,
                           'evidence': job.result_evidence}) != job.result_digest):
            return None
        _postcondition(job, job.result_evidence, job.gpo_guid)
        component = _content()[0].get((a['baseline_id'], a['backup_id']))
        if not component or (computer_only and component['scope'] != 'machine') or component['artifact_sha256'] != a['artifact_sha256']:
            return None
        return (job.domain_guid, a['domain_dns_name'], a['baseline_id'], a['backup_id'])
    except (ValidationError, KeyError, ValueError, TypeError, AttributeError):
        return None


class ManagedGposView(DomainSettingsView):
    @transaction.atomic
    def get(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        self.check_permissions(request)
        config = get_object_or_404(DomainSecuritySettings, pk=domain_id, tenant=request.tenant)
        expire_jobs(request.tenant)
        options = executor_options(request.tenant, config)
        for option in options:
            option['eligible'] = option['eligible'] and tuple(map(int, option['agent_version'].split('.'))) >= (0, 2, 35)
        jobs = visible_jobs(request.user, request.tenant, GpoImportJob.objects.filter(tenant=request.tenant, domain=config))
        policies = ManagedGpoPolicy.objects.filter(tenant=request.tenant, domain=config).select_related(
            'active_job', 'active_job__domain', 'active_job__system', 'active_job__enrollment')
        return Response({'results': [managed_projection(row) for row in policies],
                         'executors': options, 'jobs': [job_projection(row, user=request.user) for row in jobs[:50]]})

    @transaction.atomic
    def post(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        config = get_object_or_404(DomainSecuritySettings.objects.select_for_update(), pk=domain_id, tenant=request.tenant)
        job = create_change(request.tenant, request.user, config, request.data)
        return Response(job_projection(job, user=request.user, include_review=True), status=202)


class GpoPreflightsView(ManagedGposView):
    http_method_names = ('post', 'options')

    @transaction.atomic
    def post(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        config = get_object_or_404(DomainSecuritySettings.objects.select_for_update(), pk=domain_id, tenant=request.tenant)
        job = create_preflight(request.tenant, request.user, config, request.data)
        return Response(job_projection(job, user=request.user), status=202)


class ManagedJobDetailView(SecurityReadView):
    def get(self, request, job_id):
        query(request, set())
        jobs = visible_jobs(request.user, request.tenant, GpoImportJob.objects.filter(tenant=request.tenant))
        job = get_object_or_404(jobs, pk=job_id)
        return Response(job_projection(job, user=request.user, include_review=True))
