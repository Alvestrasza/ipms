# File Name: gpo_approvals.py
# Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant-configurable, immutable domain/tier scoped pilot approval authority.
import hashlib
import re
import struct

from django.contrib.auth import HASH_SESSION_KEY, get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.crypto import constant_time_compare
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ParseError
from rest_framework.response import Response

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.rbac import Permission, effective_memberships, has_tenant_permission
from .domains import CanManageDomains, DomainJSONParser
from .models import DomainSecuritySettings, GpoApprovalPolicy, GpoDomainAuthorization, GpoImportJob
from .views import SecurityReadView, query


def fresh_actor(request):
    """Reject authentication superseded while waiting for the tenant lock.

    Password/identity mutation locks tenants before users as this path does.
    The force-authentication test seam still checks the same immutable snapshot;
    production mutation views accept only cookie SessionAuthentication.
    """
    authenticated = request.user
    fresh = get_user_model().objects.select_for_update(no_key=True).filter(pk=authenticated.pk).first()
    if (fresh is None or not constant_time_compare(authenticated.password, fresh.password)
            or authenticated.username != fresh.username or not fresh.is_active
            or fresh.is_staff or fresh.is_superuser
            or authenticated.is_active != fresh.is_active
            or authenticated.is_staff != fresh.is_staff or authenticated.is_superuser != fresh.is_superuser):
        raise PublicApiError('security_gpo_authentication_changed', status_code=403)
    if isinstance(request.successful_authenticator, SessionAuthentication) and not constant_time_compare(
            request.session.get(HASH_SESSION_KEY, ''), fresh.get_session_auth_hash()):
        raise PublicApiError('security_gpo_authentication_changed', status_code=403)
    request.user = fresh


def policy_for(tenant):
    return GpoApprovalPolicy.objects.filter(tenant=tenant).first() or GpoApprovalPolicy(tenant=tenant)


def authorization_for(config):
    return GpoDomainAuthorization.objects.filter(domain=config).first() or GpoDomainAuthorization(domain=config)


def scoped(user, tenant, config, tier, *, approve=False):
    permission = Permission.SECURITY_GPO_IMPORTS_APPROVE if approve else Permission.SECURITY_GPO_IMPORTS_RUN
    if not user or config.tenant_id != tenant.pk or not has_tenant_permission(user, tenant, permission):
        return False
    return any(row.get('user_id') == str(user.pk) and str(tier) in row.get('tiers', [])
               for row in authorization_for(config).grants if isinstance(row, dict))


def visible_jobs(user, tenant, jobs):
    if has_tenant_permission(user, tenant, Permission.SECURITY_DOMAINS_MANAGE):
        return jobs
    if not has_tenant_permission(user, tenant, Permission.SECURITY_GPO_IMPORTS_APPROVE):
        return jobs.none()
    scope = Q(pk__in=[])
    for auth in GpoDomainAuthorization.objects.filter(domain__tenant=tenant):
        for grant in auth.grants:
            if isinstance(grant, dict) and grant.get('user_id') == str(user.pk):
                for tier in grant.get('tiers', []):
                    if tier in ('0', '1', '2'):
                        scope |= Q(domain_id=auth.domain_id, assignment__target_tier=int(tier))
    return jobs.filter(scope)


def is_portal(job):
    return isinstance(job.assignment, dict) and job.assignment.get('schema') == 2 and job.assignment.get('approval_mode') == 'portal'


def approval_object(job):
    if not is_portal(job) or not job.approved_at or not job.approved_by_id or not job.requested_by_id:
        return None
    return {'schema': 1, 'job_id': str(job.pk), 'input_digest': job.input_digest,
            'device_uri': job.enrollment.device_uri, 'domain_guid': job.domain_guid,
            'target_tier': job.assignment['target_tier'], 'operation': 'create_unlinked_pilot',
            'requested_by': str(job.requested_by_id), 'approved_by': str(job.approved_by_id),
            'approved_at': job.approved_at.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'expires_at': job.assignment['expires_at'], 'policy_revision': job.policy_revision,
            'four_eyes_required': job.four_eyes_required}


def policy_current(job, tenant):
    if not is_portal(job):
        return True
    policy, auth = policy_for(tenant), authorization_for(job.domain)
    return (policy.revision == job.policy_revision and policy.four_eyes_required == job.four_eyes_required
            and auth.revision == job.authorization_revision
            and scoped(job.requested_by, tenant, job.domain, job.assignment['target_tier']))


def approval_current(job, tenant):
    from .gpo_jobs import digest
    value = approval_object(job)
    return bool(value and policy_current(job, tenant)
                and scoped(job.approved_by, tenant, job.domain, job.assignment['target_tier'], approve=True)
                and (not job.four_eyes_required or job.approved_by_id != job.requested_by_id)
                and job.requested_at.replace(microsecond=0) <= job.approved_at <= timezone.now()
                and job.approved_at < job.expires_at and digest(value) == job.approval_digest)


def approval_blocker(job, user):
    if not is_portal(job):
        return 'local_approval_required'
    if job.status not in ('queued', 'awaiting_approval') or job.claimed_at:
        return 'job_not_pending'
    if timezone.now() >= job.expires_at:
        return 'job_expired'
    if job.approved_at:
        return 'already_approved'
    if not policy_current(job, job.tenant):
        return 'approval_configuration_changed'
    if not scoped(user, job.tenant, job.domain, job.assignment['target_tier'], approve=True):
        return 'domain_tier_not_authorized'
    if job.four_eyes_required and user.pk == job.requested_by_id:
        return 'four_eyes_required'
    return None


def review_document(job):
    """Verify a pinned binary bundle, then return XML as inert display text only."""
    from .gpo_jobs import _content, artifact_bytes
    components, _ = _content()
    component = components.get((job.assignment.get('baseline_id'), job.assignment.get('backup_id')))
    if not component or component['artifact_sha256'] != job.assignment.get('artifact_sha256'):
        raise ValidationError('GPO review content changed.')
    content = artifact_bytes(component)
    files = component['files']
    if len(content) < 12 or content[:8] != b'IPMSGPO1' or struct.unpack_from('<I', content, 8)[0] != len(files):
        raise ValidationError('Invalid GPO review bundle.')
    offset, report = 12, None
    for item in files:
        if offset + 4 > len(content):
            raise ValidationError('Truncated GPO review bundle.')
        length = struct.unpack_from('<I', content, offset)[0]
        offset += 4
        value = content[offset:offset + length]
        if length != item['bytes'] or len(value) != length or hashlib.sha256(value).hexdigest() != item['sha256']:
            raise ValidationError('GPO review file mismatch.')
        offset += length
        if item['path'] == 'gpreport.xml':
            try:
                report = value.decode('utf-16' if value.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig')
            except UnicodeError as exc:
                raise ValidationError('Invalid GPO review encoding.') from exc
    if offset != len(content) or report is None:
        raise ValidationError('Invalid GPO review manifest.')
    return {'component_name': component['name'], 'artifact_sha256': component['artifact_sha256'],
            'files': files, 'report_xml': report, 'changes': ['create_disabled_unlinked_pilot']}


def _revision(data, fields):
    if (not isinstance(data, dict) or set(data) != fields | {'expected_revision'}
            or type(data['expected_revision']) is not int or not 1 <= data['expected_revision'] < 2**31 - 1):
        raise ParseError('Supply exactly the documented settings and revision.')


def _withdraw(tenant, *, domain=None):
    from .gpo_jobs import ACTIVE, _invalidate
    jobs = GpoImportJob.objects.select_for_update().filter(tenant=tenant, status__in=ACTIVE, assignment__schema=2)
    if domain:
        jobs = jobs.filter(domain=domain)
    for job in jobs:
        _invalidate(job, 'approval_configuration_changed')


def _audit(tenant, user, action, object_id, revision):
    AuditEvent.objects.create(tenant=tenant, actor=str(user.pk), action=action, object_type='security_gpo_approval',
                             object_id=str(object_id), outcome='succeeded', details={'revision': revision})


class GpoApprovalPolicyView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (*SecurityReadView.permission_classes, CanManageDomains)
    parser_classes = (DomainJSONParser,)
    http_method_names = ('get', 'put', 'head', 'options')

    def get(self, request):
        query(request, set())
        policy = policy_for(request.tenant)
        return Response({'four_eyes_required': policy.four_eyes_required, 'revision': policy.revision})

    @transaction.atomic
    def put(self, request):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        _revision(request.data, {'four_eyes_required'})
        if type(request.data['four_eyes_required']) is not bool:
            raise ParseError('Supply a Boolean approval rule.')
        policy = policy_for(request.tenant)
        if request.data['expected_revision'] != policy.revision:
            raise PublicApiError('security_gpo_policy_revision_changed', status_code=409)
        policy.four_eyes_required = request.data['four_eyes_required']
        policy.revision += 1
        policy.save()
        _withdraw(request.tenant)
        _audit(request.tenant, request.user, 'security.gpo_approval_policy_changed', request.tenant.pk, policy.revision)
        return self.get(request)


class GpoDomainAuthorizationView(GpoApprovalPolicyView):
    def get(self, request, domain_id):
        query(request, set())
        config = get_object_or_404(DomainSecuritySettings, pk=domain_id, tenant=request.tenant)
        auth = authorization_for(config)
        members = effective_memberships().filter(tenant=request.tenant, role__in=('tenant_admin', 'approver')).select_related('user')
        return Response({'revision': auth.revision, 'grants': auth.grants,
                         'members': [{'user_id': str(member.user_id), 'username': member.user.username, 'role': member.role}
                                     for member in members]})

    @transaction.atomic
    def put(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        config = get_object_or_404(DomainSecuritySettings.objects.select_for_update(), pk=domain_id, tenant=request.tenant)
        _revision(request.data, {'grants'})
        grants = request.data['grants']
        if not isinstance(grants, list) or len(grants) > 250:
            raise ParseError('Supply at most 250 explicit domain grants.')
        eligible = {str(value) for value in effective_memberships().filter(tenant=request.tenant,
            role__in=('tenant_admin', 'approver')).values_list('user_id', flat=True)}
        seen, normalized = set(), []
        for row in grants:
            if (not isinstance(row, dict) or set(row) != {'user_id', 'tiers'} or not isinstance(row['user_id'], str)
                    or row['user_id'] not in eligible or row['user_id'] in seen
                    or not isinstance(row['tiers'], list) or not 1 <= len(row['tiers']) <= 3
                    or any(not isinstance(tier, str) or tier not in ('0', '1', '2') for tier in row['tiers'])
                    or len(set(row['tiers'])) != len(row['tiers'])):
                raise ParseError('Select active tenant administrators or approvers and distinct tiers.')
            seen.add(row['user_id'])
            normalized.append({'user_id': row['user_id'], 'tiers': sorted(row['tiers'])})
        auth = authorization_for(config)
        if request.data['expected_revision'] != auth.revision:
            raise PublicApiError('security_gpo_authorization_revision_changed', status_code=409)
        auth.grants = sorted(normalized, key=lambda row: int(row['user_id']))
        auth.revision += 1
        auth.save()
        _withdraw(request.tenant, domain=config)
        _audit(request.tenant, request.user, 'security.gpo_domain_authorization_changed', config.pk, auth.revision)
        return self.get(request, domain_id)


class GpoApproveView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    parser_classes = (DomainJSONParser,)
    http_method_names = ('post', 'options')

    @transaction.atomic
    def post(self, request, job_id):
        from .gpo_jobs import _scope_current, digest, job_projection
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        jobs = visible_jobs(request.user, request.tenant, GpoImportJob.objects.select_for_update(of=('self',)).select_related(
            'system', 'domain', 'tenant', 'requested_by', 'approved_by', 'enrollment').filter(tenant=request.tenant,
            system__tenant=request.tenant, enrollment__tenant=request.tenant, domain__tenant=request.tenant))
        job = get_object_or_404(jobs, pk=job_id)
        data = request.data
        if (not isinstance(data, dict) or set(data) != {'input_digest', 'policy_revision'}
                or not isinstance(data['input_digest'], str) or not re.fullmatch('[a-f0-9]{64}', data['input_digest'])
                or type(data['policy_revision']) is not int or data['policy_revision'] < 1):
            raise ParseError('Supply the reviewed immutable digest and policy revision.')
        if data['input_digest'] != job.input_digest or data['policy_revision'] != job.policy_revision:
            raise PublicApiError('security_gpo_approval_changed', status_code=409)
        blocker = approval_blocker(job, request.user)
        if blocker:
            raise PublicApiError('security_gpo_' + blocker, status_code=403 if blocker in (
                'domain_tier_not_authorized', 'four_eyes_required') else 409)
        if not _scope_current(job, job.enrollment, request.tenant):
            raise PublicApiError('security_gpo_scope_changed', status_code=409)
        try:
            review_document(job)
        except ValidationError as exc:
            raise PublicApiError('security_gpo_artifact_unavailable', status_code=409) from exc
        approved_at = timezone.now().replace(microsecond=0)
        if approved_at >= job.expires_at:
            raise PublicApiError('security_gpo_job_expired', status_code=409)
        job.approved_by = request.user
        job.approved_at = approved_at
        job.approval_digest = digest(approval_object(job))
        job.error_code = ''
        job.status = 'queued'
        job.save(update_fields=('approved_by', 'approved_at', 'approval_digest', 'error_code', 'status'))
        _audit(request.tenant, request.user, 'security.gpo_import_approved', job.pk, job.policy_revision)
        return Response(job_projection(job, user=request.user))
