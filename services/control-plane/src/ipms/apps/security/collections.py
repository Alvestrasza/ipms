# File Name: collections.py
# Version: v0.1.0 | Created: 2026-09-18 | Last Modified: 2026-09-18
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Tenant-scoped device membership and ordered multi-domain GPO collection rollout.
import copy
import re
import uuid

from django.db import transaction
from django.db.models.deletion import ProtectedError
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import APIException, ParseError
from rest_framework.response import Response

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.permissions import HasTenantPermission
from ipms.apps.tenancy.rbac import Permission
from .administration import SmallJSONParser
from .gpo_approvals import fresh_actor
from .gpo_jobs import _content, digest, executor_options, expire_jobs
from .gpo_production import IMPORT_LINK, create_change, create_preflight, domain_root, minimum_agent
from .models import (
    DeviceCollection, DomainSecuritySettings, GpoImportJob, GpoOverride,
    ManagedGpoPolicy, PolicyCollection, PolicyCollectionDeployment,
    PolicyCollectionDeploymentItem,
)
from .views import SecurityReadView, query


NAME = re.compile(r'[^\x00-\x1f\x7f]{1,100}')
TARGET = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}')
VERSION = re.compile(r'\d{1,4}\.\d{1,4}\.\d{1,4}')
DEVICE_RULE_FIELDS = {
    'domain_name', 'server_type', 'operating_system_role',
    'operating_system_family', 'hostname_contains',
}
ITEM_ACTIVE = {'preparing', 'awaiting_approval', 'running'}
JOB_ACTIVE = {'queued', 'awaiting_approval', 'running'}


class CollectionJSONParser(SmallJSONParser):
    maximum_bytes = 131072


class CanViewCollections(HasTenantPermission):
    required_permission = Permission.SECURITY_COLLECTIONS_VIEW


class CanManageCollections(HasTenantPermission):
    required_permission = Permission.SECURITY_COLLECTIONS_MANAGE


def _audit(tenant, user, action, object_type, object_id, details=None):
    AuditEvent.objects.create(
        tenant=tenant, actor=str(user.pk), action=action, object_type=object_type,
        object_id=str(object_id), outcome='succeeded', details=details or {},
    )


def _name(value):
    if not isinstance(value, str) or value != value.strip() or not NAME.fullmatch(value):
        raise ParseError('Supply a bounded collection name.')
    return value


def _description(value):
    if not isinstance(value, str) or len(value) > 500 or any(ord(char) < 32 and char not in '\r\n\t' for char in value):
        raise ParseError('Supply a bounded collection description.')
    return value.strip()


def _uuid(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ParseError('Supply a valid collection identity.') from exc


def _device_input(tenant, data, *, updating=False):
    fields = {'name', 'description', 'static_system_ids', 'rules'} | ({'expected_revision'} if updating else set())
    if not isinstance(data, dict) or set(data) != fields:
        raise ParseError('Supply exactly the documented device collection fields.')
    ids = data['static_system_ids']
    if not isinstance(ids, list) or len(ids) > 1000:
        raise ParseError('Supply at most 1000 direct device members.')
    normalized_ids = [_uuid(value) for value in ids]
    if len(set(normalized_ids)) != len(normalized_ids):
        raise ParseError('Direct device members must be unique.')
    if WindowsServer.objects.filter(tenant=tenant, pk__in=normalized_ids).count() != len(normalized_ids):
        raise PublicApiError('security_collection_device_unavailable')
    rules = data['rules']
    if not isinstance(rules, list) or len(rules) > 20:
        raise ParseError('Supply at most 20 bounded inventory rules.')
    normalized_rules = []
    for rule in rules:
        if not isinstance(rule, dict) or not rule or not set(rule) <= DEVICE_RULE_FIELDS:
            raise ParseError('Supply supported inventory rule fields.')
        normalized = {}
        for key, value in rule.items():
            if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 255:
                raise ParseError('Supply bounded inventory rule values.')
            normalized[key] = value
        if normalized.get('server_type') not in (None, 'physical', 'virtual', 'unknown'):
            raise ParseError('Supply a supported server type.')
        if normalized.get('operating_system_role') not in (None, 'client', 'server', 'domain-controller', 'unknown'):
            raise ParseError('Supply a supported operating system role.')
        normalized_rules.append(normalized)
    if updating and (type(data['expected_revision']) is not int or data['expected_revision'] < 1):
        raise ParseError('Supply the expected collection revision.')
    return {
        'name': _name(data['name']), 'description': _description(data['description']),
        'static_system_ids': normalized_ids, 'rules': normalized_rules,
    }


def _device_members(collection):
    rows = WindowsServer.objects.filter(tenant=collection.tenant)
    direct = set(collection.static_system_ids)
    members = []
    for system in rows.order_by('hostname', 'id'):
        matched = str(system.pk) in direct
        for rule in collection.rules:
            if all(
                (key == 'hostname_contains' and value.casefold() in system.hostname.casefold())
                or (key != 'hostname_contains' and str(getattr(system, key, '')).casefold() == value.casefold())
                for key, value in rule.items()
            ):
                matched = True
                break
        if matched:
            members.append({
                'id': str(system.pk), 'hostname': system.hostname, 'fqdn': system.fqdn,
                'domain_name': system.domain_name, 'server_type': system.server_type,
                'operating_system_role': system.operating_system_role,
                'operating_system_family': system.operating_system_family,
            })
    return members


def _device_projection(collection):
    members = _device_members(collection)
    return {
        'id': str(collection.pk), 'name': collection.name, 'description': collection.description,
        'revision': collection.revision, 'static_system_ids': list(collection.static_system_ids),
        'rules': copy.deepcopy(collection.rules), 'member_count': len(members), 'members': members,
        'updated_at': collection.updated_at.isoformat(),
    }


def _device_option(system):
    return {
        'id': str(system.pk), 'hostname': system.hostname, 'fqdn': system.fqdn,
        'domain_name': system.domain_name, 'server_type': system.server_type,
        'operating_system_role': system.operating_system_role,
        'operating_system_family': system.operating_system_family,
    }


def _policy_input(tenant, data, *, updating=False):
    fields = {'name', 'description', 'entries', 'bindings'} | ({'expected_revision'} if updating else set())
    if not isinstance(data, dict) or set(data) != fields:
        raise ParseError('Supply exactly the documented policy collection fields.')
    components, _profiles = _content()
    entries = data['entries']
    if not isinstance(entries, list) or not 1 <= len(entries) <= 32:
        raise ParseError('Supply one to 32 ordered policy entries.')
    normalized_entries = []
    for entry in entries:
        expected = {'source', 'baseline_id', 'backup_id', 'target', 'version', 'override_id'}
        if not isinstance(entry, dict) or set(entry) != expected:
            raise ParseError('Supply exactly the documented policy entry fields.')
        if entry['source'] not in ('baseline', 'override') or not TARGET.fullmatch(str(entry['target'])) or not VERSION.fullmatch(str(entry['version'])):
            raise ParseError('Supply a supported policy source, target alias and version.')
        component = components.get((entry['baseline_id'], entry['backup_id']))
        if not component:
            raise PublicApiError('security_collection_policy_unavailable')
        override = None
        if entry['source'] == 'override':
            override = GpoOverride.objects.filter(pk=_uuid(entry['override_id']), tenant=tenant).first()
            if (not override or not override.enabled or not override.entries
                    or override.baseline_id != entry['baseline_id'] or override.backup_id != entry['backup_id']
                    or override.artifact_sha256 != component['artifact_sha256']):
                raise PublicApiError('security_collection_policy_unavailable')
        elif entry['override_id'] is not None:
            raise ParseError('A baseline entry cannot reference an override.')
        if override:
            from .gpo_overrides import patch_document
            override_digest = digest(patch_document(override))
        else:
            override_digest = None
        normalized_entries.append({
            'source': entry['source'], 'baseline_id': entry['baseline_id'], 'backup_id': entry['backup_id'],
            'target': entry['target'], 'version': entry['version'],
            'override_id': str(override.pk) if override else None,
            'override_revision': override.revision if override else None,
            'override_sha256': override_digest,
            'component_name': component['name'], 'scope': component['scope'],
        })
    bindings = data['bindings']
    if not isinstance(bindings, list) or not 1 <= len(bindings) <= 100:
        raise ParseError('Supply one to 100 domain bindings.')
    normalized_bindings, seen = [], set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {'domain_id', 'tier', 'target_ous'}:
            raise ParseError('Supply exactly the documented domain binding fields.')
        domain_id = _uuid(binding['domain_id'])
        if domain_id in seen or binding['tier'] not in ('0', '1', '2'):
            raise ParseError('Domain bindings must be unique and use a supported tier.')
        seen.add(domain_id)
        domain = DomainSecuritySettings.objects.filter(pk=domain_id, tenant=tenant).first()
        if not domain:
            raise PublicApiError('security_collection_domain_unavailable')
        targets = binding['target_ous']
        configured = list(domain.tier_ous[binding['tier']])
        if (not isinstance(targets, list) or not targets or len(targets) > 32
                or any(not isinstance(value, str) for value in targets)
                or len(set(targets)) != len(targets) or any(value not in configured for value in targets)):
            raise PublicApiError('security_collection_target_unavailable')
        root = domain_root(domain.domain_name)
        if any(value.casefold() == root.casefold() for value in targets) and (binding['tier'] != '0' or len(targets) != 1):
            raise PublicApiError('security_collection_target_unavailable')
        if any(entry['scope'] == 'domain' for entry in normalized_entries) and (
                binding['tier'] != '0' or len(targets) != 1 or targets[0].casefold() != root.casefold()):
            raise PublicApiError('security_collection_domain_root_required')
        normalized_bindings.append({
            'domain_id': domain_id, 'domain_name': domain.domain_name, 'domain_revision': domain.revision,
            'tier': binding['tier'], 'target_ous': list(targets),
        })
    if updating and (type(data['expected_revision']) is not int or data['expected_revision'] < 1):
        raise ParseError('Supply the expected collection revision.')
    return {
        'name': _name(data['name']), 'description': _description(data['description']),
        'entries': normalized_entries, 'bindings': normalized_bindings,
    }


def _entry_public(entry):
    return {key: entry[key] for key in (
        'source', 'baseline_id', 'backup_id', 'target', 'version', 'override_id',
        'component_name', 'scope',
    )}


def _binding_public(binding):
    return {key: binding[key] for key in ('domain_id', 'domain_name', 'domain_revision', 'tier', 'target_ous')}


def _policy_projection(collection):
    return {
        'id': str(collection.pk), 'name': collection.name, 'description': collection.description,
        'revision': collection.revision, 'entries': [_entry_public(row) for row in collection.entries],
        'bindings': [_binding_public(row) for row in collection.bindings],
        'deployment_count': collection.deployments.count(), 'updated_at': collection.updated_at.isoformat(),
    }


def _preview(collection):
    rows, ready = [], True
    for binding in collection.bindings:
        domain = DomainSecuritySettings.objects.filter(pk=binding['domain_id'], tenant=collection.tenant).first()
        options = executor_options(collection.tenant, domain) if domain else []
        eligible = [row for row in options if row['eligible'] and tuple(map(int, row['agent_version'].split('.'))) >= minimum_agent(IMPORT_LINK)]
        current = bool(domain and domain.revision == binding['domain_revision'])
        for index, entry in enumerate(collection.entries):
            override = (GpoOverride.objects.filter(pk=entry['override_id'], tenant=collection.tenant).first()
                        if entry['override_id'] else None)
            if override:
                from .gpo_overrides import patch_document
            unchanged = bool(not override or (
                override.enabled and override.revision == entry['override_revision']
                and digest(patch_document(override)) == entry['override_sha256']))
            item_ready = current and unchanged and bool(eligible)
            ready = ready and item_ready
            rows.append({
                'policy_index': index, 'domain_id': binding['domain_id'], 'domain_name': binding['domain_name'],
                'tier': binding['tier'], 'target_ous': list(binding['target_ous']),
                'source': entry['source'], 'component_name': entry['component_name'],
                'executor': eligible[0] if eligible else None, 'ready': item_ready,
                'blocker': None if item_ready else ('domain_revision_changed' if not current else
                    'override_revision_changed' if not unchanged else 'executor_unavailable'),
            })
    return {'collection_id': str(collection.pk), 'revision': collection.revision, 'ready': ready, 'items': rows}


def _existing_policy(tenant, domain, entry, binding):
    rows = ManagedGpoPolicy.objects.filter(
        tenant=tenant, domain=domain, tier=int(binding['tier']), baseline_id=entry['baseline_id'],
        backup_id=entry['backup_id'], target=entry['target'], target_ous=binding['target_ous'],
    )
    return rows.filter(override_id=entry['override_id']).first()


def _error_code(exc):
    return getattr(exc, 'public_code', None) or getattr(exc, 'default_code', None) or 'request_failed'


def _dispatch_domain(deployment, domain_id):
    items = list(deployment.items.select_for_update().filter(domain_id=domain_id).order_by('sequence'))
    if any(item.status in ITEM_ACTIVE for item in items):
        return
    pending = next((item for item in items if item.status == 'pending'), None)
    if not pending:
        return
    preceding = [item for item in items if item.sequence < pending.sequence]
    if any(item.status in ('failed', 'blocked', 'reconciliation_required') for item in preceding):
        deployment.items.filter(
            domain_id=domain_id,
            status='pending',
        ).update(
            status='blocked',
            error_code='previous_policy_failed',
            completed_at=timezone.now(),
        )
        return
    if any(item.status != 'succeeded' for item in preceding):
        return
    domain = DomainSecuritySettings.objects.select_for_update().get(pk=domain_id, tenant=deployment.tenant)
    entry, binding = pending.selection['entry'], pending.selection['binding']
    options = [row for row in executor_options(deployment.tenant, domain)
               if row['eligible'] and tuple(map(int, row['agent_version'].split('.'))) >= minimum_agent(IMPORT_LINK)]
    if domain.revision != binding['domain_revision']:
        pending.status, pending.error_code = 'failed', 'domain_revision_changed'
        pending.completed_at = timezone.now()
        pending.save(update_fields=('status', 'error_code', 'completed_at'))
        return
    if not options:
        pending.status, pending.error_code = 'failed', 'executor_unavailable'
        pending.completed_at = timezone.now()
        pending.save(update_fields=('status', 'error_code', 'completed_at'))
        return
    policy = _existing_policy(deployment.tenant, domain, entry, binding)
    selection = {
        'revision': domain.revision, 'system_id': options[0]['system_id'],
        'baseline_id': entry['baseline_id'], 'backup_id': entry['backup_id'],
        'tier': binding['tier'], 'target': entry['target'], 'target_ous': binding['target_ous'],
        'version': entry['version'], 'idempotency_key': pending.selection['preflight_id'],
        'operation': IMPORT_LINK, 'managed_id': str(policy.pk) if policy else None,
        'adopt_job_id': None,
        'domain_root_confirmed': len(binding['target_ous']) == 1 and binding['target_ous'][0].casefold() == domain_root(domain.domain_name).casefold(),
    }
    if entry['override_id']:
        selection.update(override_id=entry['override_id'], override_revision=entry['override_revision'],
                         override_sha256=entry['override_sha256'])
    try:
        with transaction.atomic():
            job = create_preflight(deployment.tenant, deployment.requested_by, domain, selection)
    except APIException as exc:
        pending.status, pending.error_code = 'failed', str(_error_code(exc))[:64]
        pending.completed_at = timezone.now()
        pending.save(update_fields=('status', 'error_code', 'completed_at'))
        return
    pending.preflight_job = job
    pending.status = 'preparing'
    pending.error_code = ''
    pending.save(update_fields=('preflight_job', 'status', 'error_code'))


def _deployment_status(deployment):
    statuses = list(deployment.items.values_list('status', flat=True))
    if statuses and all(status == 'succeeded' for status in statuses):
        return 'succeeded'
    if 'reconciliation_required' in statuses:
        return 'reconciliation_required'
    if 'awaiting_approval' in statuses:
        return 'awaiting_approval'
    if any(status in ITEM_ACTIVE for status in statuses):
        return 'running'
    if 'pending' in statuses:
        return 'running' if any(status == 'succeeded' for status in statuses) else 'queued'
    if any(status == 'succeeded' for status in statuses):
        return 'partial'
    return 'failed'


def refresh_deployment(deployment):
    deployment = PolicyCollectionDeployment.objects.select_for_update().get(pk=deployment.pk)
    expire_jobs(deployment.tenant)
    for item in deployment.items.select_for_update().select_related('preflight_job', 'write_job', 'domain'):
        if item.write_job_id:
            status = item.write_job.status
            if status == 'linked':
                item.status, item.error_code, item.completed_at = 'succeeded', '', item.write_job.completed_at or timezone.now()
            elif status == 'reconciliation_required':
                item.status, item.error_code = 'reconciliation_required', item.write_job.error_code
            elif status in ('failed', 'expired', 'deleted'):
                item.status, item.error_code, item.completed_at = 'failed', item.write_job.error_code or status, item.write_job.completed_at or timezone.now()
            elif status == 'awaiting_approval':
                item.status = 'awaiting_approval'
            elif status in ('queued', 'running'):
                item.status = 'running'
            item.save(update_fields=('status', 'error_code', 'completed_at'))
        elif item.preflight_job_id:
            status = item.preflight_job.status
            if status == 'inspected':
                try:
                    with transaction.atomic():
                        job = create_change(deployment.tenant, deployment.requested_by, item.domain, {
                            'preflight_id': str(item.preflight_job_id),
                            'idempotency_key': item.selection['write_id'],
                            'safety_review': {'management_access': False, 'recovery_access': False},
                        })
                except APIException as exc:
                    item.status, item.error_code, item.completed_at = 'failed', str(_error_code(exc))[:64], timezone.now()
                else:
                    item.write_job = job
                    item.status = 'awaiting_approval' if job.status == 'awaiting_approval' else 'running'
                    item.error_code = ''
                item.save(update_fields=('write_job', 'status', 'error_code', 'completed_at'))
            elif status == 'reconciliation_required':
                item.status, item.error_code = 'reconciliation_required', item.preflight_job.error_code
                item.save(update_fields=('status', 'error_code'))
            elif status in ('failed', 'expired'):
                item.status, item.error_code, item.completed_at = 'failed', item.preflight_job.error_code or status, item.preflight_job.completed_at or timezone.now()
                item.save(update_fields=('status', 'error_code', 'completed_at'))
    for domain_id in deployment.items.values_list('domain_id', flat=True).distinct():
        _dispatch_domain(deployment, domain_id)
    status = _deployment_status(deployment)
    deployment.status = status
    deployment.completed_at = timezone.now() if status in ('succeeded', 'partial', 'failed', 'reconciliation_required') else None
    deployment.save(update_fields=('status', 'completed_at'))
    return deployment


def notify_gpo_job(job):
    """Advance only a collection that explicitly owns this immutable job."""
    item = PolicyCollectionDeploymentItem.objects.filter(preflight_job=job).first()
    if item is None:
        item = PolicyCollectionDeploymentItem.objects.filter(write_job=job).first()
    if item:
        refresh_deployment(item.deployment)


def _deployment_projection(deployment):
    return {
        'id': str(deployment.pk), 'collection_id': str(deployment.collection_id),
        'collection_revision': deployment.collection_revision, 'status': deployment.status,
        'requested_at': deployment.requested_at.isoformat(),
        'completed_at': deployment.completed_at.isoformat() if deployment.completed_at else None,
        'items': [{
            'id': str(item.pk), 'domain_id': str(item.domain_id), 'domain_name': item.domain.domain_name,
            'policy_index': item.policy_index, 'sequence': item.sequence, 'status': item.status,
            'component_name': item.selection['entry']['component_name'],
            'preflight_job_id': str(item.preflight_job_id) if item.preflight_job_id else None,
            'write_job_id': str(item.write_job_id) if item.write_job_id else None,
            'error_code': item.error_code,
        } for item in deployment.items.select_related('domain')],
    }


class DeviceCollectionsView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (*SecurityReadView.permission_classes, CanViewCollections)
    parser_classes = (CollectionJSONParser,)
    http_method_names = ('get', 'post', 'head', 'options')

    def get(self, request):
        query(request, set())
        inventory = WindowsServer.objects.filter(tenant=request.tenant).order_by('hostname', 'id')[:5000]
        return Response({
            'results': [_device_projection(row) for row in DeviceCollection.objects.filter(tenant=request.tenant)],
            'inventory': [_device_option(row) for row in inventory],
        })

    @transaction.atomic
    def post(self, request):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        data = _device_input(request.tenant, request.data)
        if DeviceCollection.objects.filter(tenant=request.tenant, name=data['name']).exists():
            raise PublicApiError('security_collection_name_exists', status_code=409)
        if DeviceCollection.objects.filter(tenant=request.tenant).count() >= 100:
            raise PublicApiError('security_collection_limit', status_code=409)
        row = DeviceCollection.objects.create(tenant=request.tenant, created_by=request.user, **data)
        _audit(request.tenant, request.user, 'security.device_collection_created', 'device_collection', row.pk)
        return Response(_device_projection(row), status=201)


class DeviceCollectionView(DeviceCollectionsView):
    http_method_names = ('get', 'put', 'delete', 'head', 'options')

    def get(self, request, collection_id):
        query(request, set())
        return Response(_device_projection(get_object_or_404(DeviceCollection, pk=collection_id, tenant=request.tenant)))

    @transaction.atomic
    def put(self, request, collection_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        row = get_object_or_404(DeviceCollection.objects.select_for_update(), pk=collection_id, tenant=request.tenant)
        data = _device_input(request.tenant, request.data, updating=True)
        if request.data['expected_revision'] != row.revision:
            raise PublicApiError('security_collection_revision_changed', status_code=409)
        if DeviceCollection.objects.filter(tenant=request.tenant, name=data['name']).exclude(pk=row.pk).exists():
            raise PublicApiError('security_collection_name_exists', status_code=409)
        for key, value in data.items():
            setattr(row, key, value)
        row.revision += 1
        row.save()
        _audit(request.tenant, request.user, 'security.device_collection_updated', 'device_collection', row.pk, {'revision': row.revision})
        return Response(_device_projection(row))

    @transaction.atomic
    def delete(self, request, collection_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        row = get_object_or_404(DeviceCollection.objects.select_for_update(), pk=collection_id, tenant=request.tenant)
        if request.data != {'expected_revision': row.revision}:
            raise PublicApiError('security_collection_revision_changed', status_code=409)
        identity = row.pk
        row.delete()
        _audit(request.tenant, request.user, 'security.device_collection_deleted', 'device_collection', identity)
        return Response(status=204)


class PolicyCollectionsView(DeviceCollectionsView):
    def get(self, request):
        query(request, set())
        return Response({'results': [_policy_projection(row) for row in PolicyCollection.objects.filter(tenant=request.tenant)]})

    @transaction.atomic
    def post(self, request):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        data = _policy_input(request.tenant, request.data)
        if PolicyCollection.objects.filter(tenant=request.tenant, name=data['name']).exists():
            raise PublicApiError('security_collection_name_exists', status_code=409)
        if PolicyCollection.objects.filter(tenant=request.tenant).count() >= 100:
            raise PublicApiError('security_collection_limit', status_code=409)
        row = PolicyCollection.objects.create(tenant=request.tenant, created_by=request.user, **data)
        _audit(request.tenant, request.user, 'security.policy_collection_created', 'policy_collection', row.pk)
        return Response(_policy_projection(row), status=201)


class PolicyCollectionView(PolicyCollectionsView):
    http_method_names = ('get', 'put', 'delete', 'head', 'options')

    def get(self, request, collection_id):
        query(request, set())
        return Response(_policy_projection(get_object_or_404(PolicyCollection, pk=collection_id, tenant=request.tenant)))

    @transaction.atomic
    def put(self, request, collection_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        row = get_object_or_404(PolicyCollection.objects.select_for_update(), pk=collection_id, tenant=request.tenant)
        data = _policy_input(request.tenant, request.data, updating=True)
        if request.data['expected_revision'] != row.revision:
            raise PublicApiError('security_collection_revision_changed', status_code=409)
        if PolicyCollection.objects.filter(tenant=request.tenant, name=data['name']).exclude(pk=row.pk).exists():
            raise PublicApiError('security_collection_name_exists', status_code=409)
        for key, value in data.items():
            setattr(row, key, value)
        row.revision += 1
        row.save()
        _audit(request.tenant, request.user, 'security.policy_collection_updated', 'policy_collection', row.pk, {'revision': row.revision})
        return Response(_policy_projection(row))

    @transaction.atomic
    def delete(self, request, collection_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        row = get_object_or_404(PolicyCollection.objects.select_for_update(), pk=collection_id, tenant=request.tenant)
        if request.data != {'expected_revision': row.revision}:
            raise PublicApiError('security_collection_revision_changed', status_code=409)
        identity = row.pk
        try:
            row.delete()
        except ProtectedError as exc:
            raise PublicApiError('security_collection_has_deployments', status_code=409) from exc
        _audit(request.tenant, request.user, 'security.policy_collection_deleted', 'policy_collection', identity)
        return Response(status=204)


class PolicyCollectionPreviewView(PolicyCollectionsView):
    http_method_names = ('get', 'head', 'options')

    def get(self, request, collection_id):
        query(request, set())
        collection = get_object_or_404(PolicyCollection, pk=collection_id, tenant=request.tenant)
        return Response(_preview(collection))


class PolicyCollectionDeploymentsView(PolicyCollectionsView):
    http_method_names = ('get', 'post', 'head', 'options')

    @transaction.atomic
    def get(self, request, collection_id):
        query(request, set())
        collection = get_object_or_404(PolicyCollection, pk=collection_id, tenant=request.tenant)
        rows = []
        for deployment in collection.deployments.filter(tenant=request.tenant)[:25]:
            rows.append(_deployment_projection(refresh_deployment(deployment)))
        return Response({'results': rows})

    @transaction.atomic
    def post(self, request, collection_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        if not CanManageCollections().has_permission(request, self):
            self.permission_denied(request)
        fresh_actor(request)
        if not isinstance(request.data, dict) or set(request.data) != {'expected_revision', 'idempotency_key'}:
            raise ParseError('Supply the collection revision and idempotency key.')
        deployment_id = _uuid(request.data['idempotency_key'])
        existing = PolicyCollectionDeployment.objects.filter(pk=deployment_id).first()
        if existing:
            if existing.tenant_id != request.tenant.pk or existing.collection_id != collection_id:
                raise PublicApiError('security_collection_request_conflict', status_code=409)
            return Response(_deployment_projection(refresh_deployment(existing)))
        collection = get_object_or_404(PolicyCollection.objects.select_for_update(), pk=collection_id, tenant=request.tenant)
        if request.data['expected_revision'] != collection.revision:
            raise PublicApiError('security_collection_revision_changed', status_code=409)
        preview = _preview(collection)
        if not preview['ready']:
            raise PublicApiError('security_collection_not_ready', status_code=409)
        snapshot = _policy_projection(collection)
        deployment = PolicyCollectionDeployment.objects.create(
            id=deployment_id, tenant=request.tenant, collection=collection,
            collection_revision=collection.revision, requested_by=request.user,
            snapshot=snapshot,
        )
        sequence = 0
        for binding in collection.bindings:
            domain = DomainSecuritySettings.objects.get(pk=binding['domain_id'], tenant=request.tenant)
            for policy_index, entry in enumerate(collection.entries):
                sequence += 1
                PolicyCollectionDeploymentItem.objects.create(
                    deployment=deployment, domain=domain, policy_index=policy_index, sequence=sequence,
                    selection={
                        'entry': copy.deepcopy(entry), 'binding': copy.deepcopy(binding),
                        'preflight_id': str(uuid.uuid4()), 'write_id': str(uuid.uuid4()),
                    },
                )
        deployment = refresh_deployment(deployment)
        _audit(request.tenant, request.user, 'security.policy_collection_deployment_requested',
               'policy_collection_deployment', deployment.pk,
               {'collection_id': str(collection.pk), 'revision': collection.revision, 'items': deployment.items.count()})
        return Response(_deployment_projection(deployment), status=202)
