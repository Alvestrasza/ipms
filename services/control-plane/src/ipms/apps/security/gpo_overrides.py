# File Name: gpo_overrides.py
# Version: v0.1.0 | Created: 2026-09-16 | Last Modified: 2026-09-16
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Typed sparse tenant overrides pinned to compiled baseline content.
import re

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import ParseError
from rest_framework.response import Response

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.tenancy.models import Tenant
from .administration import CanManageBaselines
from .domains import DomainJSONParser
from .gpo_approvals import fresh_actor
from .gpo_jobs import ACTIVE, _invalidate, canonical, digest
from .models import GpoImportJob, GpoOverride
from .views import SecurityReadView, query
from rest_framework.authentication import SessionAuthentication

OVERRIDE_FIELDS = {'override_id', 'override_revision', 'override_sha256', 'override_entries'}


def component_for(baseline_id, backup_id):
    from .gpo_override_content import OVERRIDE_COMPONENTS
    component = OVERRIDE_COMPONENTS.get((baseline_id, backup_id))
    if not component:
        raise ParseError('Select an available override component.')
    return component


def normalize_entries(component, entries, *, keep_baseline=False):
    if not isinstance(entries, list) or len(entries) > 128:
        raise ParseError('Supply at most 128 sparse override entries.')
    settings = {row['setting_id']: row for row in component['settings']}
    seen, normalized = set(), []
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'setting_id', 'value'} or not isinstance(item['setting_id'], str):
            raise ParseError('Supply setting identity and value only.')
        key, value = item['setting_id'], item['value']
        setting = settings.get(key)
        if key in seen or not setting or setting.get('editable') is not True:
            raise ParseError('Select distinct editable settings from this component.')
        seen.add(key)
        kind = setting['value_type']
        if kind == 'integer':
            valid = type(value) is int and setting.get('min', 0) <= value <= setting.get('max', 2**32 - 1)
        elif kind == 'string':
            valid = _string(value, setting.get('max_length', 4096))
        elif kind == 'string_list':
            valid = (isinstance(value, list) and len(value) <= setting.get('max_items', 128)
                     and all(_string(entry, setting.get('max_length', 2048)) for entry in value)
                     and len(set(value)) == len(value))
        else:
            valid = False
        if valid and setting.get('enum_options'):
            valid = any(value == option['value'] and type(value) is type(option['value']) for option in setting['enum_options'])
        if valid and setting['kind'] == 'privilege_right':
            valid = all(_sid(entry) for entry in value)
        if not valid:
            raise ParseError('The override value has an invalid type or exceeds its documented limits.')
        if keep_baseline or value != setting['baseline_value']:
            normalized.append({'setting_id': key, 'value': value})
    normalized.sort(key=lambda item: item['setting_id'])
    if len(canonical(normalized)) > 8192:
        raise ParseError('The override exceeds the bounded transport budget.')
    return normalized


def _sid(value):
    if not isinstance(value, str) or not re.fullmatch(r'S-1-(?:0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*)){1,15}', value):
        return False
    parts = value.split('-')
    return int(parts[2]) < 2**48 and all(int(item) < 2**32 for item in parts[3:])


def _string(value, maximum):
    return (isinstance(value, str) and len(value) <= maximum
            and not any(ord(ch) < 32 or ord(ch) == 127 or 0xD800 <= ord(ch) <= 0xDFFF for ch in value))


def patch_document(row):
    return {'id': str(row.pk), 'revision': row.revision, 'baseline_id': row.baseline_id,
            'backup_id': row.backup_id, 'artifact_sha256': row.artifact_sha256, 'entries': row.entries}


def override_projection(row):
    return {**patch_document(row), 'name': row.name, 'enabled': row.enabled, 'kind': row.kind,
            'sha256': digest(patch_document(row))}


def assignment_patch(row):
    return {'override_id': str(row.pk), 'override_revision': row.revision,
            'override_sha256': digest(patch_document(row)), 'override_entries': row.entries}


def patch_valid(assignment):
    try:
        from .gpo_jobs import uuid_text
        if uuid_text(assignment['override_id']) != assignment['override_id']:
            return False
        if type(assignment['override_revision']) is not int or not 1 <= assignment['override_revision'] < 2**31:
            return False
        component = component_for(assignment['baseline_id'], assignment['backup_id'])
        if component['artifact_sha256'] != assignment['artifact_sha256']:
            return False
        if normalize_entries(component, assignment['override_entries'], keep_baseline=True) != assignment['override_entries']:
            return False
        value = {'id': assignment['override_id'], 'revision': assignment['override_revision'],
                 'baseline_id': assignment['baseline_id'], 'backup_id': assignment['backup_id'],
                 'artifact_sha256': assignment['artifact_sha256'], 'entries': assignment['override_entries']}
        return bool(assignment['override_entries']) and digest(value) == assignment['override_sha256']
    except (KeyError, ValueError, TypeError, ParseError):
        return False


def current_patch(assignment, tenant, *, allow_historical=False):
    if not patch_valid(assignment):
        return False
    row = GpoOverride.objects.filter(pk=assignment['override_id'], tenant=tenant).first()
    if row is None:
        return False
    if allow_historical:
        return (row.baseline_id == assignment['baseline_id'] and row.backup_id == assignment['backup_id']
                and row.artifact_sha256 == assignment['artifact_sha256'])
    return row.enabled and assignment_patch(row) == {key: assignment[key] for key in OVERRIDE_FIELDS}


def _validate(data, *, update=False):
    keys = {'name', 'entries', 'enabled'} | ({'expected_revision'} if update else {'baseline_id', 'backup_id'})
    if not isinstance(data, dict) or set(data) != keys or type(data['enabled']) is not bool:
        raise ParseError('Supply exactly the documented override fields.')
    if not isinstance(data['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,47}', data['name']):
        raise ParseError('Supply only the purpose token used by the GPO naming template.')
    if update:
        if type(data['expected_revision']) is not int or not 1 <= data['expected_revision'] < 2**31 - 1:
            raise ParseError('Supply the current override revision.')
    elif not isinstance(data['baseline_id'], str) or not isinstance(data['backup_id'], str):
        raise ParseError('Supply a baseline component identity.')


def _audit(row, user, action):
    AuditEvent.objects.create(tenant=row.tenant, actor=str(user.pk), action=action,
        object_type='security_gpo_override', object_id=str(row.pk), outcome='succeeded',
        details={'revision': row.revision, 'enabled': row.enabled, 'entry_count': len(row.entries),
                 'sha256': digest(patch_document(row))})


class OverrideView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (*SecurityReadView.permission_classes, CanManageBaselines)
    parser_classes = (DomainJSONParser,)
    http_method_names = ('get', 'post', 'head', 'options')

    def get(self, request):
        query(request, set())
        return Response({'results': [override_projection(row) for row in GpoOverride.objects.filter(
            tenant=request.tenant, kind=GpoOverride.OVERRIDE)]})

    @transaction.atomic
    def post(self, request):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        _validate(request.data)
        component = component_for(request.data['baseline_id'], request.data['backup_id'])
        entries = normalize_entries(component, request.data['entries'])
        if GpoOverride.objects.filter(tenant=request.tenant, kind=GpoOverride.OVERRIDE).count() >= 1000:
            raise PublicApiError('security_override_limit', status_code=409)
        row = GpoOverride.objects.create(tenant=request.tenant, kind=GpoOverride.OVERRIDE, name=request.data['name'],
            baseline_id=request.data['baseline_id'], backup_id=request.data['backup_id'],
            artifact_sha256=component['artifact_sha256'], entries=entries, enabled=request.data['enabled'])
        _audit(row, request.user, 'security.gpo_override_created')
        return Response(override_projection(row), status=201)


class OverrideDetailView(OverrideView):
    http_method_names = ('get', 'patch', 'delete', 'head', 'options')

    def get(self, request, override_id):
        query(request, set())
        return Response(override_projection(get_object_or_404(
            GpoOverride, pk=override_id, tenant=request.tenant, kind=GpoOverride.OVERRIDE)))

    @transaction.atomic
    def patch(self, request, override_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        row = get_object_or_404(GpoOverride.objects.select_for_update(), pk=override_id,
                                tenant=request.tenant, kind=GpoOverride.OVERRIDE)
        _validate(request.data, update=True)
        if request.data['expected_revision'] != row.revision:
            raise PublicApiError('security_override_revision_changed', status_code=409)
        component = component_for(row.baseline_id, row.backup_id)
        if component['artifact_sha256'] != row.artifact_sha256:
            raise PublicApiError('security_override_artifact_changed', status_code=409)
        entries = normalize_entries(component, request.data['entries'])
        row.name, row.enabled, row.entries = request.data['name'], request.data['enabled'], entries
        row.revision += 1
        row.save()
        for job in GpoImportJob.objects.select_for_update().filter(tenant=request.tenant, status__in=ACTIVE,
                assignment__override_id=str(row.pk)):
            _invalidate(job, 'override_configuration_changed')
        _audit(row, request.user, 'security.gpo_override_updated')
        return Response(override_projection(row))

    @transaction.atomic
    def delete(self, request, override_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        row = get_object_or_404(GpoOverride.objects.select_for_update(), pk=override_id,
                                tenant=request.tenant, kind=GpoOverride.OVERRIDE)
        if (not isinstance(request.data, dict) or set(request.data) != {'expected_revision'}
                or type(request.data['expected_revision']) is not int):
            raise ParseError('Supply the current override revision.')
        if request.data['expected_revision'] != row.revision:
            raise PublicApiError('security_override_revision_changed', status_code=409)
        if row.policies.exists():
            raise PublicApiError('security_override_in_use', status_code=409)
        _audit(row, request.user, 'security.gpo_override_deleted')
        row.delete()
        return Response(status=204)


class OverrideCatalogView(OverrideView):
    http_method_names = ('get', 'head', 'options')

    def get(self, request):
        query(request, {'baseline_id', 'backup_id'})
        baseline, backup = request.query_params.get('baseline_id'), request.query_params.get('backup_id')
        component = component_for(baseline, backup)
        return Response({'baseline_id': baseline, 'backup_id': backup,
                         'artifact_sha256': component['artifact_sha256'], 'settings': component['settings']})


class CustomGpoView(OverrideView):
    """Author sparse custom GPO content without mutating AD."""

    def get(self, request):
        query(request, set())
        return Response({'results': [override_projection(row) for row in GpoOverride.objects.filter(
            tenant=request.tenant, kind=GpoOverride.CUSTOM)]})

    @transaction.atomic
    def post(self, request):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        _validate(request.data)
        component = component_for(request.data['baseline_id'], request.data['backup_id'])
        entries = normalize_entries(component, request.data['entries'], keep_baseline=True)
        if not entries:
            raise ParseError('Select at least one custom setting.')
        if GpoOverride.objects.filter(tenant=request.tenant, kind=GpoOverride.CUSTOM).count() >= 1000:
            raise PublicApiError('security_custom_gpo_limit', status_code=409)
        row = GpoOverride.objects.create(
            tenant=request.tenant, kind=GpoOverride.CUSTOM, name=request.data['name'],
            baseline_id=request.data['baseline_id'], backup_id=request.data['backup_id'],
            artifact_sha256=component['artifact_sha256'], entries=entries, enabled=request.data['enabled'],
        )
        _audit(row, request.user, 'security.custom_gpo_created')
        return Response(override_projection(row), status=201)


class CustomGpoDetailView(CustomGpoView):
    http_method_names = ('get', 'patch', 'delete', 'head', 'options')

    def _row(self, request, custom_id, *, lock=False):
        rows = GpoOverride.objects.select_for_update() if lock else GpoOverride.objects
        return get_object_or_404(rows, pk=custom_id, tenant=request.tenant, kind=GpoOverride.CUSTOM)

    def get(self, request, custom_id):
        query(request, set())
        return Response(override_projection(self._row(request, custom_id)))

    @transaction.atomic
    def patch(self, request, custom_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        row = self._row(request, custom_id, lock=True)
        _validate(request.data, update=True)
        if request.data['expected_revision'] != row.revision:
            raise PublicApiError('security_custom_gpo_revision_changed', status_code=409)
        component = component_for(row.baseline_id, row.backup_id)
        if component['artifact_sha256'] != row.artifact_sha256:
            raise PublicApiError('security_custom_gpo_artifact_changed', status_code=409)
        entries = normalize_entries(component, request.data['entries'], keep_baseline=True)
        if not entries:
            raise ParseError('Select at least one custom setting.')
        row.name, row.enabled, row.entries = request.data['name'], request.data['enabled'], entries
        row.revision += 1
        row.save()
        for job in GpoImportJob.objects.select_for_update().filter(
                tenant=request.tenant, status__in=ACTIVE, assignment__override_id=str(row.pk)):
            _invalidate(job, 'custom_gpo_configuration_changed')
        _audit(row, request.user, 'security.custom_gpo_updated')
        return Response(override_projection(row))

    @transaction.atomic
    def delete(self, request, custom_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        fresh_actor(request)
        self.check_permissions(request)
        row = self._row(request, custom_id, lock=True)
        if request.data != {'expected_revision': row.revision}:
            raise ParseError('Supply the current custom GPO revision.')
        if row.policies.exists():
            raise PublicApiError('security_custom_gpo_in_use', status_code=409)
        _audit(row, request.user, 'security.custom_gpo_deleted')
        row.delete()
        return Response(status=204)


class CustomGpoCatalogView(OverrideCatalogView):
    pass
