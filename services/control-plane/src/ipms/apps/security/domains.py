# File Name: domains.py
# Version: v0.1.2 | Created: 2026-09-14 | Last Modified: 2026-09-17
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Bounded domain directory targets, GPO names and draft composition order.
import re
import string
import unicodedata

from django.db import transaction
from django.shortcuts import get_object_or_404
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ParseError
from rest_framework.response import Response

from ipms.apps.audit.models import AuditEvent
from ipms.apps.core.exceptions import PublicApiError
from ipms.apps.discovery.models import WindowsServer
from ipms.apps.tenancy.models import Tenant
from ipms.apps.tenancy.permissions import HasTenantPermission
from ipms.apps.tenancy.rbac import Permission
from .administration import SmallJSONParser
from .catalog import BASELINES, BY_ID, CATALOG_REVISION
from .models import DomainSecuritySettings
from .views import SecurityReadView, query

DEFAULT_TEMPLATE = '{tier}-{scope}-{target}-{purpose}_V{version}'
TOKENS = {'tier', 'scope', 'target', 'purpose', 'version'}
DEFAULT_GPO_NAMES = {'default domain policy', 'default domain controllers policy'}


def domain_name(value):
    if not isinstance(value, str) or not 3 <= len(value) <= 253 or value != value.strip():
        raise ParseError('Supply a DNS domain name.')
    name = value.lower()
    labels = name.split('.')
    if len(labels) < 2 or all(label.isdecimal() for label in labels) or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels
    ):
        raise ParseError('Supply a DNS domain name.')
    return name


def ou_identity(value, domain, *, allow_domain_root=False):
    """Parse the supported OU/DC subset of escaped RFC4514 distinguished names.

    This compares syntax and containment, never claims the directory object exists.
    Reject unsupported multi-valued RDNs instead of interpreting them ambiguously.
    The exact selected-domain root is accepted only for an explicit Tier 0 caller.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ParseError('Supply a bounded OU distinguished name.')
    rdns, raw, escaped = [], '', False
    for char in value.strip():
        if escaped:
            raw += '\\' + char
            escaped = False
        elif char == '\\':
            escaped = True
        elif char == ',':
            rdns.append(raw)
            raw = ''
        else:
            raw += char
    if escaped:
        raise ParseError('Incomplete distinguished-name escape.')
    rdns.append(raw)
    decoded = []
    for raw in rdns:
        attribute, sep, text = raw.lstrip().partition('=')
        attribute = attribute.upper()
        if not sep or attribute not in ('OU', 'DC') or not text:
            raise ParseError('Only OU targets beneath the selected DNS domain are supported.')
        out = bytearray()
        index = 0
        while index < len(text):
            char = text[index]
            if char == '\\':
                if index + 1 >= len(text):
                    raise ParseError('Incomplete distinguished-name escape.')
                pair = text[index + 1:index + 3]
                if len(pair) == 2 and re.fullmatch('[0-9A-Fa-f]{2}', pair):
                    out.append(int(pair, 16))
                    index += 3
                    continue
                if text[index + 1] not in ',+"\\<>;=# ':
                    raise ParseError('Unsupported distinguished-name escape.')
                out.extend(text[index + 1].encode('utf-8'))
                index += 2
                continue
            if char in '+"<>;=' or (index == 0 and char in ' #') or (index == len(text) - 1 and char == ' '):
                raise ParseError('Escape distinguished-name separators and surrounding spaces.')
            out.extend(char.encode('utf-8'))
            index += 1
        try:
            normalized = unicodedata.normalize('NFC', out.decode('utf-8')).casefold()
        except UnicodeError as exc:
            raise ParseError('Invalid distinguished-name encoding.') from exc
        if not normalized or any(ord(c) < 32 or ord(c) == 127 for c in normalized):
            raise ParseError('Invalid distinguished-name value.')
        decoded.append((attribute, normalized))
    suffix = [('DC', label) for label in domain.split('.')]
    if decoded == suffix and allow_domain_root:
        return tuple(decoded)
    if len(decoded) <= len(suffix) or decoded[-len(suffix):] != suffix or any(a != 'OU' for a, _ in decoded[:-len(suffix)]):
        raise ParseError('The OU must belong to the configured DNS domain.')
    return tuple(decoded)


def validate_template(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 160:
        raise ParseError('The GPO template must contain at most 160 characters.')
    found = []
    try:
        for literal, field, spec, conversion in string.Formatter().parse(value):
            if not re.fullmatch(r'[A-Za-z0-9 ._-]*', literal):
                raise ValueError()
            if field is not None:
                if field not in TOKENS or spec or conversion:
                    raise ValueError()
                found.append(field)
    except ValueError as exc:
        raise ParseError('Use only the documented GPO naming tokens and plain name characters.') from exc
    if set(found) != TOKENS or len(found) != len(TOKENS):
        raise ParseError('Use each GPO naming token exactly once.')
    for tier in ('0', '1', '2'):
        render_name(value, tier, 'C', 'ALL', 'Baseline', '1.0.0', pilot=True)
    return value


def render_name(template, tier, scope, target, purpose, version, *, pilot=False, component_suffix='00000000'):
    if tier not in ('0', '1', '2') or scope not in ('C', 'U'):
        raise ParseError('Select one concrete tier and computer/user scope.')
    if not isinstance(target, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,31}', target):
        raise ParseError('The target alias is invalid.')
    if not isinstance(version, str) or not re.fullmatch(r'\d{1,4}\.\d{1,4}\.\d{1,4}', version):
        raise ParseError('Supply a three-part policy version.')
    if not isinstance(purpose, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', purpose):
        raise ParseError('The policy purpose is invalid.')
    if pilot:
        purpose += '-Pilot-' + component_suffix
    try:
        name = template.format(tier=tier, scope=scope, target=target, purpose=purpose, version=version)
    except (KeyError, ValueError, IndexError) as exc:
        raise ParseError('Invalid GPO template.') from exc
    if (not 1 <= len(name) <= 240 or name != name.strip() or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._-]*', name)
            or name.casefold() in DEFAULT_GPO_NAMES):
        raise ParseError('The generated GPO name is invalid or reserved.')
    return name


def validate_settings(data, *, updating=False):
    fields = {'domain_name', 'tier_ous', 'gpo_name_template', 'baseline_order'}
    if updating:
        fields.add('expected_revision')
    if not isinstance(data, dict) or set(data) != fields:
        raise ParseError('Supply exactly the documented domain settings.')
    try:
        name = domain_name(data['domain_name'])
    except ParseError as exc:
        raise PublicApiError('security_domain_name_invalid') from exc
    tiers = data['tier_ous']
    if not isinstance(tiers, dict) or set(tiers) != {'0', '1', '2'}:
        raise ParseError('Specify OU lists for tiers 0, 1 and 2.')
    identities = []
    cleaned = {}
    for tier in ('0', '1', '2'):
        values = tiers[tier]
        if not isinstance(values, list) or len(values) > 32:
            raise PublicApiError(f'security_domain_tier_{tier}_ou_invalid')
        cleaned[tier] = []
        for value in values:
            # A simple name always means an immediate child of this domain.
            # Explicit DNs retain strict containment/escaping validation below.
            if isinstance(value, str) and re.fullmatch(r'\w[\w .-]{0,63}', value):
                value = 'OU=' + value.strip() + ',' + ','.join('DC=' + label for label in name.split('.'))
            try:
                identity = ou_identity(value, name, allow_domain_root=tier == '0')
            except ParseError as exc:
                raise PublicApiError(f'security_domain_tier_{tier}_ou_invalid') from exc
            for other_tier, other in identities:
                overlaps = (len(identity) >= len(other) and identity[-len(other):] == other) or (
                    len(other) >= len(identity) and other[-len(identity):] == identity)
                root_target = len(identity) == len(name.split('.'))
                other_root_target = len(other) == len(name.split('.'))
                if identity == other or (tier != other_tier and overlaps and not (root_target or other_root_target)):
                    raise PublicApiError('security_domain_ou_overlap')
            identities.append((tier, identity))
            cleaned[tier].append(value.strip())
    order = data['baseline_order']
    if (not isinstance(order, list) or any(not isinstance(item, str) for item in order)
            or len(order) != len(BY_ID) or set(order) != set(BY_ID)):
        raise PublicApiError('security_domain_order_invalid')
    if updating and (type(data['expected_revision']) is not int or not 1 <= data['expected_revision'] <= 2**31 - 1):
        raise ParseError('Supply the expected settings revision.')
    try:
        template = validate_template(data['gpo_name_template'])
    except ParseError as exc:
        raise PublicApiError('security_domain_template_invalid') from exc
    return {'domain_name': name, 'tier_ous': cleaned, 'gpo_name_template': template,
            'baseline_order': order}


def projection(config):
    return {
        'id': str(config.id), 'domain_name': config.domain_name, 'revision': config.revision,
        'tier_ous': config.tier_ous, 'gpo_name_template': config.gpo_name_template,
        'baseline_order': config.baseline_order, 'updated_at': config.updated_at.isoformat(),
        'verification_status': 'unverified',
        'name_previews': [{'tier': tier,
                          'production': render_name(config.gpo_name_template, tier, 'C', 'ALL', 'Baseline', '1.0.0'),
                          'pilot': render_name(config.gpo_name_template, tier, 'C', 'ALL', 'Baseline', '1.0.0', pilot=True)}
                         for tier in ('0', '1', '2')],
    }


class DomainJSONParser(SmallJSONParser):
    maximum_bytes = 65536


class CanManageDomains(HasTenantPermission):
    required_permission = Permission.SECURITY_DOMAINS_MANAGE


class DomainSettingsView(SecurityReadView):
    authentication_classes = (SessionAuthentication,)
    permission_classes = (*SecurityReadView.permission_classes, CanManageDomains)
    parser_classes = (DomainJSONParser,)
    http_method_names = ('get', 'post', 'head', 'options')

    def get(self, request):
        query(request, set())
        from .gpo_jobs import baseline_options
        discovered = set()
        for value in WindowsServer.objects.filter(tenant=request.tenant).exclude(domain_name='').values_list('domain_name', flat=True).distinct()[:1000]:
            try:
                discovered.add(domain_name(value))
            except ParseError:
                continue
        return Response({'results': [projection(row) for row in DomainSecuritySettings.objects.filter(tenant=request.tenant)],
                         'discovered_domains': sorted(discovered), 'baseline_options': baseline_options(),
                         'default_name_template': DEFAULT_TEMPLATE, 'catalog_revision': CATALOG_REVISION})

    @transaction.atomic
    def post(self, request):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        self.check_permissions(request)
        data = validate_settings(request.data)
        if DomainSecuritySettings.objects.filter(tenant=request.tenant, domain_name=data['domain_name']).exists():
            raise PublicApiError('security_domain_exists', status_code=409)
        if DomainSecuritySettings.objects.filter(tenant=request.tenant).count() >= 100:
            raise PublicApiError('security_domain_limit', status_code=409)
        config = DomainSecuritySettings.objects.create(tenant=request.tenant, **data)
        AuditEvent.objects.create(tenant=request.tenant, actor=str(request.user.pk), action='security.domain_settings_created',
                                 object_type='security_domain', object_id=str(config.id), outcome='succeeded', details={'revision': 1})
        return Response(projection(config), status=201)


class DomainSettingView(DomainSettingsView):
    http_method_names = ('get', 'put', 'head', 'options')

    def get(self, request, domain_id):
        query(request, set())
        return Response(projection(get_object_or_404(DomainSecuritySettings, pk=domain_id, tenant=request.tenant)))

    @transaction.atomic
    def put(self, request, domain_id):
        query(request, set())
        request.tenant = Tenant.objects.select_for_update().get(pk=request.tenant.pk)
        self.check_permissions(request)
        config = get_object_or_404(DomainSecuritySettings.objects.select_for_update(), pk=domain_id, tenant=request.tenant)
        data = validate_settings(request.data, updating=True)
        if data['domain_name'] != config.domain_name:
            raise ParseError('Create a separate configuration for another domain; domain identity is immutable.')
        if request.data['expected_revision'] != config.revision:
            raise PublicApiError('security_domain_revision_changed', status_code=409)
        for key, value in data.items():
            setattr(config, key, value)
        config.revision += 1
        config.save()
        from .gpo_approvals import _withdraw
        _withdraw(request.tenant, domain=config)
        AuditEvent.objects.create(tenant=request.tenant, actor=str(request.user.pk), action='security.domain_settings_changed',
                                 object_type='security_domain', object_id=str(config.id), outcome='succeeded', details={'revision': config.revision})
        return Response(projection(config))
