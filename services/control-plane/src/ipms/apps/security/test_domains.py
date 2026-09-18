# File Name: test_domains.py
# Version: v0.1.2 | Created: 2026-09-14 | Last Modified: 2026-09-17
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Public tenant domain configuration, naming and ordering behavior.
from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from ipms.apps.audit.models import AuditEvent
from ipms.apps.tenancy.models import PlatformAdministrator, Tenant, TenantMembership
from .catalog import DEPLOYABLE_BASELINES

URL = '/api/v1/security/domain-settings/'
TEMPLATE = '{tier}-{scope}-{target}-{purpose}_V{version}'


class DomainSettingsTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug='domain-settings', display_name='Domain settings')
        self.other = Tenant.objects.create(slug='other-domain-settings', display_name='Other')
        self.user = get_user_model().objects.create_user(username='domain-admin', password='test')
        self.membership = TenantMembership.objects.create(tenant=self.tenant, user=self.user, role='tenant_admin')
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))

    def draft(self, **changes):
        data = {
            'domain_name': 'example.invalid',
            'tier_ous': {'0': ['OU=Domain Controllers,DC=example,DC=invalid'],
                         '1': ['OU=Servers,DC=example,DC=invalid', 'OU=Applications,DC=example,DC=invalid'],
                         '2': ['OU=Clients,DC=example,DC=invalid']},
            'gpo_name_template': TEMPLATE,
            'baseline_order': [item.id for item in DEPLOYABLE_BASELINES],
        }
        return {**data, **changes}

    def create(self, **changes):
        return self.client.post(URL, self.draft(**changes), format='json')

    def test_create_and_reload_multiple_ous_with_no_directory_mutation(self):
        response = self.create()
        self.assertEqual(response.status_code, 201, getattr(response, 'data', response.content))
        self.assertEqual(response.data['revision'], 1)
        self.assertEqual(response.data['verification_status'], 'unverified')
        self.assertEqual(response.data['tier_ous'], self.draft()['tier_ous'])
        self.assertEqual(response['Cache-Control'], 'no-store')
        listing = self.client.get(URL)
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.data['results'][0]['id'], response.data['id'])
        self.assertEqual(len(listing.data['baseline_options']), 8)
        self.assertTrue(all(row['provider'] == 'microsoft' for row in listing.data['baseline_options']))
        self.assertEqual(len(response.data['name_previews']), 3)
        from .models import GpoImportJob
        self.assertFalse(GpoImportJob.objects.exists())
        event = AuditEvent.objects.get(action='security.domain_settings_created')
        self.assertEqual(event.tenant_id, self.tenant.id)
        self.assertNotIn('tier_ous', event.details)

    def test_order_and_template_persist_with_revision_conflict(self):
        created = self.create().data
        url = URL + created['id'] + '/'
        new_order = list(reversed(self.draft()['baseline_order']))
        update = self.draft(baseline_order=new_order, gpo_name_template='AC-{tier}-{scope}-{target}-{purpose}_V{version}')
        update['expected_revision'] = 1
        saved = self.client.put(url, update, format='json')
        self.assertEqual(saved.status_code, 200, saved.data)
        self.assertEqual(saved.data['revision'], 2)
        self.assertTrue(saved.data['name_previews'][0]['production'].startswith('AC-0-C-ALL-'))
        self.assertEqual(self.client.put(url, update, format='json').status_code, 409)
        self.assertEqual(self.client.get(url).data['baseline_order'], new_order)

    def test_tenant_access_is_required_and_platform_admin_cannot_manage_tenant(self):
        self.membership.role = 'reader'
        self.membership.save()
        self.assertEqual(self.client.get(URL).status_code, 403)
        self.assertEqual(self.create().status_code, 403)
        self.membership.role = 'tenant_admin'
        self.membership.save()
        platform_user = get_user_model().objects.create_user(username='domain-platform', password='test')
        PlatformAdministrator.objects.create(user=platform_user)
        self.client.force_authenticate(platform_user)
        self.assertEqual(self.client.get(URL).status_code, 404)

    def test_cross_tenant_objects_are_hidden(self):
        created = self.create().data
        TenantMembership.objects.create(tenant=self.other, user=self.user, role='tenant_admin')
        self.client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.other.id))
        self.assertEqual(self.client.get(URL).data['results'], [])
        self.assertEqual(self.client.get(URL + created['id'] + '/').status_code, 404)

    def test_reject_invalid_or_cross_domain_ou_and_ambiguous_tier_scopes(self):
        cases = [
            {'0': ['CN=Computers,DC=example,DC=invalid'], '1': [], '2': []},
            {'0': ['OU=T0,DC=other,DC=invalid'], '1': [], '2': []},
            {'0': ['OU=T0,DC=example,DC=invalid'], '1': ['OU=Child,OU=T0,DC=example,DC=invalid'], '2': []},
            {'0': ['OU=T0,DC=example,DC=invalid'], '1': ['ou=t0,dc=EXAMPLE,dc=invalid'], '2': []},
            {'0': ['OU=A\x00B,DC=example,DC=invalid'], '1': [], '2': []},
            {'0': [], '1': [], '2': [], 'A': []},
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(self.create(tier_ous=value).status_code, 400)

    def test_accept_escaped_and_unicode_ou_names(self):
        result = self.create(tier_ous={'0': [], '1': [r'OU=Servers\, Europe,OU=Équipe,DC=example,DC=invalid', r'OU=Trailing\ ,DC=example,DC=invalid'], '2': []})
        self.assertEqual(result.status_code, 201, result.data)
        self.assertEqual(self.create(tier_ous={'0': [], '1': ['OU=Trailing ,DC=example,DC=invalid'], '2': []}).status_code, 400)

    def test_short_root_ou_names_are_saved_as_domain_bound_dns(self):
        short = {'0': ['_T0'], '1': ['_T1'], '2': ['_T2']}
        expected = {'0': ['OU=_T0,DC=example,DC=invalid'],
                    '1': ['OU=_T1,DC=example,DC=invalid'],
                    '2': ['OU=_T2,DC=example,DC=invalid']}
        created = self.create(tier_ous=short)
        self.assertEqual(created.status_code, 201, created.data)
        url = URL + created.data['id'] + '/'
        self.assertEqual(self.client.get(url).data['tier_ous'], expected)
        updated = self.client.put(url, {**self.draft(tier_ous={**short, '1': ['Application Servers']}),
                                       'expected_revision': 1}, format='json')
        self.assertEqual(updated.status_code, 200, updated.data)
        self.assertEqual(updated.data['tier_ous']['1'], ['OU=Application Servers,DC=example,DC=invalid'])
        from .models import GpoImportJob
        self.assertFalse(GpoImportJob.objects.exists())

    def test_exact_domain_root_is_a_tier_zero_target_only(self):
        root = 'DC=example,DC=invalid'
        mappings = self.draft()['tier_ous']
        mappings['0'] = [root, *mappings['0']]
        created = self.create(tier_ous=mappings)
        self.assertEqual(created.status_code, 201, created.data)
        self.assertEqual(created.data['tier_ous'], mappings)

        for tier in ('1', '2'):
            with self.subTest(tier=tier):
                invalid = {key: ([] if key != tier else [root]) for key in ('0', '1', '2')}
                response = self.create(tier_ous=invalid)
                self.assertEqual(response.status_code, 400, response.data)
                self.assertEqual(response.data['error']['code'], f'security_domain_tier_{tier}_ou_invalid')

        foreign = self.create(tier_ous={'0': ['DC=other,DC=invalid'], '1': [], '2': []})
        self.assertEqual(foreign.status_code, 400, foreign.data)
        self.assertEqual(foreign.data['error']['code'], 'security_domain_tier_0_ou_invalid')

    def test_normalized_short_names_cannot_bypass_tier_overlap_checks(self):
        for mappings in [
            {'0': ['_T0'], '1': ['OU=Child,OU=_T0,DC=example,DC=invalid'], '2': []},
            {'0': ['_T0', 'OU=_T0,DC=example,DC=invalid'], '1': [], '2': []},
        ]:
            with self.subTest(mappings=mappings):
                result = self.create(tier_ous=mappings)
                self.assertEqual(result.status_code, 400)
                self.assertEqual(result.data['error']['code'], 'security_domain_ou_overlap')

    def test_invalid_fields_return_safe_actionable_codes(self):
        for changes, code in [
            ({'domain_name': 'example.invalid/path'}, 'security_domain_name_invalid'),
            ({'gpo_name_template': '{unknown}'}, 'security_domain_template_invalid'),
            ({'baseline_order': []}, 'security_domain_order_invalid'),
        ]:
            result = self.create(**changes)
            self.assertEqual(result.status_code, 400)
            self.assertEqual(result.data['error']['code'], code)
        for tier in ('0', '1', '2'):
            for invalid in ['OU=_T1', '_T1/Servers', '../Servers', 'OU=_T1,DC=other,DC=invalid', '_T\x001', '_T1\n', '']:
                with self.subTest(tier=tier, invalid=invalid):
                    result = self.create(tier_ous={**{'0': [], '1': [], '2': []}, tier: [invalid]})
                    self.assertEqual(result.status_code, 400)
                    self.assertEqual(result.data['error']['code'], f'security_domain_tier_{tier}_ou_invalid')
                    self.assertNotIn(invalid or 'OU=', result.data['error']['message'])

    def test_strict_naming_and_known_complete_order(self):
        for template in ['{tier.__class__}', '{tier!r}', '{tier:04}', '{unknown}', TEMPLATE + '\n', TEMPLATE + '/x']:
            with self.subTest(template=template):
                self.assertEqual(self.create(gpo_name_template=template).status_code, 400)
        for order in [[], ['cis-missing'], self.draft()['baseline_order'] * 2]:
            self.assertEqual(self.create(baseline_order=order).status_code, 400)
        self.assertEqual(self.create(domain_name='192.168.1.1').status_code, 400)
        self.assertEqual(self.create(domain_name='example.invalid/path').status_code, 400)

    def test_no_duplicate_domain_or_rename_and_strict_json(self):
        created = self.create().data
        self.assertEqual(self.create(domain_name='EXAMPLE.INVALID').status_code, 409)
        update = self.draft(domain_name='different.invalid')
        update['expected_revision'] = 1
        self.assertEqual(self.client.put(URL + created['id'] + '/', update, format='json').status_code, 400)
        self.assertEqual(self.client.post(URL, '{"domain_name":"a","domain_name":"b"}', content_type='application/json').status_code, 400)
        self.assertEqual(self.client.post(URL, b' ' * 65537, content_type='application/json').status_code, 413)

    def test_session_writes_require_csrf(self):
        client = APIClient(enforce_csrf_checks=True)
        client.force_login(self.user)
        client.credentials(HTTP_X_IPMS_TENANT_ID=str(self.tenant.id))
        self.assertEqual(client.post(URL, self.draft(), format='json').status_code, 403)
