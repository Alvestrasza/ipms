# File Name: test_security_gpo_overrides.py
# Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Verify override metadata provenance, typed boundaries, and empty report semantics.
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('override_generator', ROOT / 'scripts/import-security-gpo-overrides.py')
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)


class OverrideCatalogTests(unittest.TestCase):
    def record(self, name='SpynetReporting'):
        return {'kind': 'registry', 'path': r'Software\Policies\Microsoft\Windows Defender\SpyNet',
                'name': name, 'reg_type_number': 4, 'expected': 2}

    def descriptor(self, record=None, source='a' * 64, path='DomainSysvol/GPO/Machine/registry.pol'):
        return G.metadata({'artifact_sha256': source}, path, 0, record or self.record())

    def test_setting_identity_is_bound_to_exact_source_and_scope(self):
        first = self.descriptor()
        self.assertNotEqual(first['setting_id'], self.descriptor(source='b' * 64)['setting_id'])
        self.assertNotEqual(first['setting_id'], self.descriptor(path='DomainSysvol/GPO/User/registry.pol')['setting_id'])
        self.assertEqual(first['setting_id'], self.descriptor()['setting_id'])

    def test_defender_values_are_explicit_not_boolean_guesses(self):
        maps = self.descriptor()
        samples = self.descriptor(self.record('SubmitSamplesConsent'))
        self.assertEqual([x['value'] for x in maps['enum_options']], [0, 1, 2])
        self.assertEqual(next(x['value'] for x in samples['enum_options'] if x['label'] == 'Never send'), 2)
        self.assertEqual(samples['baseline_value'], 2)

    def test_structural_registry_directive_cannot_be_edited(self):
        row = self.descriptor(self.record('**delvals.'))
        self.assertFalse(row['editable'])
        self.assertEqual(row['readonly_reason'], 'structural_instruction')

    def test_structured_registry_string_cannot_be_replaced_as_free_text(self):
        record = {'kind': 'registry', 'path': r'Software\Policies\Microsoft\Windows\SrpV2\Exe\rule',
                  'name': 'Value', 'reg_type_number': 1,
                  'expected': '<FilePublisherRule>\r\n<Conditions />\r\n</FilePublisherRule>'}
        row = self.descriptor(record)
        self.assertFalse(row['editable'])
        self.assertEqual(row['readonly_reason'], 'structured_registry_value')

    def test_privilege_and_service_types_preserve_fixed_metadata(self):
        privilege = G.metadata({'artifact_sha256': 'a' * 64}, 'x', 0,
                              {'kind': 'privilege_right', 'path': '', 'name': 'SeExample', 'expected': ['S-1-5-32-544']})
        service = G.metadata({'artifact_sha256': 'a' * 64}, 'x', 0,
                            {'kind': 'service', 'path': '', 'name': 'Example', 'expected': 4, 'security_descriptor': ''})
        self.assertEqual(privilege['value_type'], 'string_list')
        self.assertEqual(service['max'], 4)
        self.assertEqual(service['security_descriptor'], '')

    def test_empty_report_does_not_claim_unselected_policies(self):
        data = b'<GPO xmlns="urn:example"><Name>Baseline</Name><Computer><Enabled>true</Enabled><ExtensionData><Policy>secret-setting</Policy></ExtensionData></Computer><User><ExtensionData/></User></GPO>'
        rendered = G.empty_xml('gpreport.xml', data)
        root = ET.fromstring(rendered)
        self.assertFalse(any(x.tag.endswith('ExtensionData') for x in root.iter()))
        self.assertNotIn('secret-setting', rendered)
        self.assertIn('selected settings only', rendered)

    def test_artifact_tampering_and_trailing_data_rejected(self):
        data = b'PReg' + struct.pack('<I', 1)
        raw = b'IPMSGPO1' + struct.pack('<II', 1, len(data)) + data
        component = {'artifact_size': len(raw), 'artifact_sha256': hashlib.sha256(raw).hexdigest(),
                     'files': [{'path': 'Machine/registry.pol', 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]}
        self.assertEqual(G.unpack(component, raw), {'Machine/registry.pol': data})
        with self.assertRaises(ValueError):
            G.unpack(component, raw[:-1] + b'X')
        with self.assertRaises(ValueError):
            G.unpack(component, raw + b'X')


if __name__ == '__main__':
    unittest.main()
