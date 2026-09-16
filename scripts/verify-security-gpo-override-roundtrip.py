# File Name: verify-security-gpo-override-roundtrip.py
# Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Independently verify native sparse GPO rendering against the immutable Python catalog.
"""Validate the native JSONL export without trusting native file addresses or types."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services/control-plane/src'))
from ipms.apps.security.gpo_override_content import OVERRIDE_COMPONENTS

spec = importlib.util.spec_from_file_location('ipms_sct', ROOT / 'scripts/import-security-baselines.py')
SCT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SCT)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def local(tag):
    return tag.rsplit('}', 1)[-1]


def policy_records(filename, data):
    lower = filename.casefold()
    if lower.endswith('/registry.pol'):
        return SCT.registry_records(data)
    if lower.endswith('/gpttmpl.inf'):
        return SCT.inf_records(data)
    if lower.endswith('/audit.csv'):
        return SCT.audit_records(data)
    if lower.endswith(('comment.cmtx', 'gpreport.xml')):
        root = ET.fromstring(data)
        if lower.endswith('gpreport.xml') and any(local(node.tag) == 'ExtensionData' for node in root.iter()):
            raise AssertionError(f'{filename}: report contains unselected ExtensionData')
        return []
    raise AssertionError(f'Unexpected rendered file: {filename}')


def signature(record):
    return record['kind'], record['path'].casefold(), record['name'].casefold()


def verify(path):
    all_editable = {row['setting_id'] for component in OVERRIDE_COMPONENTS.values()
                    for row in component['settings'] if row['editable']}
    covered, components, cases, rendered_records = set(), set(), 0, 0
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line:
            continue
        document = json.loads(line)
        if set(document) != {'job', 'files'} or not isinstance(document['job'], dict) or not isinstance(document['files'], dict):
            raise AssertionError(f'Line {line_number}: invalid export envelope')
        job, encoded_files = document['job'], document['files']
        component = OVERRIDE_COMPONENTS.get((job.get('baseline_id'), job.get('backup_id')))
        if component is None or component['artifact_sha256'] != job.get('artifact_sha256'):
            raise AssertionError(f'Line {line_number}: component identity mismatch')
        components.add((job['baseline_id'], job['backup_id']))
        expected_by_file = {}
        settings = {row['setting_id']: row for row in component['settings']}
        for entry in job.get('override_entries', []):
            if set(entry) != {'setting_id', 'value'} or entry['setting_id'] in covered:
                raise AssertionError(f'Line {line_number}: duplicate or invalid sparse entry')
            setting = settings.get(entry['setting_id'])
            if setting is None or not setting['editable'] or entry['value'] == setting['baseline_value']:
                raise AssertionError(f'Line {line_number}: unbound, read-only, or unchanged entry')
            expected_by_file.setdefault(setting['file'], {})[signature(setting)] = (setting, entry['value'])
            covered.add(entry['setting_id'])
        patch = {'id': job['override_id'], 'revision': job['override_revision'],
                 'baseline_id': job['baseline_id'], 'backup_id': job['backup_id'],
                 'artifact_sha256': job['artifact_sha256'], 'entries': job['override_entries']}
        if sha(patch) != job.get('override_sha256'):
            raise AssertionError(f'Line {line_number}: override digest mismatch')
        marker = f"IPMS managed override; id={job['managed_id']}; definition={job['override_id']}"
        if job.get('owner_marker') != marker:
            raise AssertionError(f'Line {line_number}: owner marker mismatch')
        actual_by_file = {}
        for filename, hex_data in encoded_files.items():
            if not isinstance(hex_data, str):
                raise AssertionError(f'Line {line_number}: non-hex payload')
            try:
                data = bytes.fromhex(hex_data)
            except ValueError as exc:
                raise AssertionError(f'Line {line_number}: malformed hex payload') from exc
            rows = policy_records(filename, data)
            actual_by_file[filename] = {signature(row): row for row in rows}
            if len(actual_by_file[filename]) != len(rows):
                raise AssertionError(f'Line {line_number}: duplicate rendered address in {filename}')
            rendered_records += len(rows)
        for filename, expected in expected_by_file.items():
            actual = actual_by_file.get(filename)
            if actual is None or set(actual) != set(expected):
                raise AssertionError(f'Line {line_number}: sparse address mismatch in {filename}')
            for key, (setting, value) in expected.items():
                row = actual[key]
                if row['expected'] != value or type(row['expected']) is not type(value):
                    raise AssertionError(f'Line {line_number}: value mismatch for {setting["setting_id"]}')
                if setting['kind'] == 'registry' and row.get('reg_type_number') != setting['reg_type']:
                    raise AssertionError(f'Line {line_number}: registry type mismatch for {setting["setting_id"]}')
                if setting['kind'] == 'service' and row.get('security_descriptor') != setting['security_descriptor']:
                    raise AssertionError(f'Line {line_number}: service descriptor changed')
                if setting['kind'] == 'audit' and (row.get('target'), row.get('exclusion')) != (setting['target'], setting['exclusion']):
                    raise AssertionError(f'Line {line_number}: audit identity changed')
        for filename, actual in actual_by_file.items():
            if actual and filename not in expected_by_file:
                raise AssertionError(f'Line {line_number}: unselected policy data in {filename}')
        cases += 1
    if covered != all_editable:
        raise AssertionError(f'Editable catalog coverage mismatch: {len(covered)} of {len(all_editable)}')
    if set(OVERRIDE_COMPONENTS) != components:
        raise AssertionError(f'Component coverage mismatch: {len(components)} of {len(OVERRIDE_COMPONENTS)}')
    return {'cases': cases, 'components': len(components), 'settings': len(covered),
            'rendered_records': rendered_records,
            'jsonl_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('jsonl', type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.jsonl), sort_keys=True))


if __name__ == '__main__':
    main()
