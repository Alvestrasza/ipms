# File Name: import-security-gpo-overrides.py
# Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Derive typed override addresses from checksum-verified Microsoft GPO artifacts.
"""Generate matching Portal/Agent metadata. Never accept browser-supplied addresses."""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import xml.etree.ElementTree as XML
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services/control-plane/src'))
from ipms.apps.security.gpo_content import _CATALOG

spec = importlib.util.spec_from_file_location('ipms_sct', ROOT / 'scripts/import-security-baselines.py')
SCT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(SCT)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack(component, raw):
    if len(raw) != component['artifact_size'] or sha(raw) != component['artifact_sha256']:
        raise ValueError('Artifact identity mismatch')
    if raw[:8] != b'IPMSGPO1' or struct.unpack_from('<I', raw, 8)[0] != len(component['files']):
        raise ValueError('Artifact descriptor mismatch')
    offset = 12
    result = {}
    for item in component['files']:
        length = struct.unpack_from('<I', raw, offset)[0]
        offset += 4
        data = raw[offset:offset + length]
        offset += length
        if len(data) != item['bytes'] or sha(data) != item['sha256']:
            raise ValueError('Artifact member mismatch')
        result[item['path']] = data
    if offset != len(raw):
        raise ValueError('Trailing artifact bytes')
    return result


def metadata(component, filename, index, record):
    kind = record['kind']
    value_type = ('string_list' if kind == 'privilege_right' else
                  'integer' if type(record['expected']) is int else
                  'string' if isinstance(record['expected'], str) else 'unsupported')
    structured_string = (value_type == 'string' and
                         (record['expected'].lstrip().startswith('<') or
                          any(ord(ch) < 32 or ord(ch) == 127 for ch in record['expected'])))
    address = [component['artifact_sha256'], filename, index, kind,
               record['path'], record['name'], record.get('reg_type_number')]
    result = dict(setting_id=sha(canonical(address).encode()), file=filename, record_index=index,
                  kind=kind, path=record['path'], name=record['name'], section=record.get('section', ''),
                  reg_type=record.get('reg_type_number'), hive=record.get('hive', ''),
                  scope='user' if '/User/' in filename else 'machine', value_type=value_type,
                  baseline_value=record['expected'], label=record['name'], category=record.get('section') or record['path'],
                  editable=value_type != 'unsupported' and not record['name'].startswith('**') and not structured_string,
                  readonly_reason='', min=0, max=4294967295, max_length=2048, max_items=64,
                  enum_options=[])
    if kind == 'system_access':
        result['min'] = -1
    if kind == 'service':
        result.update(max=4, security_descriptor=record['security_descriptor'])
    if kind == 'audit':
        result.update(max=3, target=record['target'], exclusion=record['exclusion'])
    if not result['editable']:
        result['readonly_reason'] = 'structured_registry_value' if structured_string else 'structural_instruction'
    if kind == 'registry' and record['path'].casefold() == r'software\policies\microsoft\windows defender\spynet':
        if record['name'].casefold() == 'spynetreporting':
            result.update(label='Microsoft MAPS membership', max=2, enum_options=[
                {'value': 0, 'label': 'Disabled'}, {'value': 1, 'label': 'Basic membership'},
                {'value': 2, 'label': 'Advanced membership'}])
        if record['name'].casefold() == 'submitsamplesconsent':
            result.update(label='Sample submission', max=3, enum_options=[
                {'value': 0, 'label': 'Always prompt'}, {'value': 1, 'label': 'Send safe samples'},
                {'value': 2, 'label': 'Never send'}, {'value': 3, 'label': 'Send all samples'}])
    return result


def empty_xml(filename, data):
    root = ET.fromstring(data)
    local = lambda tag: tag.rsplit('}', 1)[-1]
    if filename.endswith('comment.cmtx'):
        for child in root:
            if local(child.tag) in ('comments', 'resources'):
                child.clear()
    else:
        # Preserve namespace declarations used by QName attribute values such
        # as xsi:type. Generic ElementTree serialization changes their meaning.
        text = SCT.decode_text(data)
        text = re.sub(r'encoding=["\']utf-16["\']', 'encoding="utf-8"', text, count=1, flags=re.I)
        expected = sum(local(node.tag) == 'ExtensionData' for node in root.iter())
        pattern = r'<(?P<tag>(?:[A-Za-z_][\w.-]*:)?ExtensionData)\b[^>]*>(?:(?!<(?:(?:[A-Za-z_][\w.-]*:)?ExtensionData)\b).)*?</(?P=tag)\s*>|<(?:[A-Za-z_][\w.-]*:)?ExtensionData\s*/>'
        text, removed = re.subn(pattern, '', text, flags=re.S)
        if removed != expected or any(local(node.tag) == 'ExtensionData' for node in ET.fromstring(text).iter()):
            raise ValueError('Unexpected report extension structure')
        end = text.rfind('</')
        if end < 0:
            raise ValueError('Missing report root close')
        return text[:end] + '<!-- IPMS override source: selected settings only. -->' + text[end:]
    return XML.tostring(root, encoding='utf-8', xml_declaration=True).decode('utf-8')


def build(directory):
    components = []
    templates = []
    for component in _CATALOG['components']:
        files = unpack(component, (directory / component['artifact_filename']).read_bytes())
        settings = []
        empty_files = []
        for filename, data in files.items():
            if filename.lower().endswith('/registry.pol'):
                records = SCT.registry_records(data)
            elif filename.lower().endswith('/gpttmpl.inf'):
                records = SCT.inf_records(data)
            elif filename.lower().endswith('/audit.csv'):
                records = SCT.audit_records(data)
            else:
                if filename.endswith(('comment.cmtx', 'gpreport.xml')):
                    empty_files.append({'file': filename, 'content': empty_xml(filename, data)})
                continue
            settings.extend(metadata(component, filename, i, row) for i, row in enumerate(records))
        identities = collections.Counter((s['file'].casefold(), s['path'].casefold(), s['name'].casefold()) for s in settings)
        for setting in settings:
            if identities[(setting['file'].casefold(), setting['path'].casefold(), setting['name'].casefold())] > 1:
                setting.update(editable=False, readonly_reason='ambiguous_source_address')
        assert len({s['setting_id'] for s in settings}) == len(settings)
        components.append({k: component[k] for k in ('baseline_id', 'backup_id', 'artifact_sha256', 'name', 'scope')} | {'settings': settings})
        templates.append(empty_files)
    return components, templates


def render(components, templates):
    body = canonical(components)
    digest = sha(body.encode())
    python = ('# File Name: gpo_override_content.py\n# Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16\n'
              '# Author: Alice Endelgard | Organization: Alvestrasza Corporation\n'
              '# Description: Generated typed baseline override metadata; regenerate with import-security-gpo-overrides.py.\n'
              'import hashlib\nimport json\n\nOVERRIDE_CATALOG_SHA256 = ' + repr(digest) + '\n'
              '_COMPONENTS = json.loads(' + repr(body) + ')\n'
              "if hashlib.sha256(json.dumps(_COMPONENTS,sort_keys=True,separators=(',', ':'),ensure_ascii=False).encode()).hexdigest() != OVERRIDE_CATALOG_SHA256:\n"
              "    raise RuntimeError('Override catalog integrity check failed')\n"
              "OVERRIDE_COMPONENTS = {(c['baseline_id'], c['backup_id']): c for c in _COMPONENTS}\n")
    header = ['// File Name: security_gpo_override_content.hpp',
              '// Version: v0.1.0 | Created: 2026-09-16 | Modified: 2026-09-16',
              '// Author: Alice Endelgard | Organization: Alvestrasza Corporation',
              '// Description: Generated fixed override addresses and empty report metadata.',
              '#pragma once', '#include <array>', '#include <span>', '#include <string_view>',
              'namespace ipms::agent::gpo {',
              'struct override_setting_descriptor { std::string_view setting_id, metadata_json; };',
              'struct override_empty_file_descriptor { std::string_view relative_path, content; };',
              'struct override_component_descriptor { std::string_view baseline_id, backup_id, artifact_sha256; std::span<const override_setting_descriptor> settings; std::span<const override_empty_file_descriptor> empty_files; };',
              'inline constexpr std::string_view override_catalog_sha256 = "' + digest + '";']
    for i, component in enumerate(components):
        header.append(f'inline constexpr std::array<override_setting_descriptor, {len(component["settings"])}> override_settings_{i}{{{{')
        for row in component['settings']:
            value = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
            assert ')IPMS"' not in value
            header.append('  {"' + row['setting_id'] + '", R"IPMS(' + value + ')IPMS"},')
        header.append('}};')
        header.append(f'inline constexpr std::array<override_empty_file_descriptor, {len(templates[i])}> override_empty_files_{i}{{{{')
        for empty in templates[i]:
            # Keep generated source line-oriented. JSON string escapes are also
            # valid C++ string escapes and avoid embedded XML whitespace that
            # would otherwise appear as trailing whitespace in the header.
            header.append('  {' + json.dumps(empty['file']) + ', ' + json.dumps(empty['content'], ensure_ascii=True) + '},')
        header.append('}};')
    header.append(f'inline constexpr std::array<override_component_descriptor, {len(components)}> override_components{{{{')
    for i, c in enumerate(components):
        header.append('  {' + ','.join(json.dumps(c[k]) for k in ('baseline_id', 'backup_id', 'artifact_sha256')) + f',override_settings_{i},override_empty_files_{i}' + '},')
    header.extend(['}};', '} // namespace ipms::agent::gpo', ''])
    return python, '\n'.join(header)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifact-dir', type=Path, default=ROOT / 'build/security-gpo-packages')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    components, templates = build(args.artifact_dir)
    outputs = render(components, templates)
    paths = [ROOT / 'services/control-plane/src/ipms/apps/security/gpo_override_content.py',
             ROOT / 'agent/include/ipms/agent/security_gpo_override_content.hpp']
    for path, text in zip(paths, outputs):
        payload = text.encode('utf-8')
        if args.check:
            assert path.read_bytes() == payload, path
        else:
            path.write_bytes(payload)
    print(json.dumps({'components': len(components), 'settings': sum(len(c['settings']) for c in components),
                      'editable': sum(s['editable'] for c in components for s in c['settings'])}))


if __name__ == '__main__':
    main()
