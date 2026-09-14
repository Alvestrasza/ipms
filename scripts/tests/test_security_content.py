# File Name: test_security_content.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Parser, scope, provenance, and pinned Microsoft SCT content regression tests.
"""Run: python -m unittest discover -s scripts/tests -p test_security_content.py -v."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IMPORTER = load_module("security_content_importer", ROOT / "scripts/import-security-baselines.py")
CONTENT = load_module("security_content_generated", ROOT / "services/control-plane/src/ipms/apps/security/content.py")
PACKAGE_DIR = ROOT / "build/security-content"
HAVE_PACKAGES = all((PACKAGE_DIR / (package["baseline_id"] + ".zip")).is_file() for package in IMPORTER.PACKAGES)


def pol_entry(path, name, reg_type, raw):
    wide = lambda text: text.encode("utf-16-le")
    return (wide("[" + path + "\0;" + name + "\0;") + struct.pack("<I", reg_type) + wide(";")
            + struct.pack("<I", len(raw)) + wide(";") + raw + wide("]"))


def pol(*entries):
    return b"PReg\x01\x00\x00\x00" + b"".join(entries)


def sourced(record, *, component="gpo-one", scope="machine", index=0, path="Machine/registry.pol"):
    return {**record, "component_id": component, "component_name": component, "scope": scope,
            "source_path": path, "source_record": index, "source_sha256": "a" * 64, "source_format": "registry.pol"}


def zip_bytes(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, value in files:
            archive.writestr(name, value)
    return buffer.getvalue()


class RegistryPolicyParserTests(unittest.TestCase):
    def test_binary_separators_do_not_change_record_boundaries(self):
        binary = b";\x00]\x00[\x00\x00\x00"
        parsed = IMPORTER.registry_records(pol(
            pol_entry("Software\\Policies\\Example", "Binary", 3, binary),
            pol_entry("Software\\Policies\\Example", "Enabled", 4, struct.pack("<I", 0xffffffff)),
        ))
        self.assertEqual(parsed[0]["expected"], {"hex": binary.hex()})
        self.assertEqual(parsed[1]["expected"], 0xffffffff)
        control = IMPORTER.normalized_control(sourced(parsed[0]))
        self.assertEqual(control["comparison"], "unsupported")
        self.assertIsNone(control["expected"])
        self.assertEqual(control["source_records"][0]["original"]["expected"], {"hex": binary.hex()})

    def test_string_and_multi_string_transport_terminators(self):
        parsed = IMPORTER.registry_records(pol(
            pol_entry("K", "Empty", 1, "\0".encode("utf-16-le")),
            pol_entry("K", "Xml", 1, "<Rule/>\r\n\0".encode("utf-16-le")),
            pol_entry("K", "Multi", 7, "one\0two\0\0".encode("utf-16-le")),
            pol_entry("K", "EmptyMulti", 7, "\0\0".encode("utf-16-le")),
        ))
        self.assertEqual([item["expected"] for item in parsed], ["", "<Rule/>\r\n", ["one", "two"], []])

    def test_wrong_width_and_truncation_are_rejected(self):
        valid = pol(pol_entry("K", "V", 4, struct.pack("<I", 1)))
        for malformed in (b"", b"PReg\x02\0\0\0", valid[:-1], valid[:-6], valid[:20],
                          pol(pol_entry("K", "V", 4, b"\x01\0")),
                          pol(pol_entry("K", "V", 1, b"\x01"))):
            with self.subTest(data=malformed[:12]), self.assertRaises((ValueError, UnicodeError)):
                IMPORTER.registry_records(malformed)

    def test_single_delete_is_absence_and_bulk_reset_stays_unknown(self):
        records = IMPORTER.registry_records(pol(
            pol_entry("K", "**del.Logging", 1, " \0".encode("utf-16-le")),
            pol_entry("K", "**delvals.", 1, " \0".encode("utf-16-le")),
            pol_entry("K", "1", 1, "required\0".encode("utf-16-le")),
        ))
        controls = [IMPORTER.normalized_control(sourced(record)) for record in records]
        self.assertEqual((controls[0]["name"], controls[0]["comparison"], controls[0]["expected"]), ("Logging", "absent", None))
        self.assertEqual(controls[0]["source_records"][0]["original"]["name"], "**del.Logging")
        self.assertEqual(IMPORTER.native_probe(controls[1]), "unsupported")
        self.assertEqual(controls[1]["kind"], "unsupported")
        self.assertEqual(controls[2]["expected"], "required")

    def test_reg_none_key_creation_is_not_an_empty_default_value(self):
        records = IMPORTER.registry_records(pol(pol_entry("K", "", 0, b""), pol_entry("K", "", 1, b"\0\0")))
        controls = [IMPORTER.normalized_control(sourced(record)) for record in records]
        self.assertEqual(controls[0]["kind"], "unsupported")
        self.assertEqual((controls[1]["kind"], controls[1]["expected"]), ("registry", ""))

    def test_qword_and_expand_string_do_not_inherit_supported_registry_type(self):
        for reg_type, value in ((11, struct.pack("<Q", 1)), (2, "%SystemRoot%\0".encode("utf-16-le"))):
            parsed = IMPORTER.registry_records(pol(pol_entry("K", "V", reg_type, value)))[0]
            control = IMPORTER.normalized_control(sourced(parsed))
            self.assertEqual(IMPORTER.native_probe(control), "unsupported")


class SecurityTemplateParserTests(unittest.TestCase):
    def test_registry_types_quoted_comma_and_empty_rights(self):
        parsed = IMPORTER.inf_records(
            '[Unicode]\nUnicode=yes\n[Version]\nsignature="$CHICAGO$"\n'
            '[Registry Values]\nMACHINE\\Software\\Example\\Text=1,"a,b"\n'
            'MACHINE\\Software\\Example\\Enabled=4,1\n'
            '[Privilege Rights]\nSeDenyNetworkLogonRight=\n'
            'SeBackupPrivilege=*S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-544\n'.encode("utf-8"))
        self.assertEqual(len(parsed), 4)
        self.assertEqual(parsed[0]["expected"], "a,b")
        self.assertEqual(parsed[1]["expected"], 1)
        self.assertEqual(parsed[2]["expected"], [])
        self.assertEqual(parsed[3]["expected"], ["S-1-5-32-544", "S-1-5-32-551"])

    def test_unresolved_account_name_and_unknown_section_remain_in_manifest(self):
        records = IMPORTER.inf_records(b"[Privilege Rights]\nSeBackupPrivilege=Administrators\n[Other Extension]\nA=1\n")
        controls = [IMPORTER.normalized_control(sourced(record)) for record in records]
        self.assertEqual(len(controls), 2)
        self.assertTrue(all(control["kind"] == "unsupported" for control in controls))
        self.assertEqual(controls[0]["source_records"][0]["original"]["expected"], "Administrators")

    def test_service_blank_sddl_does_not_invent_acl_requirement(self):
        records = IMPORTER.inf_records(b'[Service General Setting]\n"AppIDSvc",2,""\n"OtherSvc",3,"D:(A;;CC;;;SY)"\n')
        controls = [IMPORTER.normalized_control(sourced(record)) for record in records]
        self.assertEqual((controls[0]["kind"], controls[0]["expected"]), ("service", 2))
        self.assertEqual(IMPORTER.native_probe(controls[0]), "service_start")
        self.assertEqual(IMPORTER.native_probe(controls[1]), "unsupported")

    def test_registry_overflow_and_wrong_hive_do_not_produce_machine_probe(self):
        with self.assertRaises(ValueError):
            IMPORTER.inf_records(b"[Registry Values]\nMACHINE\\K\\V=4,4294967296\n")
        record = IMPORTER.inf_records(b"[Registry Values]\nUSER\\K\\V=4,1\n")[0]
        self.assertEqual(IMPORTER.native_probe(IMPORTER.normalized_control(sourced(record))), "unsupported")

    def test_audit_guid_and_mask_are_the_identity_not_localized_label(self):
        header = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n"
        line = ",System,Credential Validation,{0CCE923F-69AE-11D9-BED3-505054503030},Success and Failure,,3\n"
        parsed = IMPORTER.audit_records((header + line).encode())[0]
        self.assertEqual((parsed["path"], parsed["expected"]), ("{0cce923f-69ae-11d9-bed3-505054503030}", 3))
        for broken in (line.replace(",,3", ",,4"), line.replace("0CCE923F", "not-guid")):
            with self.assertRaises(ValueError):
                IMPORTER.audit_records((header + broken).encode())


class CompositionTests(unittest.TestCase):
    def test_last_component_wins_with_complete_override_provenance(self):
        raw = IMPORTER.registry_records(pol(pol_entry("Software\\Example", "Enabled", 4, struct.pack("<I", 0))))[0]
        first = sourced(raw, component="first")
        second = sourced({**raw, "path": "software\\example", "name": "ENABLED", "expected": 1}, component="second")
        third = sourced({**raw, "expected": 1}, component="third")
        controls = IMPORTER.normalize_controls([first, second, third], "baseline", "server")
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["expected"], 1)
        self.assertEqual(controls[0]["source_components"], ["first", "second", "third"])
        self.assertEqual([row["resolution"] for row in controls[0]["source_records"]], ["overridden", "equivalent", "effective"])
        self.assertEqual([row["original"]["expected"] for row in controls[0]["source_records"]], [0, 1, 1])

    def test_same_gpo_extension_conflict_is_rejected(self):
        raw = IMPORTER.registry_records(pol(pol_entry("K", "V", 4, struct.pack("<I", 0))))[0]
        with self.assertRaisesRegex(ValueError, "Conflicting GPO extensions"):
            IMPORTER.normalize_controls([sourced(raw), sourced({**raw, "expected": 1}, path="Machine/GptTmpl.inf")], "baseline", "server")

    def test_user_and_domain_scope_cannot_generate_native_machine_probe(self):
        raw = IMPORTER.registry_records(pol(pol_entry("K", "V", 4, struct.pack("<I", 1))))[0]
        for scope in ("user", "domain"):
            control = IMPORTER.normalized_control(sourced(raw, scope=scope))
            self.assertEqual(control["scope"], scope)
            self.assertEqual(IMPORTER.native_probe(control), "unsupported")

    def test_archive_traversal_and_case_ambiguous_members_are_rejected(self):
        for files in ([('../outside.txt', b'data')], [('GPO/value', b'a'), ('gpo/VALUE', b'b')], [('C:/target', b'data')]):
            with self.subTest(files=files), self.assertRaises(ValueError):
                IMPORTER.safe_archive(zip_bytes(files))

    def test_unrecognized_gpo_payload_is_not_silently_omitted(self):
        base = "GPOs/{00000000-0000-0000-0000-000000000001}/"
        files = [(base + "bkupInfo.xml", b"<Backup><GPODisplayName>Example</GPODisplayName></Backup>"),
                 (base + "DomainSysvol/GPO/Machine/Preferences/Registry.xml", b"<Registry/>")]
        with IMPORTER.safe_archive(zip_bytes(files)) as archive, self.assertRaisesRegex(ValueError, "Unaccounted GPO payload"):
            IMPORTER.read_components(archive)

    def test_policyrules_reference_detects_missing_or_changed_setting(self):
        data = pol(pol_entry("K", "V", 4, struct.pack("<I", 1)))
        base = "GPOs/{00000000-0000-0000-0000-000000000001}/"
        reference = ('<PolicyRules><ComputerConfig><Key>K</Key><Value>V</Value><RegType>REG_DWORD</RegType>'
                     '<RegData>0</RegData><PolicyName>Example</PolicyName></ComputerConfig></PolicyRules>').encode()
        files = [(base + "bkupInfo.xml", b"<Backup><GPODisplayName>Example</GPODisplayName></Backup>"),
                 (base + "DomainSysvol/GPO/Machine/registry.pol", data), ("Reference.PolicyRules", reference)]
        with IMPORTER.safe_archive(zip_bytes(files)) as archive:
            components = IMPORTER.read_components(archive)
            with self.assertRaisesRegex(ValueError, "does not match"):
                IMPORTER.policy_rules_inventory(archive, components)


class GeneratedContentTests(unittest.TestCase):
    def test_full_expected_profile_counts_and_source_accounting(self):
        expected = {(package["baseline_id"], profile): count for package in IMPORTER.PACKAGES for profile, count in package["raw_counts"].items()}
        self.assertEqual(set(CONTENT.MANIFESTS), set(expected))
        self.assertEqual(sum(expected.values()), 4105)
        for identity, count in expected.items():
            with self.subTest(identity=identity):
                manifest = CONTENT.MANIFESTS[identity]
                controls = manifest["controls"]
                self.assertEqual(manifest["coverage"]["raw_instruction_count"], count)
                references = [(record["source_path"], record["source_record"]) for control in controls for record in control["source_records"]]
                self.assertEqual(len(references), count)
                self.assertEqual(len(set(references)), count)
                self.assertEqual(manifest["coverage"]["control_count"], len(controls))
                self.assertTrue(all(control["source_components"] and control["source_records"] for control in controls))

    def test_manifest_hashes_and_generated_header_match_backend_data(self):
        manifests = list(CONTENT.MANIFESTS.values())
        for manifest in manifests:
            body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
            self.assertEqual(IMPORTER.digest(IMPORTER.canonical_json(body)), manifest["manifest_sha256"])
        self.assertEqual(IMPORTER.digest(IMPORTER.canonical_json(manifests)), CONTENT.CATALOG_SHA256)
        self.assertEqual((ROOT / "agent/include/ipms/agent/security_baseline_content.hpp").read_bytes(),
                         IMPORTER.render_header(manifests, CONTENT.CATALOG_SHA256))

    def test_server_2016_dc_uses_the_actual_four_component_installer_order(self):
        manifest = CONTENT.MANIFESTS[("microsoft-windows-server-2016", "domain-controller")]
        self.assertEqual(manifest["selection"]["selected_component_ids"], [
            "{37BBB33A-A159-427D-AD58-67B1BE126AD6}", "{4095647A-14FE-4CE4-955A-F2311B0D62D1}",
            "{714FD77E-8FDD-4CB0-B3F7-FF49815473FF}", "{1D2C9D38-6BB1-4C90-B5EB-2850EA18AE06}",
        ])
        self.assertFalse(any("Internet Explorer" in component["name"] for component in manifest["components"]))
        self.assertEqual(manifest["coverage"]["raw_instruction_count"], 179)

    def test_domains_users_and_unsupported_instructions_are_retained(self):
        for manifest in CONTENT.MANIFESTS.values():
            components = {component["id"]: component["name"] for component in manifest["components"]}
            for control in manifest["controls"]:
                if any("Domain Security" in components[component] for component in control["source_components"]):
                    self.assertEqual(control["scope"], "domain")
                if any("/User/" in record["source_path"] for record in control["source_records"]):
                    self.assertEqual(control["scope"], "user")
                if control["kind"] == "unsupported" or control["scope"] != "machine":
                    self.assertEqual(IMPORTER.native_probe(control), "unsupported")
            self.assertTrue(any(control["scope"] == "domain" for control in manifest["controls"]))

    def test_source_sample_and_equivalent_duplicate_are_preserved(self):
        manifest = CONTENT.MANIFESTS[("microsoft-windows-server-2025", "server")]
        control = next(control for control in manifest["controls"] if control["name"] == "EnableLUA")
        self.assertEqual((control["id"], control["expected"], control["value_type"]), ("ctrl-57a510cf671ddedf61f8854b", 1, "dword"))
        self.assertEqual(control["source_records"][0]["line"], 17)
        self.assertEqual(manifest["coverage"]["equivalent_instruction_count"], 1)
        self.assertEqual(manifest["coverage"]["overridden_instruction_count"], 0)

    def test_all_expected_values_fit_the_scalar_or_list_contract(self):
        for manifest in CONTENT.MANIFESTS.values():
            for control in manifest["controls"]:
                with self.subTest(control=control["id"]):
                    self.assertIsInstance(control["expected"], (type(None), str, int, bool, list))
                    if isinstance(control["expected"], list):
                        self.assertTrue(all(isinstance(value, str) for value in control["expected"]))
                    self.assertIn(control["value_type"], ("", "dword", "string", "string_list"))
                    if not control["value_type"]:
                        self.assertEqual(IMPORTER.native_probe(control), "unsupported")

    def test_policyrules_are_crosschecked_and_private_source_paths_are_not_copied(self):
        for manifest in CONTENT.MANIFESTS.values():
            for reference in manifest["policy_rules_references"]:
                self.assertEqual(reference["crosscheck"], "all-referenced-gpo-instructions-match")
                self.assertGreater(reference["matched_instruction_count"], 0)
        self.assertNotIn("SourceFile", json.dumps(list(CONTENT.MANIFESTS.values())))

    def test_generated_loader_rejects_changed_expected_value(self):
        changed = copy.deepcopy(list(CONTENT.MANIFESTS.values()))
        changed[0]["controls"][0]["expected"] = 999
        with self.assertRaisesRegex(RuntimeError, "integrity"):
            exec(compile(IMPORTER.render_python(changed, CONTENT.CATALOG_SHA256), "test-content.py", "exec"), {})

    @unittest.skipUnless(HAVE_PACKAGES, "Download pinned SCT packages with importer --download for the offline reproduction test")
    def test_pinned_packages_reproduce_product_artifacts_byte_for_byte(self):
        manifests, catalog_hash = IMPORTER.build_catalog(PACKAGE_DIR)
        self.assertEqual(catalog_hash, CONTENT.CATALOG_SHA256)
        for relative, data in IMPORTER.generated_files(manifests, catalog_hash).items():
            self.assertEqual((ROOT / relative).read_bytes(), data, relative.as_posix())


if __name__ == "__main__":
    unittest.main()
