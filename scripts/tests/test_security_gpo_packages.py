# File Name: test_security_gpo_packages.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Verify immutable GPO backup packages, metadata closure, and bounded artifact encoding.
"""Run: python -m unittest discover -s scripts/tests -p test_security_gpo_packages.py -v."""

import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GENERATOR = load_module("gpo_package_generator", ROOT / "scripts/import-security-gpo-packages.py")
BACKUP_ID = "{00000000-0000-0000-0000-000000000001}"
SOURCE_ID = "{00000000-0000-0000-0000-000000000002}"
PREFIX = f"Example/GPOs/{BACKUP_ID}/"
PAYLOAD_PATH = "DomainSysvol/GPO/Machine/registry.pol"
REGISTRY_EXTENSION = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
BKP_NS = "http://www.microsoft.com/GroupPolicy/GPOOperations"


def sample_files():
    return {
        "bkupInfo.xml": (
            '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest">'
            f"<GPOGuid>{SOURCE_ID}</GPOGuid><GPODomain>example.invalid</GPODomain>"
            "<GPODomainGuid>{00000000-0000-0000-0000-000000000003}</GPODomainGuid>"
            "<GPODomainController>dc.example.invalid</GPODomainController>"
            f"<ID>{BACKUP_ID}</ID><GPODisplayName>Example Computer</GPODisplayName></BackupInst>"
        ).encode(),
        "Backup.xml": (
            f'<GroupPolicyBackupScheme xmlns="{BKP_NS}" xmlns:bkp="{BKP_NS}" '
            'bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate"><GroupPolicyObject>'
            "<SecurityGroups/><FilePaths/><GroupPolicyCoreSettings>"
            f"<ID>{SOURCE_ID}</ID><Domain>example.invalid</Domain>"
            "<SecurityDescriptor/>"
            "<DisplayName>Example Computer</DisplayName><Options>1</Options>"
            "<UserVersionNumber>0</UserVersionNumber><MachineVersionNumber>1</MachineVersionNumber>"
            f"<MachineExtensionGuids>[{REGISTRY_EXTENSION}{{D02B1F72-3407-48AE-BA88-E8213C6761F1}}]</MachineExtensionGuids>"
            "<UserExtensionGuids/><WMIFilter/></GroupPolicyCoreSettings>"
            f'<GroupPolicyExtension bkp:ID="{REGISTRY_EXTENSION}" bkp:DescName="Registry">'
            '<FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\\registry.pol" '
            f'bkp:SourceExpandedPath="\\\\dc.example.invalid\\sysvol\\example.invalid\\Policies\\{SOURCE_ID}\\Machine\\registry.pol" '
            'bkp:Location="DomainSysvol\\GPO\\Machine\\registry.pol"/>'
            "</GroupPolicyExtension></GroupPolicyObject></GroupPolicyBackupScheme>"
        ).encode(),
        "gpreport.xml": (
            '<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings" '
            'xmlns:t="http://www.microsoft.com/GroupPolicy/Types">'
            f"<Identifier><t:Identifier>{SOURCE_ID}</t:Identifier><t:Domain>example.invalid</t:Domain></Identifier>"
            "<Name>Example Computer</Name><User><Enabled>false</Enabled></User>"
            "<Computer><Enabled>true</Enabled></Computer></GPO>"
        ).encode(),
        PAYLOAD_PATH: b"PReg\x01\x00\x00\x00",
    }


def archive_bytes(files, extra=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for path, data in files.items():
            archive.writestr(PREFIX + path, data)
        for name, data in extra or ():
            archive.writestr(name, data)
    return stream.getvalue()


def inspect(files):
    component = {"id": BACKUP_ID, "name": "Example Computer", "records": [{"scope": "machine"}]}
    with GENERATOR.safe_archive(archive_bytes(files)) as archive:
        return GENERATOR.inspect_component(archive, component)


class BackupValidationTests(unittest.TestCase):
    def test_original_bytes_and_source_identity_are_preserved(self):
        metadata, files = inspect(sample_files())
        self.assertEqual(metadata["backup_id"], BACKUP_ID)
        self.assertEqual(metadata["source_gpo_id"], SOURCE_ID)
        self.assertEqual(metadata["scope"], "machine")
        self.assertEqual(metadata["source_options"], 1)
        self.assertEqual(files, sample_files())

    def test_missing_metadata_or_payload_fails_closed(self):
        for missing in ("Backup.xml", "bkupInfo.xml", "gpreport.xml", PAYLOAD_PATH):
            files = sample_files()
            del files[missing]
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                inspect(files)

    def test_scripts_tasks_and_unrecognized_files_cannot_enter_bundle(self):
        for path in ("DomainSysvol/GPO/Machine/Scripts/Startup/run.ps1",
                     "DomainSysvol/GPO/Machine/Preferences/ScheduledTasks/Tasks.xml",
                     "DomainSysvol/GPO/Machine/registry.pol.exe", "payload.dll", "manifest.xml"):
            files = sample_files()
            files[path] = b"unexpected"
            with self.subTest(path=path), self.assertRaises(ValueError):
                inspect(files)

    def test_metadata_id_name_scope_and_report_must_agree(self):
        changes = (
            ("bkupInfo.xml", BACKUP_ID.encode(), SOURCE_ID.encode()),
            ("Backup.xml", SOURCE_ID.encode(), BACKUP_ID.encode()),
            ("gpreport.xml", SOURCE_ID.encode(), BACKUP_ID.encode()),
            ("Backup.xml", b"Example Computer", b"Other Computer"),
            ("gpreport.xml", b"Example Computer", b"Other Computer"),
            ("Backup.xml", b"<Options>1</Options>", b"<Options>2</Options>"),
            ("Backup.xml", b"<WMIFilter/>", b"<WMIFilter>external</WMIFilter>"),
        )
        for path, before, after in changes:
            files = sample_files()
            files[path] = files[path].replace(before, after)
            with self.subTest(path=path, after=after), self.assertRaises(ValueError):
                inspect(files)

    def test_external_or_traversing_metadata_references_are_rejected(self):
        replacements = (
            (b"DomainSysvol\\GPO\\Machine\\registry.pol", b"..\\..\\outside.pol"),
            (b"%GPO_MACH_FSPATH%\\registry.pol", b"C:\\outside.pol"),
            (b"%GPO_MACH_FSPATH%\\registry.pol", b"%GPO_MACH_FSPATH%\\..\\User\\registry.pol"),
            (b"\\\\dc.example.invalid\\sysvol", b"\\\\external.invalid\\share"),
            (b' bkp:Location=', b' bkp:ReEvaluateFunction="RunPayload" bkp:Location='),
            (REGISTRY_EXTENSION.encode(), b"{00000000-0000-0000-0000-000000000099}"),
            (b"<FilePaths/>", b"<FilePaths><Path>\\\\external.invalid\\share</Path></FilePaths>"),
        )
        for before, after in replacements:
            files = sample_files()
            files["Backup.xml"] = files["Backup.xml"].replace(before, after)
            with self.subTest(after=after), self.assertRaises(ValueError):
                inspect(files)

    def test_doctype_and_xml_entities_are_rejected(self):
        files = sample_files()
        files["Backup.xml"] = b'<!DOCTYPE test [<!ENTITY data SYSTEM "file:///outside">]>' + files["Backup.xml"]
        with self.assertRaises(ValueError):
            inspect(files)

    def test_metadata_file_closure_rejects_unreferenced_or_duplicate_payloads(self):
        files = sample_files()
        files["DomainSysvol/GPO/User/registry.pol"] = b"PReg\x01\x00\x00\x00"
        with self.assertRaisesRegex(ValueError, "account for every"):
            inspect(files)
        files = sample_files()
        source = files["Backup.xml"]
        reference = source[source.index(b"<FSObjectFile"):source.index(b"</GroupPolicyExtension>")]
        files["Backup.xml"] = source.replace(b"</GroupPolicyExtension>", reference + b"</GroupPolicyExtension>")
        with self.assertRaises(ValueError):
            inspect(files)

    def test_unreviewed_empty_directory_is_rejected(self):
        component = {"id": BACKUP_ID, "name": "Example Computer", "records": [{"scope": "machine"}]}
        data = archive_bytes(sample_files(), [(PREFIX + "DomainSysvol/GPO/Machine/Tasks/", b"")])
        with GENERATOR.safe_archive(data) as archive, self.assertRaisesRegex(ValueError, "directory"):
            GENERATOR.inspect_component(archive, component)

    def test_xml_depth_and_core_extension_identifiers_are_bounded(self):
        with self.assertRaisesRegex(ValueError, "structural"):
            GENERATOR.xml_root(b"<x>" * (GENERATOR.MAX_XML_DEPTH + 1) + b"</x>" * (GENERATOR.MAX_XML_DEPTH + 1))
        with self.assertRaisesRegex(ValueError, "Unreviewed"):
            GENERATOR._validate_core_extensions("[{00000000-0000-0000-0000-000000000009}]")

    def test_archive_windows_path_aliases_links_and_case_duplicates_are_rejected(self):
        for path in ("../outside", "C:/outside", "GPO/NUL", "GPO/file. ", "GPO/file:stream", "GPO//file"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                GENERATOR.safe_archive(archive_bytes({}, [(path, b"x")]))
        with self.assertRaises(ValueError):
            GENERATOR.safe_archive(archive_bytes({}, [("GPO/File", b"x"), ("gpo/file", b"y")]))
        link = zipfile.ZipInfo("GPO/link")
        link.create_system = 3
        link.external_attr = (0o120777 << 16)
        with self.assertRaises(ValueError):
            GENERATOR.safe_archive(archive_bytes({}, [(link, b"target")]))

    def test_file_size_and_scope_ambiguity_fail_closed(self):
        files = sample_files()
        files["gpreport.xml"] = b"x" * (GENERATOR.MAX_FILE_BYTES + 1)
        with self.assertRaises(ValueError):
            inspect(files)
        with GENERATOR.safe_archive(archive_bytes(sample_files())) as archive, self.assertRaises(ValueError):
            GENERATOR.inspect_component(archive, {"id": BACKUP_ID, "name": "Example Computer",
                                                  "records": [{"scope": "machine"}, {"scope": "user"}]})


class ArtifactEncodingTests(unittest.TestCase):
    def test_wire_format_is_exact_and_uses_no_received_paths(self):
        files = {"bkupInfo.xml": b"metadata", "Backup.xml": b"backup"}
        expected = b"IPMSGPO1" + struct.pack("<I", 2) + struct.pack("<I", 6) + b"backup" + struct.pack("<I", 8) + b"metadata"
        self.assertEqual(GENERATOR.encode_artifact(files), expected)
        self.assertNotIn(b"Backup.xml", expected)

    def test_artifact_size_and_file_count_are_bounded(self):
        for files in ({}, {str(i): b"x" for i in range(GENERATOR.MAX_FILES + 1)},
                      {"one": b"x" * (GENERATOR.MAX_FILE_BYTES + 1)},
                      {"one": b"x" * GENERATOR.MAX_FILE_BYTES, "two": b"x" * GENERATOR.MAX_FILE_BYTES}):
            with self.subTest(count=len(files)), self.assertRaises(ValueError):
                GENERATOR.encode_artifact(files)

    def test_cache_is_immutable_and_checks_existing_content(self):
        data = GENERATOR.encode_artifact({"Backup.xml": b"data"})
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            GENERATOR.prepare_artifacts(Path(temporary), {digest: data})
            artifact = Path(temporary) / (digest + ".ipmsgpo")
            self.assertEqual(artifact.read_bytes(), data)
            GENERATOR.prepare_artifacts(Path(temporary), {digest: data})
            artifact.write_bytes(b"different")
            with self.assertRaises(ValueError):
                GENERATOR.prepare_artifacts(Path(temporary), {digest: data})
            self.assertEqual(artifact.read_bytes(), b"different")

    def test_alias_is_stable_ascii_bounded_and_differentiates_long_names(self):
        first = GENERATOR.purpose_alias("MSFT " + "A" * 100 + " First")
        second = GENERATOR.purpose_alias("MSFT " + "A" * 100 + " Second")
        self.assertRegex(first, r"^[A-Za-z][A-Za-z0-9]{0,79}$")
        self.assertNotEqual(first, second)
        self.assertEqual(first, GENERATOR.purpose_alias("MSFT " + "A" * 100 + " First"))

    def test_generated_loader_rejects_changed_trust_metadata(self):
        catalog = {"schema_version": 1, "format": "IPMSGPO1", "components": [], "profiles": []}
        rendered = GENERATOR.render_python(catalog).decode()
        with self.assertRaisesRegex(RuntimeError, "integrity"):
            exec(rendered.replace('"format": "IPMSGPO1"', '"format": "MODIFIED"'), {})


PACKAGE_DIR = ROOT / "build/security-content"
HAVE_PACKAGES = all((PACKAGE_DIR / (package["baseline_id"] + ".zip")).is_file() for package in GENERATOR.SOURCE.PACKAGES)


@unittest.skipUnless(HAVE_PACKAGES, "Official pinned SCT archives are not available locally")
class PinnedPackageIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog, cls.artifacts = GENERATOR.build_catalog(PACKAGE_DIR)

    def test_complete_profiles_and_distinct_original_objects(self):
        self.assertEqual(len(self.catalog["components"]), 64)
        self.assertEqual(len(self.catalog["profiles"]), 12)
        profiles = {(row["baseline_id"], row["profile"]): row["backup_ids"] for row in self.catalog["profiles"]}
        dc_ids = profiles[("microsoft-windows-server-2025", "domain-controller")]
        self.assertEqual(len(dc_ids), 6)
        self.assertIn("{88603F56-DC8F-4132-8A8C-8FE5EB0B4B1A}", dc_ids)
        self.assertIn("{40CF40AD-F1B2-433F-A5C9-032DB7424608}", dc_ids)
        self.assertIn("{F74D904A-2A4B-4865-8877-3E71FEFF91FF}", dc_ids)

    def test_generated_outputs_reproduce_and_scanner_hash_is_unchanged(self):
        for relative, data in GENERATOR.generated_files(self.catalog).items():
            self.assertEqual((ROOT / relative).read_bytes(), data, str(relative))
        content = load_module("baseline_scan_content", ROOT / "services/control-plane/src/ipms/apps/security/content.py")
        self.assertEqual(content.CATALOG_SHA256, "ba507940b52f0a4b87f6551211871b6bd3eebd5ea01c1d91a4b3fbdd679d471b")

    def test_directories_and_public_metadata_retain_only_required_provenance(self):
        for component in self.catalog["components"]:
            prefix = component["source_backup_path"] + "/"
            with zipfile.ZipFile(PACKAGE_DIR / (component["baseline_id"] + ".zip")) as archive:
                original = {name[len(prefix):].rstrip("/") for name in archive.namelist()
                            if name.startswith(prefix) and name.endswith("/") and name != prefix}
            expected = original | {"/".join(file["path"].split("/")[:index]) for file in component["files"]
                                   for index in range(1, len(file["path"].split("/")))}
            self.assertEqual(component["directories"], sorted(expected))
            self.assertTrue(expected <= GENERATOR.ALLOWED_DIRECTORIES)
            self.assertRegex(component["purpose"], r"^[A-Za-z][A-Za-z0-9]{0,79}$")
            self.assertLessEqual(component["artifact_size"], GENERATOR.MAX_ARTIFACT_BYTES)
        rendered = GENERATOR.render_python(self.catalog).decode()
        for unnecessary in ("security.local", "DC-SEC-01", "SourceExpandedPath", "<SecurityDescriptor>", "<GroupPolicyBackupScheme"):
            self.assertNotIn(unnecessary, rendered)

    def test_every_artifact_byte_matches_descriptor_and_original_source(self):
        for component in self.catalog["components"]:
            data = self.artifacts[component["artifact_sha256"]]
            self.assertEqual(hashlib.sha256(data).hexdigest(), component["artifact_sha256"])
            self.assertEqual(len(data), component["artifact_size"])
            self.assertEqual(data[:8], b"IPMSGPO1")
            self.assertEqual(struct.unpack_from("<I", data, 8)[0], len(component["files"]))
            position = 12
            with zipfile.ZipFile(PACKAGE_DIR / (component["baseline_id"] + ".zip")) as archive:
                for file in component["files"]:
                    length = struct.unpack_from("<I", data, position)[0]
                    position += 4
                    payload = data[position:position + length]
                    position += length
                    self.assertEqual(length, file["bytes"])
                    self.assertEqual(hashlib.sha256(payload).hexdigest(), file["sha256"])
                    self.assertEqual(payload, archive.read(component["source_backup_path"] + "/" + file["path"]))
            self.assertEqual(position, len(data))

    def test_modified_archive_fails_before_metadata_or_artifact_processing(self):
        package = GENERATOR.SOURCE.PACKAGES[0]
        with tempfile.TemporaryDirectory() as temporary:
            data = bytearray((PACKAGE_DIR / (package["baseline_id"] + ".zip")).read_bytes())
            data[-1] ^= 1
            (Path(temporary) / (package["baseline_id"] + ".zip")).write_bytes(data)
            with self.assertRaisesRegex(ValueError, "checksum"):
                GENERATOR.build_catalog(Path(temporary))


if __name__ == "__main__":
    unittest.main()
