# File Name: import-security-gpo-packages.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Build immutable, bounded GPO data artifacts from checksum-pinned Microsoft backups.
"""Generate native/server trust descriptors and optional private GPO artifacts.

This offline tool reuses the reviewed SCT source pins and profile selection. It
never executes vendor code or edits the existing assessment manifests. Vendor
bytes are written only when --prepare-artifacts explicitly selects a private
cache; the repository receives identities, sizes and hashes, never vendor files.

IPMSGPO1 is eight ASCII magic bytes, a little-endian uint32 file count, followed
by a little-endian uint32 byte length and exact bytes for each file. File order
and relative paths come exclusively from the generated, compiled descriptors.
Artifacts carry no paths, commands, compression, URL or executable payloads.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import uuid
import zipfile

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException


ROOT = Path(__file__).resolve().parents[1]
_source_spec = importlib.util.spec_from_file_location("ipms_sct_importer", ROOT / "scripts/import-security-baselines.py")
SOURCE = importlib.util.module_from_spec(_source_spec)
_source_spec.loader.exec_module(SOURCE)

SCHEMA_VERSION = 1
MAGIC = b"IPMSGPO1"
MAX_FILES = 16
MAX_DIRECTORIES = 32
MAX_FILE_BYTES = 512 * 1024
MAX_ARTIFACT_BYTES = 1024 * 1024
MAX_XML_NODES = 20000
MAX_XML_DEPTH = 32
BACKUP_NAMESPACE = "http://www.microsoft.com/GroupPolicy/GPOOperations"
MANIFEST_NAMESPACE = BACKUP_NAMESPACE + "/Manifest"
REPORT_NAMESPACE = "http://www.microsoft.com/GroupPolicy/Settings"
TYPES_NAMESPACE = "http://www.microsoft.com/GroupPolicy/Types"
NS = "{" + BACKUP_NAMESPACE + "}"
META_FILES = frozenset(("Backup.xml", "bkupInfo.xml", "gpreport.xml"))
PAYLOAD_FILES = frozenset((
    "DomainSysvol/GPO/Machine/registry.pol",
    "DomainSysvol/GPO/Machine/comment.cmtx",
    "DomainSysvol/GPO/User/registry.pol",
    "DomainSysvol/GPO/User/comment.cmtx",
    "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
    "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
))
ALLOWED_FILES = META_FILES | PAYLOAD_FILES
# These empty directories occur in Microsoft's backup metadata. Files inside
# them are not allowed, and no directory is taken from a received artifact.
ALLOWED_METADATA_DIRS = frozenset((
    "DomainSysvol/GPO/Machine/Applications",
    "DomainSysvol/GPO/Machine/Preferences",
    "DomainSysvol/GPO/Machine/Preferences/Registry",
    "DomainSysvol/GPO/Machine/Scripts",
    "DomainSysvol/GPO/Machine/Scripts/Shutdown",
    "DomainSysvol/GPO/Machine/Scripts/Startup",
    "DomainSysvol/GPO/Machine/microsoft",
    "DomainSysvol/GPO/Machine/microsoft/windows nt",
    "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
    "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
))
ALLOWED_DIRECTORIES = ALLOWED_METADATA_DIRS | frozenset(
    "/".join(path.split("/")[:index])
    for path in PAYLOAD_FILES | ALLOWED_METADATA_DIRS
    for index in range(1, len(path.split("/")))
)
EXTENSIONS = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": "Registry",
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Security",
    "{F15C46CD-82A0-4C2D-A210-5D0D3182A418}": "Unknown Extension",
}
EXTENSION_FILES = {
    "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}": frozenset(path for path in PAYLOAD_FILES if path.endswith("/registry.pol")),
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": frozenset(path for path in PAYLOAD_FILES if path.endswith("/GptTmpl.inf")),
    "{F15C46CD-82A0-4C2D-A210-5D0D3182A418}": frozenset(path for path in PAYLOAD_FILES if path.endswith(("/comment.cmtx", "/audit.csv", "/GptTmpl.inf"))),
}
# Reviewed metadata identifiers in the eight pinned SCT archives. A new CSE or
# editor identifier requires content review even if the source pin is updated.
CORE_EXTENSION_GUIDS = frozenset((
    "{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}", "{0F6B957D-509E-11D1-A7CC-0000F87571E3}",
    "{2A8FDC61-2347-4C87-92F6-B05EB91A201A}", "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
    "{62C1845D-C4A6-4ACB-BBB0-C895FD090385}", "{7933F41E-56F8-41D6-A31C-4148A711EE93}",
    "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}", "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
    "{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}", "{D02B1F72-3407-48AE-BA88-E8213C6761F1}",
    "{D02B1F73-3407-48AE-BA88-E8213C6761F1}", "{D76B9641-3288-4F75-942D-087DE603E3EA}",
    "{F312195E-3D9D-447A-A3F5-08DFFA24735E}", "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}",
))
GUID_PATTERN = r"\{[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\}"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_guid(value):
    if not isinstance(value, str) or not re.fullmatch(GUID_PATTERN, value):
        raise ValueError("Invalid GPO metadata GUID")
    parsed = uuid.UUID(value)
    if parsed.int == 0:
        raise ValueError("Empty GPO metadata GUID")
    return "{" + str(parsed).upper() + "}"


def safe_archive(data):
    """Validate archive names before using any original backup data."""
    archive = SOURCE.safe_archive(data)
    try:
        for member in archive.infolist():
            name = member.filename.rstrip("/")
            parts = name.split("/")
            unix_type = stat.S_IFMT(member.external_attr >> 16)
            if (member.orig_filename != member.filename or not name or "//" in member.filename
                    or any(ord(character) < 32 or ord(character) == 127 for character in name)
                    or any(part in ("", ".", "..") or part.endswith((".", " "))
                           or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)
                           for part in parts)
                    or unix_type not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise ValueError("Unsafe Windows archive path, member type, or compression")
        return archive
    except Exception:
        archive.close()
        raise


def xml_root(data):
    if not data or len(data) > MAX_FILE_BYTES:
        raise ValueError("GPO metadata exceeds file size bounds")
    try:
        root = ET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (ET.ParseError, DefusedXmlException, UnicodeError) as error:
        raise ValueError("Unsafe or malformed GPO XML metadata") from error
    pending = [(root, 1)]
    nodes = 0
    while pending:
        node, depth = pending.pop()
        nodes += 1
        if depth > MAX_XML_DEPTH or nodes > MAX_XML_NODES:
            raise ValueError("GPO XML metadata exceeds structural bounds")
        pending.extend((child, depth + 1) for child in node)
    return root


def single(parent, tag):
    children = [child for child in parent if child.tag == tag]
    if len(children) != 1:
        raise ValueError("Missing or duplicate GPO metadata field")
    return children[0]


def field(parent, tag):
    node = single(parent, tag)
    if len(node):
        raise ValueError("Unexpected nested GPO metadata field")
    return node.text or ""


def purpose_alias(name):
    alias = re.sub(r"[^A-Za-z0-9]", "", name)
    if not alias or not alias[0].isalpha():
        alias = "Baseline" + alias
    if len(alias) > 80:
        alias = alias[:67] + digest(name.encode("utf-8"))[:13]
    return alias


def _validate_core_extensions(text):
    text = text.strip()
    if text and not re.fullmatch(r"(?:\[(?:" + GUID_PATTERN + r")+\])+", text):
        raise ValueError("Invalid GPO extension identifier sequence")
    if any(canonical_guid(value) not in CORE_EXTENSION_GUIDS for value in re.findall(GUID_PATTERN, text)):
        raise ValueError("Unreviewed GPO extension identifier")


def _expected_token_path(location):
    for prefix, token in (("DomainSysvol/GPO/Machine/", "%GPO_MACH_FSPATH%\\"),
                          ("DomainSysvol/GPO/User/", "%GPO_USER_FSPATH%\\")):
        if location.startswith(prefix):
            return token + location[len(prefix):].replace("/", "\\")
    raise ValueError("GPO metadata reference has an unsupported destination")


def _validate_backup_metadata(root, manifest, component, files, archive_names, prefix):
    if (root.tag != NS + "GroupPolicyBackupScheme"
            or root.attrib != {NS + "version": "2.0", NS + "type": "GroupPolicyBackupTemplate"}
            or len(root) != 1):
        raise ValueError("Unsupported GPO backup metadata schema")
    gpo = single(root, NS + "GroupPolicyObject")
    allowed_children = {NS + name for name in ("SecurityGroups", "FilePaths", "GroupPolicyCoreSettings", "GroupPolicyExtension")}
    if any(child.tag not in allowed_children for child in gpo):
        raise ValueError("Unrecognized GPO backup metadata section")
    paths = single(gpo, NS + "FilePaths")
    if len(paths) or (paths.text or "").strip():
        raise ValueError("Domain-specific GPO path mappings require a separate reviewed migration")
    groups = single(gpo, NS + "SecurityGroups")
    for group in groups:
        if group.tag != NS + "Group" or set(group.attrib) - {NS + "Source"}:
            raise ValueError("Unexpected security principal metadata")
        source = group.attrib.get(NS + "Source", "")
        if source not in ("", "FromDACL"):
            raise ValueError("Unexpected security principal source")
        if source != "FromDACL":
            sid = field(group, NS + "Sid")
            domain = field(group, NS + "DnsDomainName")
            if sid.startswith("S-1-5-21-") or domain:
                raise ValueError("Domain-specific security principals require reviewed migration")
    core = single(gpo, NS + "GroupPolicyCoreSettings")
    expected_core = {NS + name for name in ("ID", "Domain", "SecurityDescriptor", "DisplayName", "Options",
                                          "UserVersionNumber", "MachineVersionNumber", "MachineExtensionGuids",
                                          "UserExtensionGuids", "WMIFilter")}
    if {child.tag for child in core} != expected_core or len(core) != len(expected_core):
        raise ValueError("Unrecognized GPO core setting")
    if (canonical_guid(field(core, NS + "ID")) != manifest["source_gpo_id"]
            or field(core, NS + "DisplayName") != component["name"]
            or field(core, NS + "Domain").casefold() != manifest["domain"].casefold()):
        raise ValueError("GPO backup identities do not agree")
    options_text = field(core, NS + "Options")
    if options_text not in ("1", "2"):
        raise ValueError("Unsupported source GPO configuration options")
    options = int(options_text)
    for name in ("UserVersionNumber", "MachineVersionNumber"):
        text = field(core, NS + name)
        if not re.fullmatch(r"[0-9]{1,10}", text) or int(text) > 0xffffffff:
            raise ValueError("Invalid GPO source version")
    for name in ("MachineExtensionGuids", "UserExtensionGuids"):
        _validate_core_extensions(field(core, NS + name))
    if field(core, NS + "WMIFilter"):
        raise ValueError("A WMI filter requires an independently reviewed binding")
    scopes = {record["scope"] for record in component["records"]}
    if len(scopes) != 1 or not scopes <= {"machine", "user", "domain"}:
        raise ValueError("Ambiguous GPO configuration scope")
    scope = next(iter(scopes))
    if options != (2 if scope == "user" else 1):
        raise ValueError("Source GPO configuration options do not match its scope")
    referenced_files = set()
    seen_extensions = set()
    source_root = "\\\\" + manifest["controller"] + "\\sysvol\\" + manifest["domain"] + "\\Policies\\" + manifest["source_gpo_id"]
    for extension in gpo:
        if extension.tag != NS + "GroupPolicyExtension":
            continue
        extension_id = canonical_guid(extension.attrib.get(NS + "ID", ""))
        if (set(extension.attrib) != {NS + "ID", NS + "DescName"}
                or EXTENSIONS.get(extension_id) != extension.attrib[NS + "DescName"]
                or extension_id in seen_extensions):
            raise ValueError("Unreviewed or duplicated GPO backup extension")
        seen_extensions.add(extension_id)
        for node in extension:
            if node.tag not in (NS + "FSObjectFile", NS + "FSObjectDir") or len(node):
                raise ValueError("Unrecognized GPO filesystem operation")
            attributes = node.attrib
            if (set(attributes) - {NS + name for name in ("Path", "SourceExpandedPath", "Location", "ReEvaluateFunction")}
                    or not {NS + "Path", NS + "SourceExpandedPath"} <= set(attributes)):
                raise ValueError("Unexpected GPO filesystem metadata attributes")
            path = attributes[NS + "Path"]
            location = attributes.get(NS + "Location", "").replace("\\", "/")
            reevaluate = attributes.get(NS + "ReEvaluateFunction")
            if not location:
                if (node.tag != NS + "FSObjectFile" or path != "%GPO_FSPATH%\\Adm\\*.*"
                        or reevaluate is not None or extension_id != "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"):
                    raise ValueError("GPO metadata references an absent or external file")
                expected_source = source_root + "\\Adm\\*.*"
            else:
                if path != _expected_token_path(location):
                    raise ValueError("GPO metadata path differs from its local backup location")
                expected_source = source_root + "\\" + location.removeprefix("DomainSysvol/GPO/").replace("/", "\\")
                if node.tag == NS + "FSObjectFile":
                    if (location not in EXTENSION_FILES[extension_id] or location not in files
                            or location in referenced_files):
                        raise ValueError("GPO metadata references an absent or unsupported payload file")
                    if reevaluate is not None and not (reevaluate == "SecurityValidateSettings"
                            and location.endswith("/SecEdit/GptTmpl.inf")
                            and extension_id == "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"):
                        raise ValueError("Unreviewed GPO reevaluation function")
                    referenced_files.add(location)
                elif (extension_id != "{F15C46CD-82A0-4C2D-A210-5D0D3182A418}"
                        or location not in ALLOWED_METADATA_DIRS or reevaluate is not None
                        or prefix + location not in archive_names):
                    raise ValueError("GPO metadata references an absent or unsupported directory")
            if attributes[NS + "SourceExpandedPath"].casefold() != expected_source.casefold():
                raise ValueError("GPO metadata source path does not match its backup identity")
    if referenced_files != set(files) - META_FILES:
        raise ValueError("GPO backup metadata does not account for every payload file")
    return scope, options


def inspect_component(archive, component):
    """Inspect one exact original backup; the caller must first verify its ZIP pin."""
    backup_id = canonical_guid(component["id"])
    names = archive.namelist()
    candidates = [name for name in names if name.endswith("/bkupInfo.xml") and name.split("/")[-2] == backup_id]
    if len(candidates) != 1:
        raise ValueError("Missing or ambiguous backup component directory")
    prefix = candidates[0].rsplit("/", 1)[0] + "/"
    members = [member for member in archive.infolist() if member.filename.startswith(prefix) and not member.is_dir()]
    if not members or len(members) > MAX_FILES:
        raise ValueError("GPO backup file count exceeds bounds")
    files = {}
    for member in members:
        relative = member.filename[len(prefix):]
        if relative not in ALLOWED_FILES or not 0 < member.file_size <= MAX_FILE_BYTES:
            raise ValueError("Unsupported GPO backup file or file size")
        files[relative] = archive.read(member)
    directories = {name[len(prefix):].rstrip("/") for name in names
                   if name.startswith(prefix) and name.endswith("/") and name != prefix}
    directories.update("/".join(path.split("/")[:index]) for path in files
                       for index in range(1, len(path.split("/"))))
    if not directories <= ALLOWED_DIRECTORIES or len(directories) > MAX_DIRECTORIES:
        raise ValueError("Unsupported GPO backup directory")
    if not META_FILES <= set(files):
        raise ValueError("GPO backup is missing required metadata")
    info = xml_root(files["bkupInfo.xml"])
    if info.tag != "{" + MANIFEST_NAMESPACE + "}BackupInst":
        raise ValueError("Unsupported backup identity schema")
    mi = "{" + MANIFEST_NAMESPACE + "}"
    source_id = canonical_guid(field(info, mi + "GPOGuid"))
    if canonical_guid(field(info, mi + "ID")) != backup_id or field(info, mi + "GPODisplayName") != component["name"]:
        raise ValueError("Backup metadata identity differs from selected component")
    canonical_guid(field(info, mi + "GPODomainGuid"))
    manifest = {"source_gpo_id": source_id, "domain": field(info, mi + "GPODomain"),
                "controller": field(info, mi + "GPODomainController")}
    for value in (manifest["domain"], manifest["controller"]):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
            raise ValueError("Invalid source domain metadata")
    archive_names = {name.rstrip("/") for name in names}
    scope, options = _validate_backup_metadata(xml_root(files["Backup.xml"]), manifest, component,
                                               files, archive_names, prefix)
    report = xml_root(files["gpreport.xml"])
    rn, tn = "{" + REPORT_NAMESPACE + "}", "{" + TYPES_NAMESPACE + "}"
    if report.tag != rn + "GPO":
        raise ValueError("Unsupported GPO report schema")
    identity = single(report, rn + "Identifier")
    if (canonical_guid(field(identity, tn + "Identifier")) != source_id
            or field(identity, tn + "Domain").casefold() != manifest["domain"].casefold()
            or field(report, rn + "Name") != component["name"]):
        raise ValueError("GPO report identity differs from its backup")
    for side, enabled in (("User", options == 2), ("Computer", options == 1)):
        if field(single(report, rn + side), rn + "Enabled") != str(enabled).lower():
            raise ValueError("GPO report configuration options differ from its backup")
    return {"backup_id": backup_id, "source_gpo_id": source_id, "name": component["name"],
            "source_display_name": component["name"], "scope": scope, "source_options": options,
            "purpose": purpose_alias(component["name"]), "source_backup_path": prefix.rstrip("/"),
            "directories": sorted(directories)}, files


def encode_artifact(files):
    if not 0 < len(files) <= MAX_FILES or any(not 0 < len(data) <= MAX_FILE_BYTES for data in files.values()):
        raise ValueError("GPO artifact file count or size exceeds bounds")
    total = 12 + sum(4 + len(data) for data in files.values())
    if total > MAX_ARTIFACT_BYTES:
        raise ValueError("GPO artifact exceeds size limit")
    return MAGIC + struct.pack("<I", len(files)) + b"".join(struct.pack("<I", len(files[name])) + files[name] for name in sorted(files))


def build_catalog(package_directory):
    """Return deterministic metadata and hash-addressed, original-byte artifacts."""
    catalog = {"schema_version": SCHEMA_VERSION, "format": "IPMSGPO1", "components": [], "profiles": []}
    artifacts = {}
    for package in SOURCE.PACKAGES:
        path = package_directory / (package["baseline_id"] + ".zip")
        if path.is_symlink() or path.stat().st_size > SOURCE.MAX_ZIP_BYTES:
            raise ValueError("Unsafe or oversized SCT source archive")
        with path.open("rb") as source:
            data = source.read(SOURCE.MAX_ZIP_BYTES + 1)
        if digest(data) != package["sha256"]:
            raise ValueError("SCT source archive checksum mismatch: " + package["baseline_id"])
        with safe_archive(data) as archive:
            components = SOURCE.read_components(archive)
            selected = set()
            for profile, expected_count in package["raw_counts"].items():
                identifiers, _ = SOURCE.profile_selection(archive, components, package["baseline_id"], profile)
                if sum(len(components[identifier]["records"]) for identifier in identifiers) != expected_count:
                    raise ValueError("SCT selected profile control census changed")
                catalog["profiles"].append({"baseline_id": package["baseline_id"], "profile": profile,
                                            "backup_ids": identifiers})
                selected.update(identifiers)
            purposes = set()
            for identifier in sorted(selected):
                descriptor, files = inspect_component(archive, components[identifier])
                if descriptor["purpose"] in purposes:
                    raise ValueError("GPO purpose aliases collide within a baseline")
                purposes.add(descriptor["purpose"])
                artifact = encode_artifact(files)
                sha256 = digest(artifact)
                descriptor.update(
                    baseline_id=package["baseline_id"], source_package_name=package["filename"],
                    source_package_url=SOURCE.package_url(package), source_package_sha256=package["sha256"],
                    artifact_sha256=sha256, artifact_size=len(artifact), artifact_filename=sha256 + ".ipmsgpo",
                    files=[{"path": path, "bytes": len(files[path]), "sha256": digest(files[path])} for path in sorted(files)],
                )
                catalog["components"].append(descriptor)
                if sha256 in artifacts and artifacts[sha256] != artifact:
                    raise ValueError("GPO artifact content hash collision")
                artifacts[sha256] = artifact
    catalog["components"].sort(key=lambda value: (value["baseline_id"], value["backup_id"]))
    catalog["profiles"].sort(key=lambda value: (value["baseline_id"], value["profile"]))
    return catalog, artifacts


def prepare_artifacts(directory, artifacts):
    """Create immutable cache files; never replace a different existing object."""
    directory = Path(directory)
    if directory.is_symlink():
        raise ValueError("GPO artifact cache cannot be a symbolic link")
    directory.mkdir(parents=True, exist_ok=True)
    directory = directory.resolve(strict=True)
    for sha256, data in sorted(artifacts.items()):
        if (not re.fullmatch(r"[0-9a-f]{64}", sha256) or digest(data) != sha256
                or not 12 <= len(data) <= MAX_ARTIFACT_BYTES or not data.startswith(MAGIC)):
            raise ValueError("Invalid GPO artifact cache input")
        destination = directory / (sha256 + ".ipmsgpo")
        def verify_existing():
            if destination.is_symlink() or not destination.is_file() or destination.stat().st_size != len(data):
                raise ValueError("Existing GPO artifact cache entry differs")
            with destination.open("rb") as source:
                existing = source.read(MAX_ARTIFACT_BYTES + 1)
            if existing != data:
                raise ValueError("Existing GPO artifact cache entry differs")
        if destination.exists() or destination.is_symlink():
            verify_existing()
            continue
        descriptor, temporary = tempfile.mkstemp(prefix=".ipms-gpo-", dir=directory)
        temporary = Path(temporary)
        try:
            with os.fdopen(descriptor, "wb") as target:
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            # A hard link publishes the complete file atomically without ever
            # replacing an existing hash-addressed cache entry.
            try:
                os.link(temporary, destination)
            except FileExistsError:
                verify_existing()
            verify_existing()
        finally:
            temporary.unlink(missing_ok=True)


def render_python(catalog):
    payload = json.dumps(catalog, ensure_ascii=False, sort_keys=True, indent=2)
    sha256 = digest(canonical_json(catalog))
    return (
        "# File Name: gpo_content.py\n"
        "# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14\n"
        "# Author: Alice Endelgard | Organization: Alvestrasza Corporation\n"
        "# Description: Generated Microsoft GPO backup trust metadata; no vendor payload bytes.\n"
        "# Regenerate using scripts/import-security-gpo-packages.py. Do not edit.\n"
        "import hashlib\nimport json\n\n"
        f"CATALOG_SHA256 = {sha256!r}\nMANIFEST_SCHEMA_VERSION = 1\n"
        "ARTIFACT_FORMAT = 'IPMSGPO1'\nMAX_ARTIFACT_BYTES = 1048576\n\n"
        "_CATALOG = json.loads(r'''\n" + payload + "\n''')\n"
        "if hashlib.sha256(json.dumps(_CATALOG, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest() != CATALOG_SHA256:\n"
        "    raise RuntimeError('GPO backup catalog integrity check failed')\n"
        "COMPONENTS = {(item['baseline_id'], item['backup_id']): item for item in _CATALOG['components']}\n"
        "PROFILE_COMPONENTS = {(item['baseline_id'], item['profile']): tuple(item['backup_ids']) for item in _CATALOG['profiles']}\n"
    ).encode("utf-8")


def render_header(catalog):
    quote = lambda value: json.dumps(value, ensure_ascii=True)
    lines = [
        "// File Name: security_gpo_content.hpp",
        "// Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14",
        "// Author: Alice Endelgard | Organization: Alvestrasza Corporation",
        "// Description: Generated GPO backup identities and file hashes; no vendor payload bytes.",
        "// Regenerate with scripts/import-security-gpo-packages.py. Do not edit.",
        "#pragma once", "", "#include <array>", "#include <cstdint>", "#include <span>", "#include <string_view>", "",
        "namespace ipms::agent::gpo {", "",
        "struct file_descriptor { std::string_view relative_path; std::uint32_t bytes; std::string_view sha256; };",
        "struct component_descriptor {",
        "  std::string_view baseline_id, backup_id, source_gpo_id, source_display_name, scope, purpose;",
        "  std::string_view source_package_sha256, artifact_sha256;",
        "  std::uint32_t artifact_size, source_options;",
        "  std::span<const file_descriptor> files;",
        "  std::span<const std::string_view> directories;", "};", "",
        f"inline constexpr std::string_view catalog_sha256 = {quote(digest(canonical_json(catalog)))};", "",
    ]
    for index, component in enumerate(catalog["components"]):
        lines.append(f"inline constexpr std::array<file_descriptor, {len(component['files'])}> component_files_{index}{{{{")
        for file in component["files"]:
            lines.append(f"  {{{quote(file['path'])}, {file['bytes']}U, {quote(file['sha256'])}}},")
        lines.append("}};")
        lines.append(f"inline constexpr std::array<std::string_view, {len(component['directories'])}> component_directories_{index}{{{{")
        lines.extend("  " + quote(directory) + "," for directory in component["directories"])
        lines.append("}};")
    lines.append(f"\ninline constexpr std::array<component_descriptor, {len(catalog['components'])}> components{{{{")
    for index, component in enumerate(catalog["components"]):
        names = ("baseline_id", "backup_id", "source_gpo_id", "source_display_name", "scope", "purpose",
                 "source_package_sha256", "artifact_sha256")
        values = [quote(component[name]) for name in names]
        values.extend((str(component["artifact_size"]) + "U", str(component["source_options"]) + "U",
                       f"component_files_{index}", f"component_directories_{index}"))
        lines.append("  {" + ", ".join(values) + "},")
    lines.extend(("}};", "", "inline constexpr const component_descriptor* lookup_component(",
                  "    std::string_view baseline_id, std::string_view backup_id) noexcept {",
                  "  for (const auto& component : components)",
                  "    if (component.baseline_id == baseline_id && component.backup_id == backup_id) return &component;",
                  "  return nullptr;", "}", "", "}  // namespace ipms::agent::gpo", ""))
    return "\n".join(lines).encode("utf-8")


def generated_files(catalog):
    return {
        Path("services/control-plane/src/ipms/apps/security/gpo_content.py"): render_python(catalog),
        Path("agent/include/ipms/agent/security_gpo_content.hpp"): render_header(catalog),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-dir", type=Path, default=ROOT / "build/security-content")
    parser.add_argument("--output-root", type=Path, default=ROOT)
    parser.add_argument("--check", action="store_true", help="Compare generated descriptors without changing any files")
    parser.add_argument("--prepare-artifacts", action="store_true", help="Populate the private, hash-addressed artifact cache")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "build/security-gpo-packages")
    args = parser.parse_args(argv)
    if args.check and args.prepare_artifacts:
        parser.error("--check cannot be combined with --prepare-artifacts")
    catalog, artifacts = build_catalog(args.package_dir)
    mismatches = []
    for relative, data in generated_files(catalog).items():
        path = args.output_root / relative
        if args.check:
            if not path.is_file() or path.read_bytes() != data:
                mismatches.append(str(relative))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    if args.prepare_artifacts:
        prepare_artifacts(args.artifact_dir, artifacts)
    print(json.dumps({"catalog_sha256": digest(canonical_json(catalog)), "components": len(catalog["components"]),
                      "profiles": len(catalog["profiles"]), "artifacts_prepared": len(artifacts) if args.prepare_artifacts else 0,
                      "mismatches": mismatches}, separators=(",", ":")))
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
