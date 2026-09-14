# File Name: catalog.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Source-verified Microsoft GPO package metadata; no executable policy payloads.
from dataclasses import dataclass
import re

CATALOG_REVISION = "2026-09-14"
SOURCE_URL = "https://www.microsoft.com/en-us/download/details.aspx?id=55319"


@dataclass(frozen=True)
class Baseline:
    id: str
    name: str
    target: str
    release: str
    revision: str
    build: str
    product: str
    package_name: str
    profiles: tuple[str, ...]

    def matches(self, system):
        # An OS build alone is ambiguous (notably Windows 11 and Server 2025).
        role = system.operating_system_role
        if role not in self.profiles:
            return False
        if self.target == "client":
            product = system.operating_system.casefold()
            # GPO baselines do not apply to Home. An unidentified edition must
            # remain unmatched rather than inherit an Enterprise/Pro claim.
            if re.search(r"\bhome\b", product) or not re.search(r"\b(?:enterprise|education|professional|pro|se)\b", product):
                return False
        if re.fullmatch(r"\d+(?:\.\d+)?", system.os_build) is None:
            return False
        return (
            system.os_build.split(".")[0] == self.build
            and self.product in system.operating_system.casefold()
        )

    def projection(self):
        return {
            "id": self.id, "name": self.name, "provider": "microsoft",
            "platform": "windows", "target": self.target, "release": self.release,
            "revision": self.revision, "profiles": list(self.profiles),
            "source_url": SOURCE_URL, "package_name": self.package_name,
            "verified_at": CATALOG_REVISION, "assessment_state": "native-read-only",
        }


def server(release, build, package=None, revision=""):
    return Baseline(
        id=f"microsoft-windows-server-{release}", name=f"Microsoft Windows Server {release}",
        target="server", release=release, revision=revision, build=build,
        product=f"windows server {release}",
        package_name=package or f"Windows Server {release} Security Baseline.zip",
        profiles=("server", "domain-controller"),
    )


def client(version, release, build):
    return Baseline(
        id=f"microsoft-windows-{version}-{release.lower()}",
        name=f"Microsoft Windows {version} {release}", target="client",
        release=release, revision="", build=build, product=f"windows {version}",
        package_name=f"Windows {version} {'v' if version == '11' else 'version '}{release} Security Baseline.zip",
        profiles=("client",),
    )


BASELINES = (
    server("2025", "26100", "Windows Server 2025 Security Baseline - 2602.zip", "2602"),
    server("2022", "20348"),
    server("2019", "17763", "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip"),
    server("2016", "14393", "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip"),
    client("11", "25H2", "26200"),
    client("11", "24H2", "26100"),
    client("11", "23H2", "22631"),
    client("10", "22H2", "19045"),
)
BY_ID = {baseline.id: baseline for baseline in BASELINES}
