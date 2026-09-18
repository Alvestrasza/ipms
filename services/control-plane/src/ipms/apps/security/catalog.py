# File Name: catalog.py
# Version: v0.2.0 | Created: 2026-09-14 | Last Modified: 2026-09-18
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Source-verified Windows hardening catalog metadata; no third-party policy payloads.
from dataclasses import dataclass
import re

CATALOG_REVISION = "2026-09-18"
# Native assessment payloads did not change when reference providers were added.
ASSESSMENT_REVISION = "2026-09-14"
MICROSOFT_SOURCE = "https://www.microsoft.com/en-us/download/details.aspx?id=55319"


@dataclass(frozen=True)
class Baseline:
    id: str
    name: str
    target: str
    release: str
    revision: str
    builds: tuple[str, ...]
    product: str
    package_name: str
    profiles: tuple[str, ...]
    provider: str = "microsoft"
    provider_label: str = "Microsoft"
    platform: str = "windows"
    source_url: str = MICROSOFT_SOURCE
    verified_at: str = "2026-09-14"
    assessment_state: str = "native-read-only"
    deployment_state: str = "bundled"
    package_kind: str = "gpo-backup"

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
            system.os_build.split(".")[0] in self.builds
            and self.product in system.operating_system.casefold()
        )

    def projection(self):
        return {
            "id": self.id, "name": self.name, "provider": self.provider,
            "provider_label": self.provider_label, "platform": self.platform,
            "target": self.target, "release": self.release,
            "revision": self.revision, "profiles": list(self.profiles),
            "source_url": self.source_url, "package_name": self.package_name,
            "verified_at": self.verified_at, "assessment_state": self.assessment_state,
            "deployment_state": self.deployment_state, "package_kind": self.package_kind,
        }


def server(release, build, package=None, revision=""):
    return Baseline(
        id=f"microsoft-windows-server-{release}", name=f"Microsoft Windows Server {release}",
        target="server", release=release, revision=revision, builds=(build,),
        product=f"windows server {release}",
        package_name=package or f"Windows Server {release} Security Baseline.zip",
        profiles=("server", "domain-controller"),
    )


def client(version, release, build):
    return Baseline(
        id=f"microsoft-windows-{version}-{release.lower()}",
        name=f"Microsoft Windows {version} {release}", target="client",
        release=release, revision="", builds=(build,), product=f"windows {version}",
        package_name=f"Windows {version} {'v' if version == '11' else 'version '}{release} Security Baseline.zip",
        profiles=("client",),
    )


def reference(*, id, name, provider, provider_label, target, release, revision, builds,
              product, package_name, profiles, source_url, deployment_state, package_kind):
    return Baseline(
        id=id, name=name, provider=provider, provider_label=provider_label,
        target=target, release=release, revision=revision, builds=builds,
        product=product, package_name=package_name, profiles=profiles,
        source_url=source_url, verified_at=CATALOG_REVISION,
        assessment_state="catalog-only", deployment_state=deployment_state,
        package_kind=package_kind,
    )


DEPLOYABLE_BASELINES = (
    server("2025", "26100", "Windows Server 2025 Security Baseline - 2602.zip", "2602"),
    server("2022", "20348"),
    server("2019", "17763", "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip"),
    server("2016", "14393", "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip"),
    client("11", "25H2", "26200"),
    client("11", "24H2", "26100"),
    client("11", "23H2", "22631"),
    client("10", "22H2", "19045"),
)

CIS_SERVER_SOURCE = "https://www.cisecurity.org/benchmark/microsoft_windows_server"
CIS_CLIENT_SOURCE = "https://www.cisecurity.org/benchmark/microsoft_windows_desktop"
DISA_SOURCE = "https://www.cyber.mil/stigs/gpo/"
BSI_SOURCE = "https://www.bsi.bund.de/EN/Service-Navi/Publikationen/Studien/SiSyPHuS_Win10/SiSyPHuS.html"
ACSC_SOURCE = "https://www.cyber.gov.au/sites/default/files/2025-09/Hardening%20Microsoft%20Windows%2011%20workstations%20(September%202025).pdf"
NCSC_SOURCE = "https://github.com/ukncsc/Device-Security-Guidance-Configuration-Packs"

REFERENCE_BASELINES = (
    *(reference(
        id=f"cis-windows-server-{release}", name=f"CIS Microsoft Windows Server {release}",
        provider="cis", provider_label="CIS", target="server", release=release,
        revision=revision, builds=(build,), product=f"windows server {release}",
        package_name=f"CIS Microsoft Windows Server {release} Build Kit",
        profiles=("server", "domain-controller"), source_url=CIS_SERVER_SOURCE,
        deployment_state="licensed-package-required", package_kind="cis-build-kit",
    ) for release, revision, build in (
        ("2025", "2.1.0", "26100"), ("2022", "5.1.0", "20348"),
        ("2019", "5.0.0", "17763"), ("2016", "4.0.0", "14393"),
    )),
    reference(
        id="cis-windows-11-enterprise", name="CIS Microsoft Windows 11 Enterprise",
        provider="cis", provider_label="CIS", target="client", release="Windows 11",
        revision="5.1.0", builds=("22631", "26100", "26200"), product="windows 11",
        package_name="CIS Microsoft Windows 11 Enterprise Build Kit", profiles=("client",),
        source_url=CIS_CLIENT_SOURCE, deployment_state="licensed-package-required",
        package_kind="cis-build-kit",
    ),
    reference(
        id="cis-windows-10-enterprise", name="CIS Microsoft Windows 10 Enterprise",
        provider="cis", provider_label="CIS", target="client", release="Windows 10",
        revision="4.0.0", builds=("19045",), product="windows 10",
        package_name="CIS Microsoft Windows 10 Enterprise Build Kit", profiles=("client",),
        source_url=CIS_CLIENT_SOURCE, deployment_state="licensed-package-required",
        package_kind="cis-build-kit",
    ),
    reference(
        id="disa-stig-windows-server-2025", name="DISA STIG Windows Server 2025",
        provider="disa", provider_label="DISA", target="server", release="2025",
        revision="V1R2", builds=("26100",), product="windows server 2025",
        package_name="DISA Group Policy Objects package", profiles=("server", "domain-controller"),
        source_url=DISA_SOURCE, deployment_state="public-package-required", package_kind="disa-gpo-bundle",
    ),
    reference(
        id="disa-stig-windows-server-2022", name="DISA STIG Windows Server 2022",
        provider="disa", provider_label="DISA", target="server", release="2022",
        revision="V2R9", builds=("20348",), product="windows server 2022",
        package_name="DISA Group Policy Objects package", profiles=("server", "domain-controller"),
        source_url=DISA_SOURCE, deployment_state="public-package-required", package_kind="disa-gpo-bundle",
    ),
    reference(
        id="disa-stig-windows-11", name="DISA STIG Windows 11",
        provider="disa", provider_label="DISA", target="client", release="Windows 11",
        revision="V2R8", builds=("22631", "26100", "26200"), product="windows 11",
        package_name="DISA Group Policy Objects package", profiles=("client",),
        source_url=DISA_SOURCE, deployment_state="public-package-required", package_kind="disa-gpo-bundle",
    ),
    reference(
        id="bsi-sisyphus-windows-10", name="BSI SiSyPHuS Windows 10 Hardening",
        provider="bsi", provider_label="BSI", target="client", release="Windows 10",
        revision="AP11", builds=("19045",), product="windows 10",
        package_name="Windows 10 hardening recommendations and Group Policy table", profiles=("client",),
        source_url=BSI_SOURCE, deployment_state="guidance-only", package_kind="guidance",
    ),
    reference(
        id="acsc-windows-11-workstations", name="ASD/ACSC Windows 11 Workstation Hardening",
        provider="acsc", provider_label="ASD / ACSC", target="client", release="Windows 11 24H2",
        revision="2025-09", builds=("26100",), product="windows 11",
        package_name="Hardening Microsoft Windows 11 workstations", profiles=("client",),
        source_url=ACSC_SOURCE, deployment_state="guidance-only", package_kind="guidance",
    ),
    reference(
        id="ncsc-uk-windows-2025", name="UK NCSC Windows 2025 Configuration Pack",
        provider="ncsc-uk", provider_label="UK NCSC", target="client", release="2025",
        revision="2025", builds=("26100", "26200"), product="windows 11",
        package_name="Device Security Guidance Windows configuration pack", profiles=("client",),
        source_url=NCSC_SOURCE, deployment_state="mdm-only", package_kind="intune-policy",
    ),
)

BASELINES = DEPLOYABLE_BASELINES + REFERENCE_BASELINES
BY_ID = {baseline.id: baseline for baseline in BASELINES}
DEPLOYABLE_BY_ID = {baseline.id: baseline for baseline in DEPLOYABLE_BASELINES}
