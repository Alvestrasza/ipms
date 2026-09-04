# IPMS

Independent Platform Management System by Alvestrasza Corporation.

IPMS is a multi-tenant infrastructure management platform for physical,
virtual, network, storage, monitoring, and backup operations. It is designed
for customer-operated appliances, customer-operated scale-out deployments, and
A-Corp-hosted hybrid deployments.

## Project Status

IPMS application build `0.2.5` adds controlled Hyper-V workload actions to
the inventory foundation. A
standalone development
Appliance currently runs the tenant-aware Django Control Plane, PostgreSQL,
the multilingual Next.js Web Console, and the isolated connector worker.

The implemented physical-infrastructure foundation includes read-only HPE iLO
API discovery, portal-managed BMC enrollment, explicit certificate review,
encrypted write-only credentials, credential rotation, soft removal, safe
communication metadata, filtering, and CSV export. Dell iDRAC and generic
Redfish profiles are selectable but require dedicated hardware compatibility
acceptance before they are described as supported.

Windows workstations are separated from Windows servers and grouped by product
family, starting with Windows 11 LTSC. Hyper-V hosts report a bounded VM
inventory with state, vCPU, memory, uptime, configuration version, and guest IP
addresses. Tenant administrators can start, pause, resume, gracefully shut
down, and stop a VM through an audited durable job and the enrolled host
Agent. Windows and Linux Agents report hardware, network, installed
software, and operating-system update posture through the outbound mTLS
Gateway. The first Sophos Firewall, Loadbalancer.org ADC, and HPE Comware 7.1
connector foundations provide fixed read-only discovery operations; live
compatibility acceptance remains device- and firmware-specific.

The product roadmap is maintained in [ROADMAP.md](ROADMAP.md).

## Operations Documentation

- [Alice SSH bootstrap](docs/operations/ALICE-SSH-BOOTSTRAP.md)
- [Ubuntu Appliance hardening baseline](docs/operations/UBUNTU-APPLIANCE-HARDENING.md)
- [Ubuntu Appliance hardening automation](docs/operations/UBUNTU-HARDENING-AUTOMATION.md)
- [Standalone development deployment](docs/operations/STANDALONE-DEV-DEPLOYMENT.md)
- [Standalone development acceptance](docs/operations/STANDALONE-DEV-ACCEPTANCE.md)
- [Portal-based BMC connector management](docs/operations/BMC-CONNECTOR-MANAGEMENT.md)
- [Windows Server inventory preparation](docs/operations/WINDOWS-SERVER-INVENTORY.md)
- [Agent PKI and mTLS Gateway operations](docs/operations/AGENT-PKI-AND-GATEWAY.md)
- [Windows Agent installation and local configuration](docs/operations/WINDOWS-AGENT-INSTALLATION.md)
- [Linux Agent installation](docs/operations/LINUX-AGENT-INSTALLATION.md)
- [Network connector management](docs/operations/NETWORK-CONNECTOR-MANAGEMENT.md)
- [Windows Agent 0.1.16 foundation acceptance](docs/operations/WINDOWS-AGENT-0.1.16-ACCEPTANCE.md)
- [Windows Agent 0.1.17 enrollment and inventory](docs/operations/WINDOWS-AGENT-0.1.17-ENROLLMENT.md)
- [Portal Windows Agent deployment](docs/operations/PORTAL-WINDOWS-AGENT-DEPLOYMENT.md)
- [Development versioning](docs/operations/VERSIONING.md)

## Architecture Decisions

- [ADR-0001: Appliance encryption, unlock, and recovery policy](docs/architecture/ADR-0001-APPLIANCE-ENCRYPTION-AND-UNLOCK.md)
- [Web Console architecture and security boundary](docs/architecture/WEB-CONSOLE.md)
- [iLO Redfish connector architecture](docs/architecture/ILO-REDFISH-CONNECTOR.md)
- [ADR-0002: Native C++ Agent and Management Pack Trust Model](docs/architecture/ADR-0002-CXX-AGENT-AND-MANAGEMENT-PACKS.md)
- [ADR-0003: Agent PKI and Enrollment Trust Model](docs/architecture/ADR-0003-AGENT-PKI-AND-ENROLLMENT.md)
- [ADR-0004: Local Agent Configuration and Control Panel Integration](docs/architecture/ADR-0004-LOCAL-AGENT-CONFIGURATION.md)
- [ADR-0005: Portal Windows Agent Deployment](docs/architecture/ADR-0005-PORTAL-WINDOWS-AGENT-DEPLOYMENT.md)
- [Agent contract](docs/architecture/AGENT-CONTRACT.md)
- [Cross-platform software inventory](docs/architecture/CROSS-PLATFORM-SOFTWARE-INVENTORY.md)
- [Network connector security boundary](docs/architecture/NETWORK-CONNECTOR-BOUNDARY.md)

## Source Layout

- [Django Control Plane](services/control-plane/README.md)
- [Next.js Web Console](apps/web-console/README.md)
- [C++20 Agent](agent/README.md)

## License

IPMS is proprietary software. See [LICENSE](LICENSE). Public extension
interfaces, SDKs, and example connectors may be released under separate open
source licenses in dedicated repositories.
