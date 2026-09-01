# IPMS

Independent Platform Management System by Alvestrasza Corporation.

IPMS is a multi-tenant infrastructure management platform for physical,
virtual, network, storage, monitoring, and backup operations. It is designed
for customer-operated appliances, customer-operated scale-out deployments, and
A-Corp-hosted hybrid deployments.

## Project Status

IPMS application build `0.1.23` is in the v0.1.0 read-only foundation phase. A
standalone development
Appliance currently runs the tenant-aware Django Control Plane, PostgreSQL,
the multilingual Next.js Web Console, and the isolated connector worker.

The implemented physical-infrastructure foundation includes read-only HPE iLO
Redfish discovery, portal-managed BMC enrollment, explicit certificate review,
encrypted write-only credentials, credential rotation, soft removal, safe
communication metadata, filtering, and CSV export. Dell iDRAC and generic
Redfish profiles are selectable but require dedicated hardware compatibility
acceptance before they are described as supported.

The Windows Server portal foundation provides separate tenant-scoped views for
physical and virtual servers. Its normalized read-only API is prepared for the
native IPMS Agent and future Hyper-V discovery without exposing an inventory
write path to browsers.

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
- [Windows Agent 0.1.16 foundation acceptance](docs/operations/WINDOWS-AGENT-0.1.16-ACCEPTANCE.md)
- [Windows Agent 0.1.17 enrollment and inventory](docs/operations/WINDOWS-AGENT-0.1.17-ENROLLMENT.md)
- [Development versioning](docs/operations/VERSIONING.md)

## Architecture Decisions

- [ADR-0001: Appliance encryption, unlock, and recovery policy](docs/architecture/ADR-0001-APPLIANCE-ENCRYPTION-AND-UNLOCK.md)
- [Web Console architecture and security boundary](docs/architecture/WEB-CONSOLE.md)
- [iLO Redfish connector architecture](docs/architecture/ILO-REDFISH-CONNECTOR.md)
- [ADR-0002: Native C++ Agent and Management Pack Trust Model](docs/architecture/ADR-0002-CXX-AGENT-AND-MANAGEMENT-PACKS.md)
- [ADR-0003: Agent PKI and Enrollment Trust Model](docs/architecture/ADR-0003-AGENT-PKI-AND-ENROLLMENT.md)
- [ADR-0004: Local Agent Configuration and Control Panel Integration](docs/architecture/ADR-0004-LOCAL-AGENT-CONFIGURATION.md)
- [Agent contract](docs/architecture/AGENT-CONTRACT.md)

## Source Layout

- [Django Control Plane](services/control-plane/README.md)
- [Next.js Web Console](apps/web-console/README.md)
- [C++20 Agent](agent/README.md)

## License

IPMS is proprietary software. See [LICENSE](LICENSE). Public extension
interfaces, SDKs, and example connectors may be released under separate open
source licenses in dedicated repositories.
