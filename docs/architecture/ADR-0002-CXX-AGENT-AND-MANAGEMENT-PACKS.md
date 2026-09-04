# ADR-0002: Native C++ Agent and Management Pack Trust Model

## Status

Accepted.

## Decision

The IPMS Agent is implemented in C++20. It has one portable core and small Windows and Linux platform hosts. On Windows, the installed `IPMS Agent` service runs as LocalSystem. On Linux, its equivalent runs under a dedicated systemd service identity unless a documented capability requires another privilege boundary.

The agent initiates one persistent, bidirectional mTLS channel to the IPMS Agent Gateway on TCP 9419. The Control Plane uses that established stream to push signed Pack assignments, bounded inventory requests, certificate-rotation instructions, and signed update manifests. It never opens a connection to an agent. Managed systems therefore expose no inbound Agent Gateway listener and no remote shell, PowerShell bridge, SSH service, script runner, or general command-execution interface.

Management Packs are signed, versioned policy declarations. A pack may only activate capabilities compiled into the agent release. Packs cannot carry native code, scripts, arbitrary command lines, certificates, or credentials. The Control Plane validates tenant, device identity, license, pack signature, version compatibility, dependencies, and capability allowlists before an assignment is offered. The agent repeats signature, identity, compatibility, and dependency validation before activation.

## Initial packs

`windows-server-core` is read-only and collects bounded operating-system, hardware, storage, network, service, patch, and health inventory. The initial implementation begins with OS, processor, and memory inventory.

`hyper-v-host` depends on `windows-server-core`. Its inventory capabilities are
read-only. Version 0.2.7 adds the separately governed, compiled start, graceful
shutdown, stop, pause, and resume actions defined by ADR-0008 without accepting
arbitrary commands or provider expressions.

## Consequences

- C++ provides native Windows and Linux binaries without a managed runtime.
- LocalSystem remains a local API privilege only; server policy cannot expand it into arbitrary remote execution.
- TCP 9419 is the on-premises Agent Gateway firewall contract. A future Cloud profile may explicitly select TCP 443 as an egress fallback without changing this default.
- Agent binary updates require a separately signed, versioned installer and rollback path. A pack assignment cannot add new executable functionality.
- v0.1.0 remains read-only. Every state-changing pack requires a separate ADR,
  authorization model, audit events, acceptance tests, and license policy;
  Hyper-V VM lifecycle is the first such post-v0.1 capability.
