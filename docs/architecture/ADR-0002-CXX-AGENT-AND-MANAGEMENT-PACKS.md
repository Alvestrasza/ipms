# ADR-0002: Native C++ Agent and Management Pack Trust Model

## Status

Accepted.

## Decision

The IPMS Agent is implemented in C++20. It has one portable core and small Windows and Linux platform hosts. On Windows, the installed `IPMS Agent` service runs as LocalSystem. On Linux, its equivalent runs under a dedicated systemd service identity unless a documented capability requires another privilege boundary.

The agent uses outbound mTLS to the Control Plane. It is not remotely reachable by default and does not provide a remote shell, PowerShell bridge, SSH service, script runner, or general command-execution interface.

Management Packs are signed, versioned policy declarations. A pack may only activate capabilities compiled into the agent release. Packs cannot carry native code, scripts, arbitrary command lines, certificates, or credentials. The Control Plane validates tenant, device identity, license, pack signature, version compatibility, dependencies, and capability allowlists before an assignment is offered. The agent repeats signature, identity, compatibility, and dependency validation before activation.

## Initial packs

`windows-server-core` is read-only and collects bounded operating-system, hardware, storage, network, service, patch, and health inventory. The initial implementation begins with OS, processor, and memory inventory.

`hyper-v-host` depends on `windows-server-core` and is read-only. It will collect Hyper-V host, switch, VM, cluster, and storage inventory only after its provider contract and fixture acceptance are added.

## Consequences

- C++ provides native Windows and Linux binaries without a managed runtime.
- LocalSystem remains a local API privilege only; server policy cannot expand it into arbitrary remote execution.
- Agent binary updates require a separately signed, versioned installer and rollback path. A pack assignment cannot add new executable functionality.
- v0.1.0 remains read-only. State-changing packs require a separate ADR, authorization model, audit events, acceptance tests, and license policy.
