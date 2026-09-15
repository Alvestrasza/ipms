<!--
File Name: BASELINE-APPLICATION-0252-VERIFICATION.md
Version: v0.1.0 | Created: 2026-09-15 | Last Modified: 2026-09-15
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Baseline configuration, native application evidence and release acceptance.
-->
# Baseline application, Portal 0.2.52 and Windows Agent 0.2.33

Domain configuration, GPO naming and baseline composition order are edited
together in Tenant Administration. Security Baseline retains catalog selection
and pilot import. Details appear under the catalog only after selection and
can be collapsed or hidden. The selected deployment domain survives a change
of baseline. Square inventory and application tiles group Windows releases
by provider and system type.

The application percentage counts actual Agent-reported computer GPO
processing against verified component/GPO identities. It is independent of
individual-setting compliance, including overrides by another baseline.
Unknown, stale, partial and unmapped results cannot produce a full confirmation.
See [the evidence contract](../architecture/BASELINE-APPLICATION-EVIDENCE.md)
for identity, timing, replay and denominator rules.

## Local verification

The final scoped backend run passed 145 tests, including 41 receiver and
application cases. They cover input bounds, identity and tenant separation,
stale/partial evidence, verified component associations, family counts and
actual inventory transitions through omitted, conflicting and replayed
reports. Identity cycles and malformed receiver metadata fail closed, with
recovery from a strictly newer observation. No migration changes were found.
The initial full local run exposed two tests whose observation ordering
depended on clock resolution; deterministic observations and independent
freshness fixtures now exercise the intended behavior explicitly.

The production Next build passed. All 29 browser cases passed against the
real Portal and Django API with isolated synthetic data. They exercise the
combined revision-protected domain editor, order and naming drafts, unchanged
import guards, tenant permissions, Logs filtering/export, explicit catalog
selection, keyboard collapse, preserved deployment domain and desktop/mobile
square tile geometry. A synthetic system with failing individual settings
still contributes correctly to an independently confirmed application result:
one of 31 server systems, or 3.2 percent. No synthetic request reaches a live
Agent.

The final browser rerun after the receiver watermark change passed all 29
cases again in 1.7 minutes.

The first browser run found that remounting details reset the selected domain.
The final implementation reopens details after selection while preserving
the deployment component's state; the regression now passes.

Windows native verification used MSVC 19.44 x64 Release. All 18 runnable CTest
cases passed, with two existing privileged-storage cases skipped under the
non-elevated test account. Tests cover exact domain/GPO identity, CSE history
and version agreement, exclusions, incomplete/unstable evidence, processing
timestamps, output bounds, child cleanup and cancellation. The final domain
binding tests ensure that a domain mismatch invalidates only the GPO evidence.
The production executable completed a full local inventory; local RSoP access
was unavailable under that account, so this probe does not prove positive
collection under the Agent service identity.

The unpublished Windows package contains the existing six executable/installer
members. Package SHA-256:
`e9da75165b46eca5a203e39a98f0d4ca57469c54beeee6e671a3b0f035a4da7d`.
Agent executable SHA-256:
`05371a1bd4f4e18e395f00e4b412a9d6ee132cb1795f734b08ddb14b2d991643`.

Private evidence: `build/baseline-0252-web-build-final.log`,
`build/baseline-0252-browser-final.log`,
`build/baseline-0252-browser-watermark.log`,
`build/group-policy-033-build-domain-binding.log`,
`build/group-policy-033-ctest-domain-binding.log`,
`build/group-policy-033-native-verification-domain-binding.json`,
`build/agent-0233-package-receipt.json`.

## Activation boundary

The compatible Portal receiver must be activated before advertising Windows
Agent 0.2.33. Dedicated Python 3.14/PostgreSQL verification, protected staging
and a client update canary are separate acceptance steps. An unknown family
result is expected when no verified GPO/component association exists; existing
GPO names or matching settings must not be treated as such an association.

There are no schema migrations or changes to policy content, the updater,
local pilot approval, GPO import/link execution, credentials or Linux Agent
behavior. This release performs no directory or policy mutation. Real GPO
application and a future unattended approval model remain separate work.
