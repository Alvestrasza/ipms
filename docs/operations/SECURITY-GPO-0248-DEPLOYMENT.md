<!--
File Name: SECURITY-GPO-0248-DEPLOYMENT.md
Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Dated DEV rollout evidence for Portal 0.2.48 and Windows Agent 0.2.32.
-->
# Domain security DEV deployment

Evidence cutoff: **2026-09-14 17:44 UTC**. The user explicitly requested this
DEV software rollout after the [source verification](SECURITY-GPO-0248-VERIFICATION.md).
This record supersedes the earlier candidate-only status for deployment;
it does not constitute actual GPO import or policy activation acceptance.

## Delivered state

- Portal **0.2.48** runs from immutable commit
  `a7436e973f18b0921068ec27f00f42e6abe99648`. The supported appliance build
  completed with unchanged dependency pins, TypeScript and 54 routes.
- Only additive migration `security.0004_domain_gpo_pilots` was applied, using
  the existing application database role. Before/after fingerprints verified
  all existing rows across 53 tables, existing schema and privilege state.
  The three new content types and twelve Django permissions were accounted for.
- All seven checked services are active. The actual gateway service account
  loaded its minimal application registry, rejected an invalid GPO envelope
  and read the new tables. Existing scan evidence remains available:
  51 assessments with 18,736 findings at the cutoff.
- The six-file Windows **0.2.32** package and all **64** immutable Microsoft
  GPO component bundles are available. Both service identities read and
  verified every component. The two environment files retain their original
  inodes, permissions, extended attributes and unrelated bytes.
- A Windows client was updated first and returned a current heartbeat. The
  remaining 25 Windows servers followed through the normal authenticated
  portal lifecycle workflow. All **26 update jobs succeeded** with result
  `updated`; all 26 report version **0.2.32**, with no stale heartbeats or
  active lifecycle jobs at the cutoff. The Linux Agent was preserved.
- Twelve DCs reported `ready_for_approval`. This is executor readiness, not
  successful GPMC mutation or local approval acceptance. No domain plan or
  GPO import job was created by this rollout.
- The authenticated German portal shows **Administration > Security >
  Domains & GPOs**, including separate Tier 0/1/2 OU fields, the configured
  naming-template default and draggable baseline ordering. The live page was
  visually checked and left open. No customer settings were invented or saved.

## Release identity and recovery

Windows package SHA256:
`bbd30cfeb7cd6bb8d8fc5ad893dedc92d12d66aeebb32563460c86920e009954`.

Windows executable SHA256:
`4232cfcc55b22e7cf51f1efec37b4247a5fe902a1f15fc4c504f71f5916e4c07`.

GPO descriptor catalog SHA256:
`dafd8ee9ccfff15d077e9e8186680c2dccc834d71c150a98b5d5cb0c0c471c12`.

The prior release and Windows package were retained. Configuration archives,
a fully decoded PostgreSQL custom dump, row fingerprints and exact release
receipts are retained in protected appliance backup directories. No database
restore or migration reversal was performed.

Two deployment-helper corrections were required. Generated Next files had
group-write permission; only generated, root-owned, single-link files in the
new release had those write bits removed, with byte preservation verified.
The first stop check also expected process-ID properties on systemd timers.
Actual services were stopped, but timers do not expose those properties.
The existing release was safely restarted after verifying the unchanged
configuration, absent migration and absent new tables. The corrected guard
then completed the full backed-up activation. Timers are now checked for
inactive state; service process IDs must still be zero.

An asset helper's final readability probe initially lacked `runuser` in its
restricted PATH. The subsequent package preflight verified actual reads of
all artifacts as both service accounts. An optional receipt query was also
corrected to count findings from their existing JSON field. Neither affected
runtime data. No automatic approval block remains.

## Evidence and remaining acceptance

Private logs are retained under `build/security-gpo-0248-*.log` and
`build/security-gpo-0248-fleet-verification.json.txt`; the release package
verification is under `build/agent-release-0.2.32-20260914T1620/`. Operational
host identities, environment files and raw vendor bundles are not published.
This turn created local source and documentation commits; no push, tag or
GitHub release was made.

The previously reported 522 supported backend tests, 15 browser tests,
Windows/Linux native tests and content verification remain the source
evidence. Deployment adds actual service, migration, UI, package and fleet
acceptance. Actual independently approved GPMC import, elevated protected
storage, unlinked/disabled object verification and ambiguity recovery remain
separate acceptance work. No existing AD object, default policy, firewall
policy or GPO link was modified.
