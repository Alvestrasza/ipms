<!--
File Name: SECURITY-GATEWAY-0247-VERIFICATION.md
Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: DEV evidence for restored baseline delivery and the separate client update repair.
-->
# Security Gateway 0.2.47 verification

Portal 0.2.47 was activated on the established DEV appliance on 2026-09-14
at 12:19 UTC from local commit `1ff06b70dbcdced93ef548ffa507513d14b3b7ac`.
All 25 existing Windows Server baseline jobs subsequently completed through
the real Agent transport. This establishes live scan delivery and result
reception beyond the earlier [0.2.45 preparation](SECURITY-SCAN-0245-VERIFICATION.md).
It does not establish complete baseline coverage or policy enforcement.

## Cause and correction

The 25 servers already ran Windows Agent 0.2.31 and were online. Their scan
jobs remained queued with zero attempts because the independent gateway's
minimal Django settings omitted the Security application. The actual gateway
raised a model-registration error when loading the Security receiver.

The correction registers `ipms.apps.security` in the gateway settings. A
separate-process regression initializes the actual service settings and imports
the Security receiver and related models. It reproduced the live failure
before the correction and passes afterward. The remaining application changes
only update the Portal version to 0.2.47.

The gateway's existing database identity already owned the Security tables.
No new account, database grant, migration, native Agent change, or configuration
replacement was required.

## Verification and deployment

- All 53 focused gateway, Security and core tests passed in 5.995 seconds.
- Local and appliance production builds, including TypeScript, passed.
- The checksum-verified immutable source was staged with pinned dependencies.
  Gateway initialization and read-only database access passed under its actual
  service account and protected runtime environment.
- The guarded activation preserved the 25 authorized scan identities and
  targets, checked other operations were quiescent, and retained code rollback
  material. The schema, protected configuration, unit definitions, Agent
  package and Linux Agent process were preserved.
- Health checks passed. The previous Portal 0.2.46 code remains available.
  No database restore or recovery action was necessary.
- At 12:29 UTC, all seven checked services remained active, the Linux Agent
  process and binary still matched the preserved identity, and the gateway
  journal contained no recurrence of the registration error since cutover.
- Source and acceptance records were committed locally. No GitHub push, tag,
  release or external comment was made for this correction.

## Actual server results

The read-only receipt at 12:24 UTC and the authenticated Portal confirmed:

- All 25 original jobs completed between 12:19:49 and 12:20:04 UTC, each on
  its first lease attempt. No duplicate scan requests were created.
- All 25 assessments were stored: 13 member-server profiles and 12 domain
  controller profiles. Each job received its 12-page result set; temporary
  page buffers were cleared after completion.
- Every server had confirmed deviations: 29 to 36 failed controls per system.
  Each also had 281 to 297 unknown controls, so none had complete coverage.
- The Portal showed 25 completed jobs, zero active jobs, individual assessment
  times, and per-control expected/observed values with reasons. A real server's
  findings page was checked through the authenticated browser.
- Compliance was 0% because no server fulfilled the entire baseline. Full
  assessment coverage was also 0%; that metric requires a complete current
  result and must not be interpreted as absence of received scan data.

Missing values and unsupported or out-of-scope checks remain unknown. Known
deviations remain noncompliant even when other controls are unknown. No Windows
setting or GPO was changed by these scans.

## Separate Windows client update issue

The single Windows client remained on Agent 0.2.30. Two actual update jobs had
been delivered and started, then failed before replacing the running binary.
An elevated operator diagnostic confirmed that both staged 0.2.31 candidates
matched the expected checksum. A rollback file left from an older installation
had a different checksum from the current executable. The updater correctly
refused to overwrite that mismatched recovery file.

A reviewed private, exact-host helper preserves that old file by moving it to
an adjacent archive. It validates the current service, process, registry,
candidate, paths and file hashes; rejects updater processes and reparse points;
and verifies the archive's checksum and ACL. It requires an explicit `-Apply`
and an elevated operator. It does not stop the service, replace the executable,
change configuration, or reenroll the Agent.

At this evidence cutoff, the operator's archive action and the subsequent
normal Portal update retry are pending. Client update success must be verified
separately before claiming all Windows Agents are current.
