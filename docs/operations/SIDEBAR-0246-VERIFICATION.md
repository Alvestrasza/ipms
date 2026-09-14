<!--
File Name: SIDEBAR-0246-VERIFICATION.md
Version: v0.1.0
Created: 2026-09-14
Last Modified: 2026-09-14
Author: Alice Endelgard
Organization: Alvestrasza Corporation
Description: Verified DEV correction for navigation below the viewport.
-->
# Sidebar scrolling in Portal 0.2.46

Portal 0.2.46 was activated on the established DEV appliance on 2026-09-14
at 11:42 UTC from commit `78bd74ff098ad309543912cf2392846bd66d6173`.
The previous 0.2.45 release remains available for code rollback. Source was
committed locally and delivered through a checksum-verified Git bundle;
no GitHub publication occurred.

## Behavior and correction

At a viewport of 1880 by 821 pixels, the expanded Administration navigation
placed the Agents link at vertical coordinates 892 through 928. The fixed
sidebar had 980 pixels of content and no vertical scroll container. A real
wheel operation did not move its content.

The sidebar now scrolls vertically, keeps its children at their natural height,
and uses the same list reset for Administration as for the main navigation.
The existing mobile header behavior is preserved. The other seven changed
application files only update the displayed or reported version to 0.2.46.

## Verification

- Local production build, TypeScript, focused Biome checks and seven existing
  core API tests passed. The core tests used the explicit test settings.
- All nine existing isolated Security browser tests passed in 36.7 seconds,
  including the narrow viewport and baseline administration flows.
- The appliance rebuilt the candidate with its pinned dependencies. Read-only
  PostgreSQL checks confirmed there were no pending migrations. The application
  schema, configuration, unit definitions and Agent package were preserved.
- At the original browser viewport, a wheel operation moved the sidebar from
  scroll position 0 to 159. The Agents link was fully visible at 733 through
  769 pixels, and clicking it opened the Agents administration page.
- Starting again at scroll position 0, tabbing from Administration through its
  links focused Agents and automatically scrolled it into view. Enter opened
  the Agents page. The browser displayed version 0.2.46.
- Application health checks passed after activation. The Linux Agent process
  and binary were preserved. No Agent update or new operation job was created.

Deployment used a shared cutover lock, a short service fence and retained code
rollback material. No migration, database restore or configuration replacement
was performed. The existing HSTS configuration warning remains unchanged.

This correction does not establish updated Windows Agent or real Security scan
acceptance; those boundaries remain as documented in
[the 0.2.45 verification](SECURITY-SCAN-0245-VERIFICATION.md).
