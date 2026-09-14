<!--
File Name: DOMAIN-SETTINGS-0249-VERIFICATION.md
Version: v0.1.1 | Created: 2026-09-14 | Last Modified: 2026-09-14
Author: Alice Endelgard | Organization: Alvestrasza Corporation
Description: Verify root OU name normalization and actionable domain-settings errors.
-->
# Domain settings correction, Portal 0.2.49

The 0.2.48 domain form accepted only complete OU distinguished names. An
administrator entering `_T0`, `_T1` and `_T2` received the same generic error as
an invalid domain or naming template, without knowing which field to correct.

Portal 0.2.49 accepts a simple OU name as an immediate child of the selected
domain. For `example.invalid`, `_T0` is stored as
`OU=_T0,DC=example,DC=invalid`. Simple names are limited to 64 characters, start
with a letter, digit or underscore, and contain only letters, digits, spaces,
underscores, dots or hyphens. Nested OUs and names requiring DN escaping still
use complete distinguished names, for example
`OU=Servers,OU=_T1,DC=example,DC=invalid`.

Normalization precedes the existing domain-containment and cross-tier overlap
checks. GET responses contain the complete saved DNs. The UI now translates
allowlisted validation codes identifying the domain, individual tier, overlap,
naming template or baseline order. It never displays arbitrary server error
text. Invalid submissions retain the draft for correction.

## Verification before deployment

- Three new API regressions failed against the previous implementation for the
  expected reasons: short names returned HTTP 400 and errors lost field context.
- The corrected domain and GPO-job suites passed all 37 tests. The seven core
  tests also passed; migration drift was absent. These local checks used Python
  3.12 and an isolated SQLite database; they do not establish live PostgreSQL
  acceptance.
- Next.js production build, TypeScript and four-file Biome check passed.
- All 16 integrated Security browser tests passed against a disposable local
  database and the real application API. The new German regression rejects an
  OU in another domain, identifies an invalid naming template, saves all three
  short tier names, reloads their complete DNs and observes no GPO-import POST.
  Existing naming/order persistence, conflicts, tenant permissions and mobile
  accessibility checks also passed.

Private evidence: `build/domain-save-0249-regression-before.log`,
`build/domain-save-0249-backend.log`, `build/domain-save-0249-web-build.log`,
`build/domain-save-0249-browser.log`, and
`build/security-baseline-e2e/2026-09-14T20-46-18-781Z/`.

## Deployment and acceptance boundary

The authorized DEV rollout completed on **2026-09-14 at 20:56 UTC**, using
immutable source `7b86cd05bb37d2c49b5268d71c9b115aed0efdf0`. On the appliance,
all 44 focused tests also passed under Python 3.14 and the actual Control Plane
OS account with a disposable in-memory SQLite database and no production
configuration. The production build and minimal Agent Gateway registry checks
passed. The code switch preserved all existing rows, schema, privileges,
configuration, Agent artifacts and the 64 GPO content files. A verified backup
and the previous release remain available for code-only recovery.

The administrator's existing draft was then saved through the authenticated
German portal. The success receipt showed revision 1; reloading under 0.2.49
retained all three complete OU DNs. At **20:58:38 UTC**, an independent read-only
PostgreSQL receipt confirmed one matching saved plan, zero GPO import jobs and
51 retained baseline assessments. All seven checked services were active, and
the existing Linux Agent process was unchanged. This establishes actual live
saving acceptance in addition to the isolated regression tests.

Additional private evidence: `build/domain-save-0249-preflight.log`,
`build/domain-save-0249-stage.log`, `build/domain-save-0249-activate.log`, and
`build/domain-save-0249-live-receipt.json.txt`. No source push, tag or GitHub
release was performed as part of this correction.

This patch has no schema migration or Agent update. Saving records an
unverified domain plan and neither creates OUs nor imports, links or applies
GPOs. Windows Agent 0.2.32 and the separately approved pilot-import workflow
remain unchanged.
