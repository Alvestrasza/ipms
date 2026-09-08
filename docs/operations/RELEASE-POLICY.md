# Release publication policy

Owner instruction, 2026-09-08: publish new IPMS releases immediately after their
required verification, without asking for publication approval on every version.

- Increment the application and affected Agent versions, record test evidence,
  publish the exact source commit, and create immutable GitHub release tags.
- Attach verified, credential-free Agent packages and SHA-256 checksums. Clearly
  label development/pre-release maturity and unverified real-host acceptance.
- Never overwrite an existing immutable tag or artifact to hide a correction.
- Publication does not imply fleet-wide rollout or authorize changes to customer
  or production systems. Preserve explicit target, environment and canary gates.
- DEV activation remains a separate recorded phase with identity checks,
  quiescence checks, protected recovery material and runtime verification.
- Do not interrupt an occupied console or unresolved management operation to
  satisfy the publication policy. Publish first; report any rollout blocker.
- Keep release notes and issue evidence English and sanitized. Never include
  internal hostnames, addresses, identities, secrets or raw operational logs.
