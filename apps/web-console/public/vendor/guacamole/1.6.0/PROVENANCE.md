# Guacamole browser dependency

Only `all.min.js` (78,778 bytes) is extracted from the official Apache Maven
artifact `org.apache.guacamole:guacamole-common-js:1.6.0:zip`. This is not the
unofficial, older npm fork. IPMS remains proprietary; this dependency is Apache
License 2.0, with its original LICENSE and NOTICE retained.

- Artifact: https://repo.maven.apache.org/maven2/org/apache/guacamole/guacamole-common-js/1.6.0/guacamole-common-js-1.6.0.zip
- ZIP SHA-512: `228c08dd0b3e860bcbae1dbccfdcbe55652bebed2aec4c59b738ee025d1354d1e35983459bf25c57495c733d6502ec1e469e9bcb596235a3eac96b62345e1bac`
- Detached signature verified against the Apache HTTPS KEYS distribution.
- Signer fingerprint: `F467E54ACC52F1D2778826865B2977AEE5E4518F`.
- Signature timestamp: 2025-06-16 23:10:01 UTC.
- The isolated verification keyring does not establish external web-of-trust
  identity; provenance is anchored in the official Apache KEYS distribution.
- LICENSE and NOTICE originate from the Apache `guacamole-client` 1.6.0 tag;
  their SHA-512 digests are pinned in the extraction helper.

Reproduce with PowerShell 7: `./scripts/update-guacamole.ps1`. An optional
`-ArtifactDirectory` uses already downloaded files. The helper verifies every
input before extracting exactly one named JS file and the two notices. It
does not install npm packages or execute downloaded scripts. This dependency
adds no build-time download. Scoped Git attributes preserve the original bytes
across Windows and Linux checkouts so integrity checks remain reproducible.

For upgrades: select an official release, verify its signature and dependency
compatibility, update the helper's fixed digests and layout assertion, extract,
update the runtime URL and integrity value, run native channel/browser tests,
and review the generated diff. Never substitute an unofficial npm package or
skip the negative certificate-mismatch acceptance tests.
