# Native console adapter notices

The renderer is built from the official Apache Guacamole 1.6.0 source release.
Apache Guacamole is copyright The Apache Software Foundation and distributed
under the Apache License, Version 2.0. The source patch contains excerpts of
that Apache-licensed source and marks IPMS changes. The build installs the
release's complete LICENSE and NOTICE alongside the resulting adapter.

IPMS changes: strict per-session certificate verification, rejected RDP
redirects, explicit fixed-mode capability marker, current-libc compatibility,
post-connect graphics initialization for the tested Ubuntu FreeRDP 3.31.0
baseline, explicit nested-socket state/mutex initialization and cleanup, a
TLS 1.2 host-console minimum, a two-worker per-session encoding cap, and a
disabled Wake-on-LAN implementation. These changes do not imply upstream
Apache or FreeRDP acceptance or endorsement. The exact FreeRDP version is
checked by the build; support for another version requires separate review.

Final isolated verification on 2026-09-05 passed 97 upstream `make check`
checks with allocator perturbation, nine certificate-helper cases and six
synthetic loopback TLS cases. This is evidence for the adapted build, not a
license modification, host-compatibility guarantee, deployment approval or
production-readiness claim. No live-service cutover has occurred for this
change; real-host console acceptance and performance measurements remain
pending. See the operations document for the full evidence boundaries.

The separately pinned browser runtime and its notices are under
`apps/web-console/public/vendor/guacamole/1.6.0/`. IPMS's proprietary license
does not replace applicable third-party licenses or notices. Ubuntu-provided
runtime libraries retain their distribution copyright and license files.

See [Apache Guacamole 1.6.0](https://guacamole.apache.org/releases/1.6.0/) and
the exact build and verification procedure in
`docs/operations/NATIVE-HYPERV-CONSOLE.md`.
