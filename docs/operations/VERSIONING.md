# IPMS Development Versioning

## Policy

Every published IPMS application change increments the visible semantic
version. During the v0.1.0 foundation milestone, development builds use the
`0.1.x` sequence. The current source-of-truth version is stored in the root
`VERSION` file and must match the Control Plane package, Web Console package,
API information response, and localized Web Console footer.

Infrastructure documentation-only commits may retain the current application
version when they do not change a deployable artifact. A commit that changes a
deployable service, UI, schema, runtime configuration, or installer must bump
the patch component before publication.

## Release Verification

An operator can verify a deployment through:

- the version shown at the bottom of the Web Console sidebar;
- `GET /api/v1/`, which returns `application_version`; and
- the immutable Git commit selected by `/srv/ipms/current`.

The semantic version identifies the application build. The Git commit remains
the authoritative immutable deployment identity and rollback target.
