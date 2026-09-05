# Detached console browser acceptance

Use a dedicated local SQLite database, never a deployed IPMS database. This
suite seeds one synthetic Hyper-V host and VM, so it is separate from the
empty-inventory portal suite. No Agent or real hypervisor is contacted.

From `services/control-plane`, set `PYTHONPATH` to `src`,
`DJANGO_SETTINGS_MODULE=ipms_control_plane.settings.e2e`,
`IPMS_E2E_DATABASE` to an absolute temporary SQLite path,
`IPMS_ALLOWED_HOSTS=127.0.0.1,localhost`, and
`IPMS_CSRF_TRUSTED_ORIGINS=http://127.0.0.1:3107`.

1. Run `python ../../apps/web-console/tests/fixtures/seed-console.py`.
2. Run `python manage.py runserver 127.0.0.1:8107 --noreload`.
3. From `apps/web-console`, set
   `IPMS_CONTROL_PLANE_URL=http://127.0.0.1:8107` and build with `pnpm exec next build`.
   Test the standalone production artifact, not `next start` (unsupported for
   `output: standalone`). Copy `.next/standalone`, `.next/static`, and `public`
   as the installer does into an isolated ignored build directory. Preserve
   the traced dependencies; on Windows, a junction to the standalone
   `node_modules` avoids recursively duplicating nested package links.
   Start that directory's `server.js` with `HOSTNAME=127.0.0.2`, `PORT=3107`.
   Use a loopback-only front door on `127.0.0.1:3107` forwarding `/api/v1/`
   directly to Django at `127.0.0.1:8107` and other requests to
   `127.0.0.2:3107`. This mirrors the deployment's nginx split and avoids
   development-only CSRF/Strict Mode behavior. Do not alter the production
   security headers or real credentials for the fixture.
4. Install the test browser with `pnpm exec playwright install chromium --only-shell`.
5. Run `pnpm exec playwright test --config=playwright.console.config.ts`.
6. Stop the browser and all three local helpers after the test; verify the
   fixture ports are free. Keep fixture databases and evidence out of Git.

The fixture uses the test-only account `e2e-admin` / `test-only-password`.
The thumbnail test exercises real authentication, session exclusivity, input validation,
ordered input, window resizing/reuse, occupied-session warnings, and close.
Only image responses are synthetic. Real host frame timing, guest rendering,
and guest input effects require separate, explicitly scoped live acceptance.

Run the input buffering tests with `node --test tests/console-input-queue.test.mjs`.

The native tests use the same real fixture login and server-rendered inventory,
but mock only the native configuration, session creation/deletion, and WebSocket
broker. The official pinned renderer must draw actual synthetic pixel data.
Assertions cover the default native choice, explicit external-session warning,
admin-only configuration UI, certificate approval/cancellation, no automatic
fallback after authentication failure, keyboard/mouse/secure attention, resize,
and socket cleanup. This is browser integration evidence, not proof of host
authentication, backend authorization, TLS pinning, relay behavior, or FPS.
Those require their own backend tests and separately authorized live acceptance.

Run deterministic native state and dependency integrity tests with
`node --test tests/native-console-channel.test.mjs tests/guacamole-artifact.test.mjs`.
