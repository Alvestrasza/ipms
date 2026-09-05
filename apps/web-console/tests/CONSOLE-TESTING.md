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
   `IPMS_CONTROL_PLANE_URL=http://127.0.0.1:8107` and start
   `pnpm exec next dev --hostname 127.0.0.1 --port 3107`.
4. Install the test browser with `pnpm exec playwright install chromium --only-shell`.
5. Run `pnpm exec playwright test --config=playwright.console.config.ts`.
6. Stop both local servers after the test. Keep test artifacts out of Git.

The fixture uses the test-only account `e2e-admin` / `test-only-password`.
The test exercises real authentication, session exclusivity, input validation,
ordered input, window resizing/reuse, occupied-session warnings, and close.
Only image responses are synthetic. Real host frame timing, guest rendering,
and guest input effects require separate, explicitly scoped live acceptance.

Run the input buffering tests with `node --test tests/console-input-queue.test.mjs`.
