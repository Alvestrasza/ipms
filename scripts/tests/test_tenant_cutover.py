"""Run recovery control flow with inert command doubles, never live services."""
import os
from pathlib import Path
import shutil
import subprocess
import unittest


SOURCE = (Path(__file__).resolve().parents[1] / "deploy-tenancy-dev.sh").read_text()
BASH = os.environ.get("IPMS_TEST_BASH") or shutil.which("bash")


def function_source(name):
    start = SOURCE.index(name + "() {")
    return SOURCE[start:SOURCE.index("\n}\n", start) + 3]


@unittest.skipUnless(BASH, "A Bash interpreter is required")
class RecoveryTests(unittest.TestCase):
    def exercise(self, schema_started, failure):
        # All external commands reachable from these two functions are replaced
        # with shell functions. No filesystem or service mutation is possible.
        script = "\n".join([
            next(line for line in SOURCE.splitlines() if line.startswith("set -")),
            "systemctl() { printf 'SERVICE:%s\\n' \"$*\"; }",
            "install() { printf 'FENCE_CREATED\\n'; }",
            "unlink() { printf 'FENCE_REMOVED\\n'; }",
            "sudo() { return 17; }",
            "fence=/nonexistent-ipms-test-marker; backup=test; release=test",
            "units=(test.service); restart_units=(test.service)",
            "schema_started=" + ("true" if schema_started else "false"),
            function_source("assert_quiescent"),
            function_source("recover"),
            "trap recover ERR",
            failure,
            "printf 'UNSAFE_CONTINUATION\\n'",
        ])
        return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=5)

    def test_nested_query_failure_restores_pre_migration_runtime_once(self):
        result = self.exercise(False, "assert_quiescent")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(result.stdout.count("SERVICE:start test.service"), 1)
        self.assertNotIn("FENCE_CREATED", result.stdout)
        self.assertNotIn("UNSAFE_CONTINUATION", result.stdout)

    def test_nested_query_failure_fences_after_migration_once(self):
        result = self.exercise(True, "assert_quiescent")
        self.assertEqual(result.returncode, 17, result.stderr)
        self.assertEqual(result.stdout.count("FENCE_CREATED"), 1)
        self.assertEqual(result.stdout.count("SERVICE:stop test.service"), 1)
        self.assertNotIn("SERVICE:start", result.stdout)
        self.assertNotIn("UNSAFE_CONTINUATION", result.stdout)

    def test_direct_failure_keeps_forward_only_recovery(self):
        result = self.exercise(True, "false")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("SERVICE:stop test.service"), 1)
        self.assertNotIn("SERVICE:start", result.stdout)

    def test_persistent_guard_is_installed_before_migration_and_switch(self):
        self.assertIn("exec 9>/run/lock/ipms-tenant-cutover.lock", SOURCE)
        self.assertLess(SOURCE.index("flock -n 9"), SOURCE.index("expected_host=$1"))
        self.assertLess(SOURCE.index("60-ipms-tenant-cutover.conf"), SOURCE.index("schema_started=true"))
        self.assertLess(SOURCE.index("schema_started=true"), SOURCE.index('mv -Tf /srv/ipms/.current-tenancy-next'))
        self.assertLess(SOURCE.index('mv -Tf /srv/ipms/.current-tenancy-next'), SOURCE.rindex('unlink "$fence"'))
        unit = (Path(__file__).resolve().parents[2] / "deploy/standalone/ipms-tenant-cutover.conf").read_text()
        self.assertIn("ConditionPathExists=!/srv/ipms/shared/tenant-cutover.pending", unit)

    def check_administrator_readiness(self, count):
        script = "\n".join([
            "set -Eeuo pipefail",
            "sudo() { printf '%s\\n' " + str(count) + "; }",
            function_source("assert_tenant_administrator_readiness"),
            "assert_tenant_administrator_readiness",
            "printf 'CONTINUE\\n'",
        ])
        return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=5)

    def test_missing_active_historical_administrator_blocks_cutover(self):
        result = self.check_administrator_readiness(1)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("CONTINUE", result.stdout)
        self.assertIn("Resolve access recovery explicitly", result.stderr)

    def test_admin_ready_or_uninitialized_tenants_pass_preflight(self):
        result = self.check_administrator_readiness(0)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CONTINUE", result.stdout)


if __name__ == "__main__":
    unittest.main()
