"""Exercise forward-only recovery with inert commands, never a live cutover."""

import os
from pathlib import Path
import shutil
import subprocess
import unittest


SOURCE = (
    Path(__file__).resolve().parents[1] / "deploy-hyperv-management-dev.sh"
).read_text()
BASH = os.environ.get("IPMS_TEST_BASH") or shutil.which("bash")


def function_source(name):
    start = SOURCE.index(name + "() {")
    return SOURCE[start : SOURCE.index("\n}\n", start) + 3]


@unittest.skipUnless(BASH, "A Bash interpreter is required")
class ForwardOnlyRecoveryTests(unittest.TestCase):
    def exercise(self, command, query="return 17"):
        # Only the two selected functions are evaluated. Every reachable
        # external command is a shell function; kill below is Bash's builtin
        # directed exclusively at this disposable subprocess itself.
        script = "\n".join(
            [
                next(line for line in SOURCE.splitlines() if line.startswith("set -")),
                # Keep events visible even inside captured command output, so
                # an accidental second recovery in a subshell cannot hide.
                "exec 3>&1",
                "systemctl() { printf 'SERVICE:%s\\n' \"$*\" >&3; }",
                "install() { printf 'FENCE_CREATED\\n' >&3; }",
                "unlink() { printf 'FENCE_REMOVED\\n' >&3; }",
                "psql_read() { " + query + "; }",
                "fence=/nonexistent-ipms-test-marker; backup=test; release=test; artifact=test",
                "units=(test.service); restart_units=(test.service)",
                function_source("assert_quiescent"),
                function_source("recover"),
                "trap recover ERR INT TERM",
                command,
                "printf 'CONTINUED\\n'",
            ]
        )
        return subprocess.run(
            [BASH, "-c", script], capture_output=True, text=True, timeout=5
        )

    def assert_fenced_once(self, result, expected_code):
        self.assertEqual(result.returncode, expected_code, result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual(lines.count("FENCE_CREATED"), 1, result.stdout)
        self.assertEqual(lines.count("SERVICE:stop test.service"), 1, result.stdout)
        self.assertNotIn("SERVICE:start", result.stdout)
        self.assertNotIn("FENCE_REMOVED", result.stdout)
        self.assertNotIn("CONTINUED", result.stdout)
        self.assertIn("explicitly reviewed forward recovery", result.stderr)

    def test_direct_failure_fences_and_stops_once(self):
        self.assert_fenced_once(self.exercise("false"), 1)

    def test_nested_query_failure_propagates_and_fences_only_in_parent(self):
        self.assert_fenced_once(self.exercise("assert_quiescent"), 17)

    def test_handled_termination_fences_and_stops_once(self):
        self.assert_fenced_once(self.exercise('kill -TERM "$$"'), 1)

    def test_active_work_blocks_continuation(self):
        result = self.exercise("assert_quiescent", query="printf '1\\n'")
        self.assert_fenced_once(result, 1)
        self.assertIn("Active or queued operations prevent this cutover", result.stderr)

    def test_quiescent_result_does_not_enter_recovery(self):
        result = self.exercise("assert_quiescent", query="printf '0\\n'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "CONTINUED\n")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
