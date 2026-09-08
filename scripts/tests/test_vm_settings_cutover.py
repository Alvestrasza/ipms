"""Exercise the schema-neutral portal rollback with inert commands only."""

from pathlib import Path
import shutil
import subprocess
import unittest

SOURCE = (Path(__file__).resolve().parents[1] / "deploy-vm-settings-dev.sh").read_text()
BASH = shutil.which("bash")


@unittest.skipUnless(BASH, "A Bash interpreter is required")
class PortalRollbackTests(unittest.TestCase):
    def exercise(self, command="false", healthy=True, preserved=True):
        start = SOURCE.index("recover() {")
        recover = SOURCE[start:SOURCE.index("\n}\n", start) + 3]
        script = "\n".join([
            "set -Eeuo pipefail; shopt -s inherit_errexit; exec 3>&1",
            "units=(portal-api portal-web); previous=/nonexistent-previous; previous_ref=expected; next_link=/nonexistent-next; fence=/nonexistent-fence; preserved=unchanged",
            "install() { echo FENCE_CREATED >&3; }; unlink() { echo REMOVED:$1 >&3; }",
            "systemctl() { echo SERVICE:$* >&3; }; protected() { return 0; }",
            "git() { echo expected; }; ln() { echo PREVIOUS_SELECTED >&3; }; mv() { echo LINK_SWITCHED >&3; }",
            "sha256sum() { echo " + ("unchanged" if preserved else "changed") + "; }",
            "wait_ready() { return " + ("0" if healthy else "1") + "; }",
            recover, "trap recover ERR INT TERM", command, "echo CONTINUED",
        ])
        return subprocess.run([BASH, "-c", script], capture_output=True, text=True, timeout=5)

    def test_failure_restores_only_previous_portal(self):
        result = self.exercise()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("PREVIOUS_SELECTED"), 1)
        self.assertIn("SERVICE:start portal-api portal-web", result.stdout)
        self.assertIn("0.2.36 portal is restored", result.stderr)
        self.assertNotIn("CONTINUED", result.stdout)

    def test_signal_uses_same_rollback_once(self):
        result = self.exercise('kill -TERM "$$"')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("PREVIOUS_SELECTED"), 1)
        self.assertNotIn("CONTINUED", result.stdout)

    def test_failed_recovery_keeps_fence(self):
        result = self.exercise(healthy=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout.count("FENCE_CREATED"), 2)
        self.assertIn("services remain fenced", result.stderr)

    def test_changed_environment_prevents_unsafe_restore(self):
        result = self.exercise(preserved=False)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("PREVIOUS_SELECTED", result.stdout)
        self.assertNotIn("SERVICE:start", result.stdout)
        self.assertIn("services remain fenced", result.stderr)

    def test_unchanged_path_does_not_recover(self):
        result = self.exercise("true")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "CONTINUED\n")


if __name__ == "__main__":
    unittest.main()
