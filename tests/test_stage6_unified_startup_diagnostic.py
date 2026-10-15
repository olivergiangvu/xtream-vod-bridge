"""Safe startup reproduction contracts. These tests never start Docker."""
from contextlib import redirect_stdout
import io
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from canary import stage6_unified_startup_diagnostic as diag


class UnifiedStartupDiagnosticTests(unittest.TestCase):
    def test_pin_identity_and_approval(self):
        self.assertEqual(diag.NAME, "xtream-vod-unified-diagnostic")
        self.assertEqual(diag.APPROVAL, "run-one-offline-unified-startup-diagnostic")
        self.assertEqual(diag.IMAGE,
                         "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd")

    def test_safe_exception_shape_only(self):
        raw = (
            'Traceback (most recent call last):\n'
            '  File "/srv/unified_app.py", line 18, in unified_lifespan\n'
            '  File "/srv/app.py", line 139, in init_db\n'
            'sqlite3.OperationalError: unable to open database file; '
            'secret-token=SUPERSECRET\n'
        )
        with redirect_stdout(io.StringIO()) as output:
            diag.safe_diag(raw)
        text = output.getvalue()
        self.assertIn("unified_app.py:L18", text)
        self.assertIn("app.py:L139", text)
        self.assertIn("sqlite3.OperationalError", text)
        self.assertIn("SQLITE_DATABASE_OPEN_FAILED", text)
        self.assertNotIn("SUPERSECRET", text)
        self.assertNotIn("secret-token", text)

    def test_never_print_untrusted_frame_names(self):
        raw = (
            'File "/var/tmp/secret=xyz.py", line 12, in foo\n'
            'ValueError: XTREAM_PASSWORD=my-secret\n'
        )
        with redirect_stdout(io.StringIO()) as output:
            diag.safe_diag(raw)
        self.assertNotIn("my-secret", output.getvalue())
        self.assertNotIn("secret=xyz", output.getvalue())

    def test_disposable_container_strict_run_args(self):
        with patch.object(diag, "disposable_clone",
                          return_value=Path("/opt/xtream-vod-canary/mock-data")), \
             patch.object(diag, "execute") as command, \
             patch.object(diag, "docker_inspect") as inspect, \
             patch.object(diag, "time") as clock, \
             patch.object(diag, "safe_diag"), \
             patch.object(diag, "verify_unchanged"):
            command.return_value = SimpleNamespace(
                returncode=0, stdout="", stderr=""
            )
            inspect.return_value = {
                "HostConfig": {
                    "NetworkMode": "none",
                    "NanoCpus": 500000000,
                    "Memory": 268435456,
                    "ReadonlyRootfs": True,
                    "PortBindings": {},
                },
                "State": {"Running": False, "ExitCode": 1, "OOMKilled": False},
            }
            with redirect_stdout(io.StringIO()):
                diag.run_one({}, Path("/tmp/unit-test-only"))
            argv = command.call_args_list[0].args[0]
            self.assertEqual(argv[:3], ["docker", "run", "--detach"])
            for expected in (
                "--network", "none",
                "--restart", "no",
                "--cpus", "0.5",
                "--memory", "256m",
                "--cap-drop", "ALL",
                "--read-only",
                "--pull", "never",
            ):
                self.assertIn(expected, argv)
            self.assertNotIn("--publish", argv)
            self.assertNotIn("--privileged", argv)
            self.assertEqual(argv[-1], diag.IMAGE)

    def test_rollback_refuses_unknown_container(self):
        with patch.object(diag, "docker_inspect",
                          return_value={
                              "Config": {"Image": "production:latest"},
                              "HostConfig": {"NetworkMode": "host"},
                              "State": {"Running": True},
                          }), patch.object(diag, "execute") as command:
            with self.assertRaises(RuntimeError):
                diag.cleanup({})
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
