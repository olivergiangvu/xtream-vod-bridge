"""Static safety checks for M3.5 non-networked, repaired-image startup."""
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
from contextlib import redirect_stdout
from io import StringIO

from canary import stage6_unified_permfix_runtime_verify as stage


class PermfixRuntimeTests(unittest.TestCase):
    def test_uses_new_image_and_unique_ephemeral_identity(self):
        self.assertTrue(stage.IMAGE.endswith("-permfix1"))
        self.assertEqual(stage.NAME, "xtream-vod-unified-permfix-diagnostic")
        self.assertEqual(stage.APPROVAL, "verify-one-offline-unified-permfix-startup")
        self.assertNotEqual(stage.NAME, "xtream-vod-unified-canary")

    def test_no_network_or_host_port_exposure(self):
        with patch.object(stage, "disposable_clone", return_value=Path("/opt/xtream-vod-canary/temporary/data")), \
             patch.object(stage, "execute") as invoke, \
             patch.object(stage, "docker_inspect") as inspect, \
             patch.object(stage.time, "sleep"), \
             patch.object(stage, "safe_diag"), \
             patch.object(stage, "verify_unchanged"):
            invoke.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
            inspect.return_value = {
                "HostConfig": {
                    "NetworkMode": "none", "NanoCpus": 500000000,
                    "Memory": 268435456, "ReadonlyRootfs": True,
                    "PortBindings": {},
                },
                "State": {"Running": False, "ExitCode": 1, "OOMKilled": False},
            }
            with redirect_stdout(StringIO()):
                with self.assertRaisesRegex(RuntimeError, "DIAGNOSTIC_STARTUP_DID_NOT_SURVIVE"):
                    stage.run_one({}, Path("/tmp/not-executed"))
            args = invoke.call_args_list[0].args[0]
            self.assertEqual(args[:3], ["docker", "run", "--detach"])
            self.assertIn("--network", args)
            self.assertEqual(args[args.index("--network") + 1], "none")
            self.assertEqual(args[args.index("--cpus") + 1], "0.5")
            self.assertEqual(args[args.index("--memory") + 1], "256m")
            self.assertIn("--read-only", args)
            self.assertNotIn("--publish", args)
            self.assertNotIn("--privileged", args)
            self.assertEqual(args[-1], stage.IMAGE)

    def test_no_secret_data_in_exception_output(self):
        raw = ('Traceback (most recent call last):\n'
               '  File "/srv/unified_app.py", line 18, in startup\n'
               'PermissionError: Permission denied /srv/admin_ui.py '
               'secret=do-not-echo\n')
        with redirect_stdout(StringIO()) as output:
            stage.safe_diag(raw)
        self.assertIn("PERMISSION_DENIED", output.getvalue())
        self.assertNotIn("do-not-echo", output.getvalue())


if __name__ == "__main__":
    unittest.main()
