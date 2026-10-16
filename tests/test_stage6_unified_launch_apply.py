"""M3.2 audit tests: the only mutating operation is a separately approved start.

No Docker daemon, host nginx, user files, network, or service is touched.
"""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from canary import stage6_unified_launch_apply as stage


def fake_container(plan):
    return {
        "Id": "candidate-1",
        "Config": {
            "Image": plan.IMAGE,
            "Labels": {
                "com.docker.compose.project": plan.PROJECT,
                "com.docker.compose.service": "xtream-unified",
            },
        },
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "HostConfig": {
            "NanoCpus": 500000000,
            "Memory": 268435456,
            "PidsLimit": 64,
            "ReadonlyRootfs": True,
            "RestartPolicy": {"Name": "no"},
            "PortBindings": {},
        },
        "NetworkSettings": {
            "Networks": {plan.NETWORK: {"IPAddress": "172.30.15.3"}},
            "Ports": {"8767/tcp": None},
        },
        "Mounts": [{"Source": str(plan.TARGET_DATA), "Destination": "/data"}],
    }


class UnifiedAtomicLaunchTests(unittest.TestCase):
    def setUp(self):
        self.plan = SimpleNamespace(
            NAME="xtream-vod-unified-canary",
            IMAGE=stage.CANARY_IMAGE,
            PROJECT="xtream-vod-unified-canary",
            NETWORK="xtream-vod-unified-canary_unified_private",
            TARGET_DATA=Path("/opt/xtream-vod-canary/unified-data"),
            OLD={
                "xtream-vod-canary-admin": "old-admin",
                "xtream-vod-canary-playback": "old-playback",
            },
            inspect=lambda name: {"State": {"Running": False}},
            check_protected=lambda: None,
            git_blob=stage.blob,
        )

    def test_pinned_unchangeable_plan_and_exact_approval(self):
        self.assertEqual(
            stage.PIN_COMMIT, "f1dac319d428043183b4d4e56e6ea6a24e53b50c"
        )
        self.assertEqual(stage.PIN_BLOB, "91ec448409dd686157ea298283cf6cf5dac1cea7")
        self.assertEqual(stage.APPROVAL, "start-only-one-private-unified-canary")
        self.assertEqual(
            stage.CANARY_IMAGE, "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd"
        )

    def test_one_container_health_and_isolation(self):
        obj = fake_container(self.plan)
        with patch.object(stage, "maybe_container", return_value=obj), \
             patch.object(stage, "maybe_network",
                          return_value={"Internal": True}), \
             patch.object(stage, "run", return_value=""):
            self.assertIs(stage.verify_runtime(self.plan, require_healthy=True), obj)

    def test_reject_any_host_port_and_extra_network(self):
        for field in ("published", "dormant", "extra-network", "noninternal"):
            obj = fake_container(self.plan)
            network = {"Internal": True}
            if field == "published":
                obj["NetworkSettings"]["Ports"]["8767/tcp"] = [
                    {"HostIp": "0.0.0.0", "HostPort": "18770"}
                ]
            elif field == "dormant":
                obj["HostConfig"]["PortBindings"] = {
                    "8767/tcp": [{"HostPort": "18770"}]
                }
            elif field == "extra-network":
                obj["NetworkSettings"]["Networks"]["bridge"] = {}
            else:
                network["Internal"] = False
            with self.subTest(field=field), \
                 patch.object(stage, "maybe_container", return_value=obj), \
                 patch.object(stage, "maybe_network", return_value=network), \
                 patch.object(stage, "run", return_value=""):
                with self.assertRaises(ValueError):
                    stage.verify_runtime(self.plan)

    def test_reject_resource_limits_or_wrong_mount(self):
        for field in ("cpu", "ram", "pid", "mount", "image", "project"):
            obj = fake_container(self.plan)
            if field == "cpu":
                obj["HostConfig"]["NanoCpus"] = 1000000000
            elif field == "ram":
                obj["HostConfig"]["Memory"] = 0
            elif field == "pid":
                obj["HostConfig"]["PidsLimit"] = 0
            elif field == "mount":
                obj["Mounts"][0]["Source"] = "/opt/xtream-vod-canary/data"
            elif field == "image":
                obj["Config"]["Image"] = "rogue:latest"
            else:
                obj["Config"]["Labels"]["com.docker.compose.project"] = "prod"
            with self.subTest(field=field), \
                 patch.object(stage, "maybe_container", return_value=obj), \
                 patch.object(stage, "maybe_network",
                              return_value={"Internal": True}), \
                 patch.object(stage, "run", return_value=""):
                with self.assertRaises(ValueError):
                    stage.verify_runtime(self.plan)

    def test_rollback_refuses_wrong_container(self):
        obj = fake_container(self.plan)
        obj["Config"]["Image"] = "production:image"
        with patch.object(stage, "maybe_container", return_value=obj), \
             patch.object(stage, "maybe_network", return_value=None), \
             patch.object(stage, "run") as run, \
             patch.object(stage, "prod_unchanged"):
            with redirect_stdout(io.StringIO()) as output:
                self.assertFalse(stage.rollback(self.plan, {}, compose_created=False))
            run.assert_not_called()
            self.assertIn("CRITICAL_M3_2_ROLLBACK_VERIFIED=NO", output.getvalue())

    def test_rollback_success_keeps_snapshot_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unified-compose.yaml"
            data = b"services:\n  xtream-unified: {}\n"
            path.write_bytes(data)
            self.plan.COMPOSE_BLOB = stage.blob(data)
            with patch.object(stage, "COMPOSE_TARGET", path), \
                 patch.object(stage, "maybe_container", return_value=None), \
                 patch.object(stage, "maybe_network", return_value=None), \
                 patch.object(stage, "prod_unchanged"), \
                 patch.object(stage, "run") as run:
                with redirect_stdout(io.StringIO()) as output:
                    ok = stage.rollback(self.plan, {}, compose_created=True)
                self.assertTrue(ok)
                self.assertFalse(path.exists())
                run.assert_not_called()
                self.assertIn("M3_2_ISOLATED_TEST_DATA_RETAINED=YES", output.getvalue())
                self.assertIn("M3_2_ROLLBACK_VERIFIED=YES", output.getvalue())

    def test_smoke_asserts_prefix_and_no_legacy_sync(self):
        self.assertIn("app.LEGACY_SYNC_ENABLED is False", stage.SMOKE)
        self.assertIn('route_paths.ADMIN_PATH == "/canary/admin/"', stage.SMOKE)
        self.assertIn("/api/auth/gate-check", stage.SMOKE)
        self.assertIn("Path=/canary/admin-signin/", stage.SMOKE)
        self.assertIn("/live", stage.SMOKE)


if __name__ == "__main__":
    unittest.main()
