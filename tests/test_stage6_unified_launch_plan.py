"""Offline M3 unified one-Canary config safety contracts; no Docker required."""
import copy
import io
import unittest
from contextlib import redirect_stdout

from canary import stage6_unified_launch_plan as stage


def minimal_effective():
    return {
        "services": {
            "xtream-unified": {
                "container_name": stage.NAME,
                "image": stage.IMAGE,
                "restart": "no",
                "pull_policy": "never",
                "ports": [],
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "cpus": 0.5,
                "mem_limit": "256m",
                "pids_limit": 64,
                "command": [
                    "uvicorn", "unified_app:application",
                    "--host", "0.0.0.0", "--port", "8767",
                    "--no-access-log"
                ],
                "healthcheck": {
                    "test": [
                        "CMD", "python", "-c",
                        "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8767/live')"
                    ]
                },
                "environment": {
                    "XTREAM_UNIFIED_MODE": "1",
                    "LEGACY_SYNC_ENABLED": "0",
                    "XTREAM_URL_PREFIX": "/canary",
                    "XTREAM_SESSION_COOKIE": "xtream_canary_admin_session",
                    "XTREAM_LOGIN_NONCE_COOKIE": "xtream_canary_login_nonce",
                    "ADMIN_PUBLIC_ORIGIN": "https://olivergiangvu.asuscomm.com:18450",
                    "PUBLIC_BASE_URL": "https://olivergiangvu.asuscomm.com:18450/canary",
                },
                "volumes": [{
                    "type": "bind", "source": str(stage.TARGET_DATA),
                    "target": "/data"
                }],
                "networks": {"unified_private": None},
            },
        },
        "networks": {
            "unified_private": {
                "name": stage.NETWORK, "internal": True
            },
        },
    }


class Stage6UnifiedCanaryPlanTests(unittest.TestCase):
    def test_one_service_exact_network_and_limits(self):
        with redirect_stdout(io.StringIO()) as output:
            stage.check_effective(minimal_effective())
        self.assertIn("UNIFIED_COMPOSE_ONE_SERVICE_ONLY=PASS", output.getvalue())
        self.assertIn("UNIFIED_PUBLISHED_HOST_PORTS=NONE", output.getvalue())

    def test_rejects_host_ports(self):
        cfg = minimal_effective()
        cfg["services"]["xtream-unified"]["ports"] = [
            {"published": "18770", "target": 8767}
        ]
        with self.assertRaisesRegex(ValueError, "COMPOSE_EXTERNAL_EXPOSURE"):
            stage.check_effective(cfg)

    def test_rejects_second_container(self):
        cfg = minimal_effective()
        cfg["services"]["xtream-vod-admin"] = {}
        with self.assertRaisesRegex(ValueError, "COMPOSE_NOT_EXACTLY_ONE_SERVICE"):
            stage.check_effective(cfg)

    def test_rejects_non_private_or_extra_network(self):
        for change in ("noninternal", "extra"):
            cfg = minimal_effective()
            if change == "noninternal":
                cfg["networks"]["unified_private"]["internal"] = False
            else:
                cfg["services"]["xtream-unified"]["networks"]["bridge"] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage.check_effective(cfg)

    def test_rejects_mount_to_legacy_canary_data(self):
        cfg = minimal_effective()
        cfg["services"]["xtream-unified"]["volumes"][0]["source"] = str(stage.SOURCE_DATA)
        with self.assertRaisesRegex(ValueError, "DATA_MOUNT_NOT_ISOLATED"):
            stage.check_effective(cfg)

    def test_rejects_unsafe_egress_and_sync(self):
        for env_name, val in (
            ("LEGACY_SYNC_ENABLED", "1"),
            ("XTREAM_UNIFIED_MODE", "0"),
            ("XTREAM_URL_PREFIX", ""),
        ):
            cfg = minimal_effective()
            cfg["services"]["xtream-unified"]["environment"][env_name] = val
            with self.subTest(name=env_name), self.assertRaisesRegex(
                ValueError, "COMPOSE_REQUIRED_ENV_INVALID"
            ):
                stage.check_effective(cfg)

    def test_rejects_resource_cap_drift(self):
        for key, val in (
            ("cpus", 1.0), ("mem_limit", "1024m"), ("pids_limit", 256)
        ):
            cfg = minimal_effective()
            cfg["services"]["xtream-unified"][key] = val
            with self.subTest(key=key), self.assertRaises(ValueError):
                stage.check_effective(cfg)

    def test_rejects_healthcheck_sql_or_missing_live(self):
        cfg = minimal_effective()
        cfg["services"]["xtream-unified"]["healthcheck"]["test"] = [
            "CMD", "python", "-c", "urllib.request.urlopen('http://localhost:8767/health')"
        ]
        with self.assertRaisesRegex(ValueError, "HEALTH_NOT_CONSTANT_TIME"):
            stage.check_effective(cfg)

    def test_pinned_source_release(self):
        self.assertEqual(
            stage.COMPOSE_BLOB, "32da1db31ac09e746245eebdf10b8f18ebe54da3"
        )
        self.assertEqual(len(stage.REF), 40)
        self.assertEqual(stage.MAX_COPY_BYTES, 512 * 1024 * 1024)
        self.assertEqual(stage.MAX_COPY_FILES, 10000)


if __name__ == "__main__":
    unittest.main()
