"""Stage5A3 atomic Canary recreate, no-port guarantees and verified rollback."""
from pathlib import Path
from types import SimpleNamespace
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from canary import stage5a3_atomic_recreate as stage
from canary import stage5a3_recreate_plan as plan


def baseline_container():
    return {
        "Id": "canary-new-id",
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Config": {
            "Image": plan.NEW_ADMIN,
            "Labels": {"com.docker.compose.project": "xtream-vod-canary"},
        },
        "NetworkSettings": {
            "Networks": {plan.NETWORK: {"IPAddress": "172.30.0.3"}},
            "Ports": {"8768/tcp": None},
        },
        "HostConfig": {"PortBindings": {}},
    }


class Stage5A3AtomicTests(unittest.TestCase):
    def test_candidate_and_exact_pinned_plan(self):
        self.assertEqual(
            stage.sha256(plan.CANDIDATE.encode("utf-8")),
            stage.CANDIDATE_SHA
        )
        self.assertEqual(stage.PLAN_COMMIT,
                         "ce7b76cb56a3b4699484f682641b6f2b9d5b02cb")
        self.assertEqual(stage.PLAN_BLOB,
                         "822a9c22162c4d54721e98f0346763128a4509c2")
        self.assertEqual(stage.RECREATE_APPROVAL,
                         "canary-admin-and-playback")

    def test_health_rejects_live_and_dormant_ports(self):
        for mutate in (
            lambda c: c["NetworkSettings"]["Ports"].update({
                "8768/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18770"}]
            }),
            lambda c: c["HostConfig"]["PortBindings"].update({
                "8768/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18770"}]
            }),
            lambda c: c["NetworkSettings"]["Networks"].update({
                "bridge": {"IPAddress": "172.17.0.10"}
            }),
            lambda c: c["Config"].update(Image="unapproved:latest"),
        ):
            obj = baseline_container()
            mutate(obj)
            with self.subTest(change=mutate), \
                 patch.object(stage, "wait_healthy", return_value=obj), \
                 patch.object(stage, "command",
                              side_effect=['[{"Internal": true}]', ""]):
                with self.assertRaises(ValueError):
                    stage.verify_canary(
                        plan, "xtream-vod-canary-admin", plan.NEW_ADMIN
                    )

    def test_health_success_requires_correct_image_and_new_id(self):
        obj = baseline_container()
        with patch.object(stage, "wait_healthy", return_value=obj), \
             patch.object(stage, "command",
                          side_effect=['[{"Internal": true}]', ""]):
            output = stage.verify_canary(
                plan, "xtream-vod-canary-admin",
                plan.NEW_ADMIN, old_id="canary-old-id"
            )
            self.assertIs(output, obj)
        with patch.object(stage, "wait_healthy", return_value=obj):
            with self.assertRaises(ValueError):
                stage.verify_canary(
                    plan, "xtream-vod-canary-admin",
                    plan.NEW_ADMIN, old_id="canary-new-id"
                )

    def test_cpu_recreate_gate_fails_if_psi_high(self):
        fake = SimpleNamespace(psi10=lambda: 32.8)
        with patch.object(stage.os, "cpu_count", return_value=2), \
             patch.object(stage, "host_cpu_sample",
                          side_effect=[(10000, 4000), (12000, 5000)]), \
             patch.object(stage.time, "sleep"), \
             patch.object(stage, "command", return_value="/tmp"), \
             patch.object(stage.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=4 * 1024**3)):
            with self.assertRaisesRegex(ValueError, "CPU_PSI_NOT_READY"):
                stage.readiness(fake)

    def test_atomic_override_exact_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ui-override.yaml"
            original = b"services:\n  xtream-vod-admin:\n    image: original\n"
            candidate = b"services:\n  xtream-vod-admin:\n    image: new\n"
            target.write_bytes(original)
            target.chmod(0o600)
            meta = target.stat()
            stage.atomic_override(target, candidate, meta)
            self.assertEqual(target.read_bytes(), candidate)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            stage.atomic_override(target, original, meta)
            self.assertEqual(target.read_bytes(), original)

    def test_rollback_verifies_both_old_containers_and_override(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ui-override.yaml"
            old = b"old-canary-override\n"
            target.write_bytes(b"new-canary-override\n")
            fake = SimpleNamespace(
                OVERRIDE=target,
                OVERRIDE_SHA=hashlib.sha256(old).hexdigest(),
                PLAY_IMAGE=plan.PLAY_IMAGE,
                OLD_ADMIN=plan.OLD_ADMIN,
            )
            with patch.object(stage, "compose_up") as up, \
                 patch.object(stage, "verify_canary") as check, \
                 patch.object(stage, "verify_unchanged"):
                ok = stage.rollback(fake, old, {}, recreate_attempted=True)
                self.assertTrue(ok)
                self.assertEqual(target.read_bytes(), old)
                self.assertEqual(up.call_count, 2)
                self.assertGreaterEqual(check.call_count, 4)

    def test_file_only_rollback_checks_original_dormant_binding_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ui-override.yaml"
            old = b"old-canary-override\n"
            target.write_bytes(b"new-canary-override\n")
            orig_ids = {
                "xtream-vod-canary-playback": "old-play",
                "xtream-vod-canary-admin": "old-admin",
            }
            fake = SimpleNamespace(
                OVERRIDE=target,
                OVERRIDE_SHA=hashlib.sha256(old).hexdigest(),
                PLAY_IMAGE=plan.PLAY_IMAGE,
                OLD_ADMIN=plan.OLD_ADMIN,
                check_live=lambda: dict(orig_ids),
            )
            with patch.object(stage, "compose_up") as up, \
                 patch.object(stage, "verify_canary") as verify, \
                 patch.object(stage, "verify_unchanged"):
                self.assertTrue(stage.rollback(
                    fake, old, orig_ids, recreate_attempted=False
                ))
                up.assert_not_called()
                verify.assert_not_called()
                self.assertEqual(target.read_bytes(), old)

    def test_failed_override_restore_blocks_recreate(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ui-override.yaml"
            old = b"old-canary-override\n"
            target.write_bytes(b"new-canary-override\n")
            fake = SimpleNamespace(
                OVERRIDE=target,
                OVERRIDE_SHA=hashlib.sha256(old).hexdigest(),
                PLAY_IMAGE=plan.PLAY_IMAGE,
                OLD_ADMIN=plan.OLD_ADMIN,
            )
            with patch.object(stage, "atomic_override",
                              side_effect=OSError("no space")), \
                 patch.object(stage, "compose_up") as up, \
                 patch.object(stage, "verify_canary") as verify:
                self.assertFalse(stage.rollback(
                    fake, old, {}, recreate_attempted=True
                ))
                up.assert_not_called()
                verify.assert_not_called()
    def test_rollback_failure_never_claims_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "ui-override.yaml"
            old = b"old-canary-override\n"
            target.write_bytes(b"new-canary-override\n")
            fake = SimpleNamespace(
                OVERRIDE=target,
                OVERRIDE_SHA=hashlib.sha256(old).hexdigest(),
                PLAY_IMAGE=plan.PLAY_IMAGE,
                OLD_ADMIN=plan.OLD_ADMIN,
            )
            with patch.object(stage, "compose_up",
                              side_effect=ValueError("container fails")), \
                 patch.object(stage, "verify_canary",
                              side_effect=ValueError("unhealthy")), \
                 patch.object(stage, "verify_unchanged"):
                ok = stage.rollback(fake, old, {}, recreate_attempted=True)
                self.assertFalse(ok)
                self.assertEqual(target.read_bytes(), old)


if __name__ == "__main__":
    unittest.main()
