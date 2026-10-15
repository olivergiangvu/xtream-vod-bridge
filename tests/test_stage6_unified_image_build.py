"""Guardrails for immutable one-container image-only build and Compose."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from canary import stage6_unified_image_build as stage


class Stage6SourceAndBuildTests(unittest.TestCase):
    def test_git_pins_and_production_images(self):
        self.assertEqual(len(stage.REF), 40)
        self.assertEqual(len(stage.SOURCES), 3)
        self.assertEqual(
            stage.BASE_IMAGE, "homedocker/xtream-vod-canary-admin:0.5g-prefix-206cf27063b8"
        )
        self.assertTrue(stage.CANDIDATE_IMAGE.startswith("homedocker/xtream-vod-unified-canary:"))
        self.assertEqual(len(stage.PRODUCTION), 2)
        self.assertEqual(len(stage.OLD_CANARY), 2)

    def test_offline_canary_is_one_service_with_no_host_ports(self):
        content = (Path(__file__).resolve().parents[1] /
                   "canary/unified-compose.yaml").read_text()
        self.assertEqual(content.count("  xtream-unified:\n"), 1)
        self.assertNotIn("  xtream-vod-admin:\n", content)
        self.assertNotIn("  xtream-vod-bridge:\n", content)
        self.assertNotIn("\n    ports:", content)
        self.assertIn("internal: true", content)
        self.assertIn('restart: "no"', content)
        self.assertIn('LEGACY_SYNC_ENABLED: "0"', content)
        self.assertIn('XTREAM_UNIFIED_MODE: "1"', content)
        self.assertIn("8767/live", content)
        self.assertIn("interval: 60s", content)
        self.assertNotIn("8768", content)

    def test_offline_image_contains_only_pinned_from_and_copy(self):
        source = (Path(__file__).resolve().parents[1] /
                  "canary/Dockerfile.unified-offline").read_text()
        commands = [
            ln.strip() for ln in source.splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")
        ]
        self.assertEqual(commands[0], "FROM " + stage.BASE_IMAGE)
        self.assertIn("COPY unified_app.py admin_ui.py /srv/", commands)
        self.assertFalse(any(ln.startswith("RUN ") for ln in commands))
        self.assertFalse(any(ln.startswith("ADD ") for ln in commands))
        self.assertTrue(any("unified_app:application" in ln for ln in commands))
        self.assertFalse(any("8768" in ln for ln in commands))

    def test_build_gate_cpu_and_psi_headroom(self):
        with patch.object(stage.os, "cpu_count", return_value=2), \
             patch.object(stage, "run", return_value="/tmp"), \
             patch.object(stage, "host_ticks",
                          side_effect=[(10000, 4000), (12000, 5000)]), \
             patch.object(stage, "psi10", side_effect=[40.0, 39.0]), \
             patch.object(stage.shutil, "disk_usage",
                          return_value=SimpleNamespace(free=4 * 1024**3)), \
             patch.object(stage.Path, "read_text",
                          return_value="MemAvailable: 2097152 kB\n"), \
             patch.object(stage.time, "sleep") as sleeper:
            stage.build_gate()
            sleeper.assert_called_once_with(10)

    def test_build_gate_rejects_host_cpu_pressure(self):
        for ticks, psi in (
            ([(10000, 4000), (12000, 4400)], [30.0, 30.0]),
            ([(10000, 4000), (12000, 5000)], [30.0, 80.0]),
        ):
            with self.subTest(ticks=ticks, psi=psi), \
                 patch.object(stage.os, "cpu_count", return_value=2), \
                 patch.object(stage, "run", return_value="/tmp"), \
                 patch.object(stage, "host_ticks", side_effect=ticks), \
                 patch.object(stage, "psi10", side_effect=psi), \
                 patch.object(stage.shutil, "disk_usage",
                              return_value=SimpleNamespace(free=4 * 1024**3)), \
                 patch.object(stage.Path, "read_text",
                              return_value="MemAvailable: 2097152 kB\n"), \
                 patch.object(stage.time, "sleep"):
                with self.assertRaisesRegex(ValueError, "RESOURCE_GATE_NOT_READY"):
                    stage.build_gate()


if __name__ == "__main__":
    unittest.main()
