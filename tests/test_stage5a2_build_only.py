"""Stage 5A.2 no-recreate image-only build plan safety regression tests."""
import unittest
from unittest.mock import patch

from canary import stage5a2_build_only as stage


class Stage5A2Tests(unittest.TestCase):
    def test_old_images_stay_pinned(self):
        self.assertEqual(
            stage.IMAGES["xtream-vod-admin"],
            "homedocker/xtream-vod-admin:0.4.3-manifest",
        )
        self.assertEqual(
            stage.IMAGES["xtream-vod-bridge"],
            "homedocker/xtream-vod-bridge:0.4.0",
        )
        self.assertTrue(stage.NEW_ADMIN.endswith("206cf27063b8"))
        self.assertEqual(len(stage.SOURCES), 5)

    def test_build_contains_only_allowlisted_source_copies(self):
        text = stage.dockerfile()
        self.assertIn("FROM " + stage.OLD_ADMIN, text)
        self.assertIn("COPY route_paths.py admin_auth.py admin_ui.py /srv/", text)
        self.assertIn("COPY admin/assets/app.js admin/assets/workspace.js /srv/admin/assets/", text)
        self.assertNotIn("RUN ", text)
        self.assertNotIn("ENV ", text)
        self.assertNotIn("secrets", text)

    def test_git_blob_hash_algorithm(self):
        self.assertEqual(
            stage.git_blob(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )

    def test_cpu_gate_refuses_any_sample_above_threshold(self):
        with patch.object(stage.time, "sleep") as sleepy:
            for samples in ([34, 22], [22, 31], [30, 22], [None, 22]):
                with self.subTest(samples=samples), patch.object(
                    stage, "psi", side_effect=samples
                ):
                    with self.assertRaisesRegex(ValueError, "CPU_PSI_GATE_NOT_READY"):
                        stage.check_psi()
            self.assertTrue(sleepy.called)

    def test_cpu_gate_accepts_two_low_psi_samples(self):
        with patch.object(stage.time, "sleep") as sleepy, patch.object(
            stage, "psi", side_effect=[22.1, 26.8]
        ):
            self.assertEqual(stage.check_psi(), (22.1, 26.8))
            sleepy.assert_called_once_with(10)

    def test_baseline_sha_pins_exact_stage4f_files(self):
        self.assertEqual(
            stage.PINNED_SHA[stage.BASE],
            "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354",
        )
        self.assertEqual(
            stage.PINNED_SHA[stage.OVERRIDE],
            "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
        )
        self.assertNotIn("18769", stage.STAGE4A_OVERRIDE)
        self.assertNotIn("18770", stage.STAGE4A_OVERRIDE)

    def test_docker_build_network_off_and_no_pull(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(stage.build_image))
        words = ast.dump(tree)
        self.assertIn("none", words)
        self.assertIn("pull=false", words)
        self.assertIn("quiet", words)
        self.assertNotIn("force-recreate", words)


if __name__ == "__main__":
    unittest.main()
