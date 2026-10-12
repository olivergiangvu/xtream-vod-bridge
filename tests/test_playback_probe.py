"""Offline tests of the signed playback URL guard; no credentials or provider."""
import importlib.util
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "scripts" / "probe_playback.py"
spec = importlib.util.spec_from_file_location("playback_probe", FILE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class PlaybackPathTests(unittest.TestCase):
    def setUp(self):
        self.base = "https://olivergiangvu.asuscomm.com:18450"

    def test_accept_matching_https_origin(self):
        path = probe.playback_path(
            self.base + "/play/movie/123.mp4?exp=123456&sig=abc", self.base
        )
        self.assertEqual(path, "/play/movie/123.mp4?exp=123456&sig=abc")

    def test_reject_other_host(self):
        with self.assertRaises(ValueError):
            probe.playback_path(
                "https://other.example:18450/play/movie/123.mp4?exp=123&sig=abc",
                self.base,
            )

    def test_reject_other_port(self):
        with self.assertRaises(ValueError):
            probe.playback_path(
                "https://olivergiangvu.asuscomm.com:18451/play/movie/123.mp4?exp=123&sig=abc",
                self.base,
            )

    def test_reject_unsigned_and_admin_paths(self):
        for url in (
            self.base + "/play/movie/123.mp4",
            self.base + "/admin/refresh?exp=123&sig=abc",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    probe.playback_path(url, self.base)


if __name__ == "__main__":
    unittest.main()
