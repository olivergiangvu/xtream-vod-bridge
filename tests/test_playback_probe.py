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

    def test_descriptive_movie_filename_url(self):
        url = (self.base + "/play/movie/28369/tt1234567/1792005348/"
               + "a" * 64 + "/Zootopia.2.2025.mkv")
        result = probe.playback_path(url, self.base)
        self.assertTrue(result.endswith("/Zootopia.2.2025.mkv"))
        self.assertNotIn("?", result)

    def test_descriptive_anime_filename_url(self):
        url = (self.base + "/play/movie/42/anilist-999/1792005348/"
               + "b" * 64 + "/Anime.Title.2025.mkv")
        self.assertIn("Anime.Title", probe.playback_path(url, self.base))

    def test_descriptive_path_rejects_missing_signature(self):
        url = self.base + "/play/movie/28369/tt1234567/1792005348/no/Zootopia.2.mkv"
        with self.assertRaises(ValueError):
            probe.playback_path(url, self.base)

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


class ReadinessWaitTests(unittest.TestCase):
    def test_transient_502_then_200(self):
        responses = iter((502, 503, 200))
        delays = []
        result = probe.wait_for_health(
            lambda: next(responses), attempts=4,
            pause_seconds=1, sleeper=delays.append,
        )
        self.assertEqual(result, (200, 3))
        self.assertEqual(delays, [1, 1])

    def test_denied_health_returns_immediately(self):
        delays = []
        result = probe.wait_for_health(
            lambda: 403, attempts=10,
            sleeper=delays.append,
        )
        self.assertEqual(result, (403, 1))
        self.assertEqual(delays, [])

    def test_backend_unavailable_is_bounded(self):
        result = probe.wait_for_health(
            lambda: 502, attempts=3,
            sleeper=lambda _: None,
        )
        self.assertEqual(result, (502, 3))

    def test_connection_refused_then_healthy(self):
        responses = iter((ConnectionRefusedError(), 200))

        def checker():
            status = next(responses)
            if isinstance(status, Exception):
                raise status
            return status

        result = probe.wait_for_health(
            checker, attempts=3, sleeper=lambda _: None
        )
        self.assertEqual(result, (200, 2))


if __name__ == "__main__":
    unittest.main()
