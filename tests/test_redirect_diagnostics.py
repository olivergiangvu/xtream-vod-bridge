"""Offline tests for provider redirect diagnostics without using IPTV credentials."""
import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / "scripts" / "inspect_provider_redirects.py"
spec = importlib.util.spec_from_file_location("redirect_diagnostics", PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RedirectDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.base = "https://provider.example:8080"
        self.patch = patch.object(module.bridge, "BASE", self.base)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_foreign_cdn_is_reported_without_path_or_tokens(self):
        result = module.redirect_details(
            self.base + "/movie/user/password/123.mp4",
            "https://cdn.example/video/123.mp4?token=secret",
        )
        self.assertEqual(result["redirect_target"], "cdn.example")
        self.assertEqual(result["allowed"], "False")
        self.assertNotIn("secret", repr(result))
        self.assertNotIn("password", repr(result))
        self.assertNotIn("/video/", repr(result))

    def test_same_origin_relative_redirect(self):
        result = module.redirect_details(
            self.base + "/movie/user/password/123.mp4",
            "/movie/file/123.mp4",
        )
        self.assertEqual(result["allowed"], "True")

    def test_scheme_downgrade_is_rejected(self):
        result = module.redirect_details(
            self.base + "/movie/user/password/123.mp4",
            "http://provider.example:8080/movie/video.mp4",
        )
        self.assertEqual(result["reason"], "https_downgrade")
        self.assertEqual(result["allowed"], "False")

    def test_private_addresses_are_redacted(self):
        self.assertEqual(module.safe_host_name("127.0.0.1"), "(non-public-address)")
        self.assertEqual(module.safe_host_name("192.168.1.1"), "(non-public-address)")


if __name__ == "__main__":
    unittest.main()
