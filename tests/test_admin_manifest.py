"""Read-only private addon manifest URL and UI confidentiality regressions."""
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote
import unittest

from fastapi.testclient import TestClient
import admin_ui
import app as bridge

ROOT = Path(__file__).resolve().parents[1]


class ManifestAdminTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)
        self.key = "test-addon-secret+with/slash"
        self.auth = {"Authorization": "Bearer " + "b" * 40}

    def test_private_manifest_requires_existing_admin_authorization(self):
        with patch.object(bridge, "PUBLIC", "https://example.invalid:18450"), \
             patch.object(bridge, "ADDON_TOKEN", self.key):
            anon = self.client.get("/api/manifest")
            self.assertEqual(anon.status_code, 401)
            self.assertNotIn(self.key, anon.text)
            html = self.client.get("/").text
            js = self.client.get("/assets/app.js").text
            self.assertNotIn(self.key, html)
            self.assertNotIn(self.key, js)
            self.assertNotIn("/a/" + quote(self.key, safe=""), html)

    def test_manifest_url_only_in_authorized_no_store_response(self):
        with patch.object(bridge, "PUBLIC", "https://example.invalid:18450"), \
             patch.object(bridge, "ADDON_TOKEN", self.key), \
             patch.object(bridge, "MOVIES_ONLY", False):
            resp = self.client.get("/api/manifest", headers=self.auth)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(
                resp.json()["url"],
                "https://example.invalid:18450/a/" + quote(self.key, safe="") + "/manifest.json",
            )
            self.assertEqual(resp.json()["types"], ["movie", "series"])
            self.assertEqual(resp.headers["Cache-Control"], "no-store")
            self.assertEqual(resp.headers["Referrer-Policy"], "no-referrer")
            self.assertNotIn(self.key, self.client.get("/").text)

    def test_absent_or_insecure_addon_configuration_fails_closed(self):
        cases = [
            ("http://example.invalid", "some-secret"),
            ("https://example.invalid", ""),
            ("https://user:pass@example.invalid", "some-secret"),
            ("https://example.invalid/?q=secret", "some-secret"),
        ]
        for public, token in cases:
            with self.subTest(public=public):
                with patch.object(bridge, "PUBLIC", public), \
                     patch.object(bridge, "ADDON_TOKEN", token):
                    r = self.client.get("/api/manifest", headers=self.auth)
                    self.assertEqual(r.status_code, 503)
                    if token:
                        self.assertNotIn(token, r.text)

    def test_manifest_ui_requires_explicit_reveal_and_never_stores_token(self):
        html = (ROOT / "admin/index.html").read_text()
        js = (ROOT / "admin/assets/app.js").read_text()
        self.assertIn('id="manifestUrl" type="password"', html)
        self.assertIn('id="manifestReveal"', html)
        self.assertIn('id="manifestCopy"', html)
        self.assertIn("navigator.clipboard.writeText(privateManifest)", js)
        self.assertIn("input.value = revealed ? privateManifest : ''", js)
        self.assertIn("manifestEpoch += 1", js)
        self.assertIn("if (epoch !== manifestEpoch) return", js)
        self.assertIn("void prepareManifest()", js)
        self.assertIn("concealManifest()", js)
        self.assertNotIn("localStorage.setItem", js)
        self.assertNotIn("sessionStorage.setItem", js)


if __name__ == "__main__":
    unittest.main()
