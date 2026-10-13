"""No-network regression gates for nginx /admin/ on an existing public port.

Nginx is external to this test: simulate its trailing-slash prefix removal
and assert the FastAPI backend and relative browser paths still function.
"""
import pathlib
import re
import unittest
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from fastapi.testclient import TestClient

import admin_ui


ROOT = pathlib.Path(__file__).resolve().parents[1]
NGINX = ROOT / "nginx-admin-18450.location.conf"
HTML = ROOT / "admin" / "index.html"
JS = ROOT / "admin" / "assets" / "app.js"


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "link" and "href" in d:
            self.refs.append(d["href"])
        if tag == "script" and "src" in d:
            self.refs.append(d["src"])


class AdminPrefixTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(admin_ui.console)

    def tearDown(self):
        self.client.close()

    def test_static_assets_work_at_direct_root_and_https_admin_prefix(self):
        parser = Assets()
        parser.feed(HTML.read_text(encoding="utf-8"))
        self.assertIn("assets/app.js", parser.refs)
        self.assertIn("assets/style.css", parser.refs)
        for origin in (
            "http://127.0.0.1:18768/",
            "https://olivergiangvu.asuscomm.com:18450/admin/",
        ):
            for asset in parser.refs:
                browser = urljoin(origin, asset)
                prefix = urlsplit(origin).path
                self.assertTrue(browser.startswith(origin), browser)
                # nginx proxy_pass /admin/ -> /, with a trailing slash.
                backend_path = urlsplit(browser).path.removeprefix(
                    prefix.rstrip("/") if prefix != "/" else ""
                )
                response = self.client.get(backend_path)
                self.assertEqual(response.status_code, 200, (browser, backend_path))
                self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_admin_api_auth_retained_under_prefix_rewrite(self):
        for remote in ("/api/overview", "/admin/api/overview"):
            upstream = remote.removeprefix("/admin")
            self.assertEqual(self.client.get(upstream).status_code, 401)
            self.assertEqual(
                self.client.put(upstream.replace("overview", "settings"),
                                json={"source_label": "Injected"}).status_code,
                401,
            )

    def test_api_url_resolution_works_for_both_access_modes(self):
        js = JS.read_text(encoding="utf-8")
        self.assertIn("new URL('api/', document.baseURI)", js)
        self.assertIn("fetch(new URL(suffix, adminApiRoot)", js)
        self.assertNotIn("fetch(path, {", js)
        for origin, expected in (
            ("http://127.0.0.1:18768/",
             "http://127.0.0.1:18768/api/overview"),
            ("https://olivergiangvu.asuscomm.com:18450/admin/",
             "https://olivergiangvu.asuscomm.com:18450/admin/api/overview"),
        ):
            self.assertEqual(urljoin(urljoin(origin, "api/"), "overview"), expected)

    def test_nginx_does_not_change_manifest_playback_or_listener(self):
        snippet = NGINX.read_text(encoding="utf-8")
        active = "\n".join(
            line for line in snippet.splitlines()
            if not line.strip().startswith("#")
        )
        self.assertRegex(active, r"location\s+\^~\s+/admin/\s*\{")
        self.assertRegex(active, r"location\s+=\s+/admin\s*\{")
        self.assertIn("proxy_pass http://127.0.0.1:18768/;", active)
        self.assertIn("allow 192.168.50.0/24;", active)
        self.assertIn("deny all;", active)
        self.assertIn("access_log off;", active)
        self.assertNotIn("listen ", active)
        self.assertNotIn("server {", active)
        self.assertNotIn("0.0.0.0:18768", active)
        self.assertNotRegex(active, r"location[^\n]+/(?:play|a)/")
        self.assertNotIn("proxy_pass http://127.0.0.1:18767", active)

    def test_main_and_admin_compose_image_tags_are_identical(self):
        compose = (ROOT / "compose.yaml").read_text(encoding="utf-8")
        main = compose.split("  xtream-vod-bridge:", 1)[1].split("  xtream-vod-admin:", 1)[0]
        admin = compose.split("  xtream-vod-admin:", 1)[1]
        def image(block):
            return next(line.partition(": ")[2] for line in block.splitlines()
                        if line.startswith("    image: "))
        self.assertEqual(image(main), image(admin))
        self.assertEqual(image(admin), "homedocker/xtream-vod-bridge:0.4.2")

    def test_prefix_ui_does_not_include_sensitive_tokens(self):
        html = self.client.get("/")
        self.assertEqual(html.status_code, 200)
        self.assertNotIn("ADMIN_TOKEN=", html.text)
        self.assertNotIn("XTREAM_PASSWORD=", html.text)
        self.assertEqual(html.headers["Content-Security-Policy"].count("script-src"), 1)
        self.assertEqual(self.client.get("/assets/app.js").status_code, 200)


if __name__ == "__main__":
    unittest.main()
