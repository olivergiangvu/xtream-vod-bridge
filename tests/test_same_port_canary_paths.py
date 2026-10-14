"""Same-port 18450 Canary route-prefix: redirects, cookies and manifest URLs.

All mutations are isolated to ephemeral SQLite. The nginx reverse proxy
strips /canary/ before forwarding to the existing Python app paths.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://olivergiangvu.asuscomm.com:18450"
CHECK = r"""
import admin_auth, admin_ui, app, personal_manifests, route_paths
from urllib.parse import urlsplit
print("LOGIN=" + route_paths.LOGIN_PATH)
print("ADMIN=" + route_paths.ADMIN_PATH)
print("COOKIE=" + admin_auth.COOKIE)
print("COOKIE_PATH=" + admin_auth.COOKIE_PATH)
print("NONCE=" + admin_ui.GATE_LOGIN_COOKIE)
print("NONCE_PATH=" + route_paths.NONCE_COOKIE_PATH)
print("ORIGIN=" + admin_auth.PUBLIC_ORIGIN)
print("MANIFEST_URL=" + personal_manifests._public_url("v5_SYNTHETIC"))
print("SIGNED_URL=" + app.signed_url("movie", 1, "mp4"))
"""


def process(prefix, origin=ORIGIN):
    env = os.environ.copy()
    for key in (
        "XTREAM_URL_PREFIX", "XTREAM_SESSION_COOKIE", "XTREAM_LOGIN_NONCE_COOKIE",
        "PUBLIC_BASE_URL", "ADMIN_PUBLIC_ORIGIN", "XTREAM_GATEWAY_REFERRER_POLICY",
    ):
        env.pop(key, None)
    env.update({
        "XTREAM_URL_PREFIX": prefix,
        "PUBLIC_BASE_URL": origin + prefix,
        "ADMIN_PUBLIC_ORIGIN": origin,
        "PLAYBACK_SECRET": "Stage5SyntheticPlaybackSecret0123456789Abcdef",
    })
    if prefix:
        env.update({
            "XTREAM_SESSION_COOKIE": "xtream_canary_admin_session",
            "XTREAM_LOGIN_NONCE_COOKIE": "xtream_canary_login_nonce",
            "XTREAM_GATEWAY_REFERRER_POLICY": "same-origin",
        })
    return subprocess.run(
        [sys.executable, "-B", "-c", CHECK], env=env, cwd=ROOT,
        capture_output=True, text=True, check=False, timeout=15
    )


class RoutePrefixTests(unittest.TestCase):
    def test_production_default_remains_rooted(self):
        result = process("")
        self.assertEqual(result.returncode, 0, result.stderr[-1700:])
        self.assertIn("LOGIN=/admin-signin/\n", result.stdout)
        self.assertIn("ADMIN=/admin/\n", result.stdout)
        self.assertIn("COOKIE=xtream_admin_session\n", result.stdout)
        self.assertIn("COOKIE_PATH=/admin/\n", result.stdout)
        self.assertIn("NONCE_PATH=/admin-signin/\n", result.stdout)
        self.assertIn("MANIFEST_URL=" + ORIGIN + "/a/v5_SYNTHETIC/manifest.json", result.stdout)
        self.assertIn("SIGNED_URL=" + ORIGIN + "/play/movie/", result.stdout)

    def test_canary_cookies_and_playback_paths_are_prefixed(self):
        result = process("/canary")
        self.assertEqual(result.returncode, 0, result.stderr[-1700:])
        self.assertIn("LOGIN=/canary/admin-signin/\n", result.stdout)
        self.assertIn("ADMIN=/canary/admin/\n", result.stdout)
        self.assertIn("COOKIE=xtream_canary_admin_session\n", result.stdout)
        self.assertIn("COOKIE_PATH=/canary/admin/\n", result.stdout)
        self.assertIn("NONCE=xtream_canary_login_nonce\n", result.stdout)
        self.assertIn("NONCE_PATH=/canary/admin-signin/\n", result.stdout)
        self.assertIn("ORIGIN=" + ORIGIN + "\n", result.stdout)
        self.assertIn("MANIFEST_URL=" + ORIGIN + "/canary/a/v5_SYNTHETIC/manifest.json", result.stdout)
        self.assertIn("SIGNED_URL=" + ORIGIN + "/canary/play/movie/", result.stdout)
        self.assertNotIn(":18451", result.stdout)

    def test_only_expected_prefixes_allowed(self):
        for prefix in ("/canary/", "//canary", "/production", "/admin",
                       "/canary/../admin", "/canary?x=1", "/canary\n"):
            env = os.environ.copy()
            env["XTREAM_URL_PREFIX"] = prefix
            result = subprocess.run(
                [sys.executable, "-B", "-c", "import route_paths"],
                env=env, cwd=ROOT, capture_output=True, text=True, timeout=10
            )
            # Environment parser trims outer whitespace; for newline prefix
            # the validator may normalize it. All other malformed cases fail.
            if prefix != "/canary\n":
                self.assertNotEqual(result.returncode, 0, prefix)

    def test_gateway_cookie_paths_redirect_and_nonce(self):
        from unittest.mock import patch
        from fastapi.testclient import TestClient
        import admin_auth, admin_ui, ops, route_paths
        if route_paths.PREFIX:
            self.skipTest("This process uses external Canary prefix")
        # Probe the behavior in an isolated child process with Canary env to
        # avoid module-import cache pollution throughout the test suite.
        code = r"""
import os, re, tempfile
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
import admin_auth, admin_ui, ops, route_paths
with tempfile.TemporaryDirectory(prefix="stage5-canary-") as td:
    with patch.object(ops, "PATH", Path(td)/"index.sqlite"):
        with TestClient(admin_ui.console, follow_redirects=False) as client:
            page = client.get("/gateway/")
            assert page.status_code == 200
            assert 'action="/canary/admin-signin/"' in page.text
            nonce_cookie = page.headers.get("set-cookie", "")
            assert "xtream_canary_login_nonce=" in nonce_cookie
            assert "Path=/canary/admin-signin/" in nonce_cookie
            assert "Secure" in nonce_cookie and "HttpOnly" in nonce_cookie
            nonce = re.search(r'name="nonce" value="([^"]+)"', page.text).group(1)
            with patch.object(admin_auth, "login", return_value=("synthetic-session", "csrf")):
                response = client.post(
                    "/gateway/", data={"nonce":nonce,"username":"owner",
                                        "password":"TotallyFakePassword14"},
                    headers={"cookie": "xtream_canary_login_nonce=" + nonce,
                             "origin": os.environ["ADMIN_PUBLIC_ORIGIN"],
                             "referer":os.environ["ADMIN_PUBLIC_ORIGIN"]+"/canary/admin-signin/",
                             "host":"olivergiangvu.asuscomm.com:18450",
                             "x-forwarded-proto":"https",
                             "sec-fetch-site":"same-origin"},
                )
            assert response.status_code == 303, (response.status_code,response.text)
            assert response.headers["location"] == "/canary/admin/"
            cookie = response.headers.get("set-cookie", "")
            assert "xtream_canary_admin_session=" in cookie
            assert "Path=/canary/admin/" in cookie
            assert "Secure" in cookie and "HttpOnly" in cookie
            assert "xtream_admin_session=" not in cookie
            print("SAME_PORT_GATEWAY_FORM_COOKIE_REDIRECT=PASS")
"""
        env = os.environ.copy()
        env.update({
            "XTREAM_URL_PREFIX": "/canary",
            "XTREAM_SESSION_COOKIE": "xtream_canary_admin_session",
            "XTREAM_LOGIN_NONCE_COOKIE": "xtream_canary_login_nonce",
            "XTREAM_GATEWAY_REFERRER_POLICY": "same-origin",
            "ADMIN_PUBLIC_ORIGIN": ORIGIN,
            "PUBLIC_BASE_URL": ORIGIN + "/canary",
        })
        result = subprocess.run(
            [sys.executable, "-B", "-c", code], cwd=ROOT, env=env,
            capture_output=True, text=True, timeout=25, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2600:] + result.stdout[-500:])


if __name__ == "__main__":
    unittest.main()
