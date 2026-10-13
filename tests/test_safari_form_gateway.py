"""Browser form gateway regression tests; no leaked password or basic-auth prompt."""
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import admin_auth
import admin_ui
import ops
from test_bridge import bridge

ORIGIN = "https://olivergiangvu.asuscomm.com:18450"
PASSWORD = "Test only very strong Admin password"


class SafariFormGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patches = [
            patch.object(ops, "PATH", Path(self.temp.name) / "index.sqlite"),
            patch.object(admin_auth, "PUBLIC_ORIGIN", ORIGIN),
            patch.object(admin_auth, "LAN_ORIGIN", ""),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        ops.init()
        admin_auth.init()
        admin_auth.set_password(PASSWORD)
        self.client = TestClient(admin_ui.console)
        self.addCleanup(self.client.close)

    def open_form(self):
        response = self.client.get("/gateway/")
        self.assertEqual(response.status_code, 200)
        self.assertIn('form-action &#x27;self&#x27;', response.headers.get("Content-Security-Policy", "").replace("'", "&#x27;"))
        self.assertIn('action="/admin-signin/"', response.text)
        self.assertIn("No separate nginx Gateway", response.text)
        self.assertNotIn(PASSWORD, response.text)
        nonce = re.search(r'name="nonce" value="([^"]+)"', response.text).group(1)
        self.assertIn("HttpOnly", response.headers["set-cookie"])
        self.assertIn("Secure", response.headers["set-cookie"])
        self.assertIn("SameSite=strict", response.headers["set-cookie"])
        self.assertIn("Path=/admin-signin/", response.headers["set-cookie"])
        return nonce

    def form_request(self, nonce, password=PASSWORD, origin=ORIGIN, extra_cookie=None):
        cookie = extra_cookie or (
            admin_ui.GATE_LOGIN_COOKIE + "=" + nonce
        )
        return self.client.post(
            "/gateway/", data={"password": password, "nonce": nonce},
            headers={"Origin": origin, "Cookie": cookie},
            follow_redirects=False
        )

    def test_cookie_session_redirect_and_gateway_check(self):
        nonce = self.open_form()
        logged = self.form_request(nonce)
        self.assertEqual(logged.status_code, 303)
        self.assertEqual(logged.headers["location"], "/admin/")
        session = logged.cookies.get(admin_auth.COOKIE)
        self.assertTrue(session)
        self.assertIn("HttpOnly", logged.headers["set-cookie"])
        self.assertIn("SameSite=strict", logged.headers["set-cookie"])
        self.assertIn("Path=/admin/", logged.headers["set-cookie"])
        no_cookie = self.client.get("/api/auth/gate-check")
        self.assertEqual(no_cookie.status_code, 401)
        good_cookie = {"Cookie": admin_auth.COOKIE + "=" + session}
        check = self.client.get("/api/auth/gate-check", headers=good_cookie)
        self.assertEqual(check.status_code, 204)
        dashboard_session = self.client.get("/api/auth/session", headers=good_cookie)
        self.assertTrue(dashboard_session.json()["authenticated"])
        self.assertTrue(dashboard_session.json()["csrf_token"])

    def test_login_rejects_forged_origin_nonce_and_password(self):
        nonce = self.open_form()
        self.assertEqual(self.form_request(nonce, origin="https://evil.invalid").status_code, 403)
        self.assertEqual(self.form_request(nonce, extra_cookie="bad_cookie=123").status_code, 403)
        bad = self.form_request(nonce, password="bad password phrase")
        self.assertEqual(bad.status_code, 401)
        self.assertNotIn("bad password phrase", bad.text)
        self.assertNotIn(PASSWORD, bad.text)

    def test_page_reuses_existing_session_and_password_lockout(self):
        nonce = self.open_form()
        logged = self.form_request(nonce)
        session = logged.cookies.get(admin_auth.COOKIE)
        r = self.client.get("/gateway/", headers={"Cookie": admin_auth.COOKIE + "=" + session},
                            follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.headers["location"], "/admin/")
        admin_auth.set_password("New long admin password 2026")
        self.assertEqual(self.client.get("/api/auth/gate-check",
                         headers={"Cookie": admin_auth.COOKIE + "=" + session}).status_code, 401)
        # Failed sign-ins use the same global lockout as the ordinary Admin UI.
        for _ in range(5):
            n = self.open_form()
            self.assertEqual(self.form_request(n, password="not-the-password").status_code, 401)
        n = self.open_form()
        self.assertEqual(self.form_request(n, password="New long admin password 2026").status_code, 429)

    def test_nginx_deployment_patcher_changes_only_admin_and_adds_internal_gate(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1] / "scripts" / "install_safari_form_gateway.py"
        spec = importlib.util.spec_from_file_location("nginx_gateway_deploy", path)
        loader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loader)
        original = '''server {
    listen 18450 ssl;
    server_name olivergiangvu.asuscomm.com;
    location ^~ /admin/ {
        # HomeDocker Safari Private Relay gateway v2 (Basic required for ALL clients)
        satisfy all;
        allow all;
        auth_basic "HomeDocker Admin Gateway";
        auth_basic_user_file /etc/nginx/xtream-vod-admin-secrets/xtream-admin-basic.htpasswd;
        proxy_pass http://127.0.0.1:18768/;
        proxy_http_version 1.1;
    }
    location ^~ /play/ { proxy_pass http://127.0.0.1:18767; }
    location /a/ { proxy_pass http://127.0.0.1:18767; }
}
'''
        with patch.object(loader, "SNIPPET", Path(self.temp.name) / "absent.conf"):
            updated = loader.build_config(original)
        self.assertIn("auth_request /__xtream_admin_gate_check;", updated)
        self.assertNotIn("auth_basic_user_file", updated)
        self.assertIn("location ^~ /play/ { proxy_pass http://127.0.0.1:18767; }", updated)
        self.assertIn("location /a/ { proxy_pass http://127.0.0.1:18767; }", updated)
        self.assertIn("location = /__xtream_admin_gate_check", loader.NGINX_SNIPPET)
        self.assertIn("internal;", loader.NGINX_SNIPPET)
        self.assertIn("location ^~ /admin-signin/", loader.NGINX_SNIPPET)
        self.assertIn("auth_basic off;", loader.NGINX_SNIPPET)


if __name__ == "__main__":
    unittest.main()
