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
        # no-referrer sets Origin:null for native HTML form POST per Fetch.
        self.assertIn(
            '<meta name="referrer" content="strict-origin-when-cross-origin">',
            response.text
        )
        self.assertEqual(
            response.headers["Referrer-Policy"], "strict-origin-when-cross-origin"
        )
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

    def test_native_password_manager_form_fields(self):
        form = self.client.get("/gateway/")
        self.assertEqual(form.status_code, 200)
        html = form.text
        self.assertIn("<title>Sign in · Xtream VOD Bridge</title>", html)
        self.assertIn('name="username" type="text" value="owner"', html)
        self.assertIn('autocomplete="username"', html)
        self.assertIn('name="password" type="password"', html)
        self.assertIn('autocomplete="current-password"', html)
        self.assertIn('method="post" action="/admin-signin/" autocomplete="on"', html)
        self.assertIn('name="nonce"', html)
        self.assertIn("No separate nginx Gateway password", html)
        self.assertNotIn(PASSWORD, html)
        self.assertIn("script-src 'none'", form.headers["Content-Security-Policy"])

    def test_named_owner_login_and_wrong_username_counted(self):
        nonce = self.open_form()
        cookie = {admin_ui.GATE_LOGIN_COOKIE: nonce}
        wrong = self.client.post(
            "/gateway/",
            data={"username": "admin", "password": PASSWORD, "nonce": nonce},
            headers={"Origin": ORIGIN},
            cookies=cookie,
            follow_redirects=False,
        )
        self.assertEqual(wrong.status_code, 401)
        self.assertIn("Incorrect username or password", wrong.text)
        self.assertNotIn(PASSWORD, wrong.text)
        with ops.database() as con:
            guard = con.execute(
                "SELECT attempts FROM admin_login_guard WHERE id=1"
            ).fetchone()
        self.assertEqual(guard["attempts"], 1)

        unicode_name = self.client.post(
            "/gateway/",
            data={"username": "quản trị", "password": PASSWORD, "nonce": nonce},
            headers={"Origin": ORIGIN},
            cookies=cookie,
            follow_redirects=False,
        )
        self.assertEqual(unicode_name.status_code, 401)
        with ops.database() as con:
            attempts = con.execute(
                "SELECT attempts FROM admin_login_guard WHERE id=1"
            ).fetchone()["attempts"]
        self.assertEqual(attempts, 2)

        retry = self.client.get("/gateway/")
        fresh_nonce = re.search(
            r'name="nonce" value="([^"]+)"', retry.text
        ).group(1)
        success = self.client.post(
            "/gateway/",
            data={"username": "owner", "password": PASSWORD, "nonce": fresh_nonce},
            headers={"Origin": ORIGIN},
            cookies={admin_ui.GATE_LOGIN_COOKIE: fresh_nonce},
            follow_redirects=False,
        )
        self.assertEqual(success.status_code, 303)
        self.assertEqual(success.headers["location"], "/admin/")

    def test_json_login_preserves_password_only_clients(self):
        legacy = self.client.post(
            "/api/auth/login", json={"password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        self.assertEqual(legacy.status_code, 200)
        owner = self.client.post(
            "/api/auth/login", json={"username": "owner", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        self.assertEqual(owner.status_code, 200)
        wrong = self.client.post(
            "/api/auth/login", json={"username": "admin", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        self.assertEqual(wrong.status_code, 401)

    def test_non_login_admin_response_keeps_no_referrer(self):
        response = self.client.get("/api/auth/session")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")

    def test_nginx_login_referrer_header_and_one_time_patcher(self):
        import importlib.util
        root = Path(__file__).resolve().parents[1]
        installer = (root / "scripts" / "install_safari_form_gateway.py").read_text()
        self.assertIn(
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            installer
        )
        patcher_file = root / "scripts" / "fix_safari_login_referrer_policy.py"
        spec = importlib.util.spec_from_file_location("safari_referrer_fixer", patcher_file)
        fixer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixer)
        original = fixer.OLD + "\n"
        with patch.object(fixer, "SNIPPET", Path(self.temp.name) / "current.conf"):
            Path(fixer.SNIPPET).write_text(original)
            self.assertEqual(Path(fixer.SNIPPET).read_text().count(fixer.OLD), 1)
        self.assertEqual(
            fixer.login_policy("HTTP/1.1 200 OK\r\nReferrer-Policy: "
                               "strict-origin-when-cross-origin\r\n"),
            ["strict-origin-when-cross-origin"]
        )
        self.assertEqual(fixer.NEW.count("strict-origin-when-cross-origin"), 1)

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

    def test_lock_revokes_gateway_session_before_redirect(self):
        # Server-side revocation must be real; a UI-only hide is not Lock.
        nonce = self.open_form()
        logged = self.form_request(nonce)
        session = logged.cookies.get(admin_auth.COOKIE)
        cookie = {"Cookie": admin_auth.COOKIE + "=" + session}
        status = self.client.get("/api/auth/session", headers=cookie).json()
        self.assertTrue(status["authenticated"])

        denied = self.client.post("/api/auth/logout", headers=cookie)
        self.assertEqual(denied.status_code, 403)

        logout = self.client.post(
            "/api/auth/logout", headers={
                **cookie,
                "Origin": ORIGIN,
                "X-CSRF-Token": status["csrf_token"],
            },
        )
        self.assertEqual(logout.status_code, 200)
        self.assertIs(logout.json()["authenticated"], False)
        self.assertEqual(
            self.client.get("/api/auth/gate-check", headers=cookie).status_code,
            401,
        )

    def test_admin_lock_js_uses_single_public_gateway(self):
        js = (Path(__file__).resolve().parents[1] /
              "admin/assets/app.js").read_text()
        click = js.split("$('logout').addEventListener('click', async () => {", 1)[1]
        self.assertIn("api('/api/auth/logout', 'POST')", click)
        self.assertIn("result.authenticated !== false", click)
        self.assertIn("window.location.replace('/admin-signin/')", click)
        self.assertLess(
            click.index("result.authenticated !== false"),
            click.index("window.location.replace('/admin-signin/')"),
        )
        # The direct loopback/SSH UI retains its legacy form.
        self.assertIn("window.location.pathname.startsWith('/admin/')", click)
        self.assertIn("Lock failed:", click)

    def test_login_rejects_forged_origin_nonce_and_password(self):
        nonce = self.open_form()
        self.assertEqual(self.form_request(nonce, origin="https://evil.invalid").status_code, 403)
        self.assertEqual(self.form_request(nonce, extra_cookie="bad_cookie=123").status_code, 403)
        bad = self.form_request(nonce, password="bad password phrase")
        self.assertEqual(bad.status_code, 401)
        self.assertNotIn("bad password phrase", bad.text)
        self.assertNotIn(PASSWORD, bad.text)

    def test_safari_native_form_post_missing_origin_with_https_provenance(self):
        nonce = self.open_form()
        # Safari native POST may omit Origin and Referer when tracking
        # protection or Referrer-Policy: no-referrer is in effect.
        headers = {
            "Cookie": admin_ui.GATE_LOGIN_COOKIE + "=" + nonce,
            "Host": "olivergiangvu.asuscomm.com",
            "X-Forwarded-Proto": "https",
            "Sec-Fetch-Site": "same-origin",
        }
        ok = self.client.post("/gateway/", data={"password": PASSWORD, "nonce": nonce},
                              headers=headers, follow_redirects=False)
        self.assertEqual(ok.status_code, 303, ok.text)
        self.assertIn(admin_auth.COOKIE, ok.cookies)

        # The fallback must NEVER accept an explicit hostile Origin,
        # cross-site Fetch Metadata, untrusted Host, or an HTTP proxy.
        bad_headers = (
            {**headers, "Origin": "https://evil.invalid"},
            {**headers, "Sec-Fetch-Site": "cross-site"},
            {**headers, "Host": "attacker.invalid"},
            {**headers, "X-Forwarded-Proto": "http"},
            {**headers, "Referer": "https://evil.invalid/hack"},
        )
        for altered in bad_headers:
            r = self.client.post("/gateway/", data={"password": PASSWORD, "nonce": nonce},
                                 headers=altered, follow_redirects=False)
            self.assertEqual(r.status_code, 403, altered)

    def test_absent_origin_cannot_skip_independent_nonce(self):
        nonce = self.open_form()
        headers = {
            "Cookie": admin_ui.GATE_LOGIN_COOKIE + "=" + nonce,
            "Host": "olivergiangvu.asuscomm.com",
            "X-Forwarded-Proto": "https",
        }
        for missing_nonce, expected_status in (("forged", 403), ("", 400)):
            r = self.client.post("/gateway/",
                data={"password": PASSWORD, "nonce": missing_nonce},
                headers=headers, follow_redirects=False)
            self.assertEqual(r.status_code, expected_status)

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
