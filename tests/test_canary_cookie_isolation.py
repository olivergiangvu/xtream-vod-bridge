"""Safari Canary :18451 must never reuse production :18450 cookie names.

Same-origin cookies do not include a port. These tests exercise a clean
Python import process with Canary env overrides, while default names remain
fully backward-compatible with v0.4 production.
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = (
    "import admin_auth, admin_ui; "
    "print('SESSION=' + admin_auth.COOKIE); "
    "print('NONCE=' + admin_ui.GATE_LOGIN_COOKIE)"
)


def probe(session=None, nonce=None):
    env = os.environ.copy()
    env.pop("XTREAM_SESSION_COOKIE", None)
    env.pop("XTREAM_LOGIN_NONCE_COOKIE", None)
    if session is not None:
        env["XTREAM_SESSION_COOKIE"] = session
    if nonce is not None:
        env["XTREAM_LOGIN_NONCE_COOKIE"] = nonce
    return subprocess.run(
        [sys.executable, "-B", "-c", CHECK],
        cwd=ROOT,
        env=env, text=True, capture_output=True, timeout=15,
        check=False,
    )


class CookiePortIsolation(unittest.TestCase):
    def test_legacy_production_names_unchanged(self):
        result = probe()
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn("SESSION=xtream_admin_session", result.stdout)
        self.assertIn("NONCE=xtream_admin_login_nonce", result.stdout)

    def test_canary_cookies_namespaced_for_same_hostname(self):
        result = probe(
            "xtream_canary_admin_session", "xtream_canary_login_nonce"
        )
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        self.assertIn("SESSION=xtream_canary_admin_session", result.stdout)
        self.assertIn("NONCE=xtream_canary_login_nonce", result.stdout)
        self.assertNotIn("SESSION=xtream_admin_session\n", result.stdout)
        self.assertNotIn("NONCE=xtream_admin_login_nonce\n", result.stdout)

    def test_invalid_or_colliding_names_fail_closed(self):
        for session, nonce in [
            ("__Host-xtream_session", "xtream_canary_login_nonce"),
            ("xtream_canary;evil", "xtream_canary_login_nonce"),
            ("xtream_canary_admin_session", "xtream_canary_admin_session"),
            ("xtream_canary_admin_session", "cross_origin_nonce"),
            ("xtream_canary_admin_session", "xtream_\nlogin"),
        ]:
            with self.subTest(session=session, nonce=nonce):
                result = probe(session, nonce)
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
