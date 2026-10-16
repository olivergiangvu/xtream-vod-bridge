"""No-network unit tests for read-only nginx preflight parser."""
import tempfile
import unittest
from pathlib import Path

from canary import stage4b_preflight as preflight


class Stage4BReadOnlyPreflightTests(unittest.TestCase):
    def test_find_live_domain_cert_from_nested_nginx_server(self):
        with tempfile.TemporaryDirectory() as dirname:
            cert = Path(dirname) / "fullchain.pem"
            key = Path(dirname) / "privkey.pem"
            cert.write_text("fake certificate (not a real key)")
            key.write_text("fake placeholder (not a real key)")
            config = (
                "http {\n"
                " server {\n"
                "  listen 18450 ssl;\n"
                "  server_name homedocker.local;\n"
                "  ssl_certificate /none;\n"
                "  ssl_certificate_key /none;\n"
                "  location /admin { return 404; }\n"
                " }\n"
                " server {\n"
                "  listen 18450 ssl;\n"
                "  server_name olivergiangvu.asuscomm.com;\n"
                f"  ssl_certificate {cert};\n"
                f"  ssl_certificate_key {key};\n"
                "  location ^~ /admin/ {\n"
                "    proxy_set_header Host $http_host;\n"
                "    auth_request /__xtream_admin_gate_check;\n"
                "  }\n"
                " }\n"
                "}\n"
            )
            blocks = preflight.server_blocks(config)
            self.assertEqual(len(blocks), 2)
            self.assertEqual(preflight.production_tls(config), (str(cert), str(key)))

    def test_other_host_or_missing_tls_fails_closed(self):
        config = (
            "server {\nlisten 18450 ssl;\n"
            "server_name example.org;\n"
            "ssl_certificate /foo;\nssl_certificate_key /bar;\n}\n"
        )
        with self.assertRaisesRegex(ValueError, "exactly one"):
            preflight.production_tls(config)

    def test_nginx_comments_not_confused_with_locations(self):
        raw = (
            "server { # braces } fake\n"
            " # server { fake block\n"
            " location ~ ^/a/[a-z]{1,5}/ { proxy_pass http://127.0.0.1; }\n"
            "}\n"
        )
        blocks = preflight.server_blocks(raw)
        self.assertEqual(len(blocks), 1)
        self.assertIn("proxy_pass", blocks[0])
        self.assertEqual(preflight._strip_comments(' listen 18450 ssl; # ignore'), ' listen 18450 ssl; ')


if __name__ == "__main__":
    unittest.main()
