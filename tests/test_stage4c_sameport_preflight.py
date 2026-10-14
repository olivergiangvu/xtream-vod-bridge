"""Nginx :18450 preflight parser regressions; does not require local nginx."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from canary import stage4c_sameport_preflight as preflight


class SamePortPreflightTests(unittest.TestCase):
    def test_detect_public_https_vhost_and_file(self):
        with tempfile.TemporaryDirectory() as td:
            config_file = Path(td) / "xtream.conf"
            config_file.write_text("test vhost")
            sample = (
                "# configuration file /etc/nginx/nginx.conf:\nhttp {}\n"
                f"# configuration file {config_file}:\n"
                "server {\n"
                "listen 18450 ssl;\n"
                "server_name homedocker.local;\n"
                "location / { return 404; }\n"
                "}\n"
                "server {\n"
                "listen 18450 ssl;\n"
                "server_name olivergiangvu.asuscomm.com;\n"
                "location ^~ /admin/ {\n"
                "auth_request /__xtream_admin_gate_check;\n"
                "proxy_pass http://127.0.0.1:18768/;\n"
                "}\n"
                "location ^~ /admin-signin/ {\n"
                "proxy_pass http://127.0.0.1:18768/gateway/;\n"
                "}\n"
                "location / {\nproxy_pass http://127.0.0.1:18767;\n}\n"
                "}\n"
            )
            with patch.object(Path, "is_relative_to", return_value=True):
                original, resolved, block = preflight.find_server_config(sample)
            self.assertEqual(original, config_file)
            self.assertEqual(resolved, config_file.resolve())
            self.assertIn("location ^~ /admin-signin/", block)

    def test_reject_canary_or_unknown_gateway_layout(self):
        p = (
            "server {\nlisten 18450 ssl;\n"
            "server_name olivergiangvu.asuscomm.com;\n"
            "location ^~ /admin/ { auth_request /__xtream_admin_gate_check; }\n"
            "location ^~ /admin-signin/ { return 200; }\n"
            "location / { proxy_pass http://127.0.0.1:18767; }\n"
            "}\n"
        )
        for vhost in (p.replace("location / {", "location ^~ /canary/ { return 200; }\nlocation / {"),
                      p.replace("/admin-signin/", "/something-else/")):
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "server.conf"
                path.write_text(vhost)
                sample = f"# configuration file {path}:\n" + vhost
                with patch.object(Path, "is_relative_to", return_value=True):
                    with self.assertRaises(ValueError):
                        preflight.find_server_config(sample)

    def test_marker_and_comment_parser_preserve_quote(self):
        self.assertEqual(
            preflight.no_comments('  listen 18450 ssl; # comment'),
            '  listen 18450 ssl; ',
        )
        self.assertEqual(
            preflight.no_comments('set $header "#valid"; # comment'),
            'set $header "#valid"; ',
        )


if __name__ == "__main__":
    unittest.main()
