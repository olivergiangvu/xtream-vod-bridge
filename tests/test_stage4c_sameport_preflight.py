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
                      p.replace("auth_request /__xtream_admin_gate_check;", "auth_request off;")):
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "server.conf"
                path.write_text(vhost)
                sample = f"# configuration file {path}:\n" + vhost
                with patch.object(Path, "is_relative_to", return_value=True):
                    with self.assertRaises(ValueError):
                        preflight.find_server_config(sample)

    def test_route_mismatch_lists_safe_check_ids_only(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "test-vhost.conf"
            vhost = (
                "server {\n"
                " listen 18450 ssl;\n"
                " server_name olivergiangvu.asuscomm.com;\n"
                " location / { return 404; }\n"
                "}\n"
            )
            path.write_text(vhost)
            dump = f"# configuration file {path}:\n" + vhost
            with patch.object(Path, "is_relative_to", return_value=True):
                with self.assertRaisesRegex(
                    ValueError,
                    "admin_location,auth_request_gate"
                ):
                    preflight.find_server_config(dump)

    def test_signin_nginx_include_is_verified_by_live_sni_not_source_regex(self):
        # nginx -T lists included files in separate chunks. A sign-in
        # location defined by an include may be absent from this vhost's
        # physical text even though the real HTTPS route works.
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "vhost.conf"
            vhost = (
                "server {\n"
                " listen 18450 ssl;\n"
                " server_name olivergiangvu.asuscomm.com;\n"
                " location ^~ /admin/ { auth_request /__xtream_admin_gate_check; }\n"
                " include /etc/nginx/snippets/admin-gateway.conf;\n"
                " location / { return 404; }\n"
                "}\n"
            )
            path.write_text(vhost)
            with patch.object(Path, "is_relative_to", return_value=True):
                file, resolved, block = preflight.find_server_config(
                    f"# configuration file {path}:\n" + vhost
                )
            self.assertEqual(file, path)
            self.assertIn("admin-gateway.conf", block)
            self.assertNotIn("location ^~ /admin-signin/", block)

    def test_https_sni_probe_uses_curl_verified_tls_and_fixed_domain(self):
        from types import SimpleNamespace
        html = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Set-Cookie: xtream_admin_login_nonce=synthetic; Path=/admin-signin/; Secure; HttpOnly\r\n"
            "\r\n"
            '<form method="post" action="/admin-signin/">'
            '<input name="nonce" value="synthetic" type="hidden"></form>'
        )
        with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout=html, stderr=""
        )) as invoked:
            self.assertTrue(preflight.verify_public_signin_https("192.168.50.10"))
        args = invoked.call_args.args[0]
        self.assertEqual(args[0], "curl")
        self.assertIn("--resolve", args)
        self.assertIn(
            "olivergiangvu.asuscomm.com:18450:192.168.50.10",
            args,
        )
        self.assertIn("--noproxy", args)
        self.assertIn("--http1.1", args)
        self.assertIn("https://olivergiangvu.asuscomm.com:18450/admin-signin/", args)
        self.assertNotIn("--insecure", args)
        self.assertNotIn("-k", args)
        self.assertNotIn("--location", args)
        self.assertTrue(invoked.call_args.kwargs["capture_output"])
        self.assertLessEqual(invoked.call_args.kwargs["timeout"], 20)

    def test_https_signin_fail_closed_bad_response_or_tls(self):
        from types import SimpleNamespace
        cases = [
            (0, "HTTP/1.1 302 Found\r\n\r\n"),
            (0, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nMissing nonce"),
            (60, ""),
        ]
        for code, output in cases:
            with self.subTest(code=code, response=output[:25]):
                with patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
                    returncode=code, stdout=output, stderr="sensitive synthetic error"
                )):
                    with self.assertRaises(ValueError) as caught:
                        preflight.verify_public_signin_https("192.168.50.10")
                    self.assertNotIn("sensitive synthetic error", str(caught.exception))
        with patch.object(preflight.subprocess, "run") as invoked:
            with self.assertRaisesRegex(ValueError, "private IPv4"):
                preflight.verify_public_signin_https("8.8.8.8")
            invoked.assert_not_called()

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
