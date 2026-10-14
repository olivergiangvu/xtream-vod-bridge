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

    def test_https_sni_probe_uses_existing_port_and_validates_nonce(self):
        from unittest.mock import MagicMock
        context = MagicMock()
        dialed = MagicMock()
        tls = MagicMock()
        reply = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = tls
        dialed.__enter__.return_value = MagicMock()
        reply.status = 200
        reply.getheader.return_value = "text/html; charset=utf-8"
        reply.getheaders.return_value = [
            ("Set-Cookie", "xtream_admin_login_nonce=synthetic; Path=/admin-signin/; HttpOnly; Secure")
        ]
        reply.read.return_value = (
            b'<form action="/admin-signin/" method="post">'
            b'<input type="hidden" name="nonce" value="synthetic"></form>'
        )
        with patch.object(preflight.ssl, "create_default_context", return_value=context):
            with patch.object(preflight.socket, "create_connection", return_value=dialed) as dial:
                with patch.object(preflight.http.client, "HTTPResponse", return_value=reply):
                    self.assertTrue(preflight.verify_public_signin_https())
        dial.assert_called_once_with(("127.0.0.1", 18450), timeout=8)
        self.assertEqual(
            context.wrap_socket.call_args.kwargs["server_hostname"],
            "olivergiangvu.asuscomm.com",
        )
        request = tls.sendall.call_args.args[0]
        self.assertTrue(request.startswith(b"GET /admin-signin/ HTTP/1.1\r\n"))
        self.assertIn(
            b"Host: olivergiangvu.asuscomm.com:18450\r\n",
            request,
        )
        self.assertIn(b"\r\n\r\n", request)
        self.assertNotIn(b"password", request.lower())

    def test_https_signin_failure_refuses_unknown_login_routes(self):
        from unittest.mock import MagicMock
        context = MagicMock()
        dialed = MagicMock()
        tls = MagicMock()
        reply = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = tls
        reply.status = 302
        reply.getheader.return_value = "text/html"
        reply.getheaders.return_value = []
        reply.read.return_value = b"wrong login route"
        with patch.object(preflight.ssl, "create_default_context", return_value=context):
            with patch.object(preflight.socket, "create_connection", return_value=dialed):
                with patch.object(preflight.http.client, "HTTPResponse", return_value=reply):
                    with self.assertRaisesRegex(ValueError, "does not match secure Gateway"):
                        preflight.verify_public_signin_https()
        with patch.object(preflight.ssl, "create_default_context", return_value=context):
            with patch.object(preflight.socket, "create_connection",
                              side_effect=OSError("synthetic dial failure")):
                with self.assertRaisesRegex(ValueError, "HTTPS probe failed"):
                    preflight.verify_public_signin_https()

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
