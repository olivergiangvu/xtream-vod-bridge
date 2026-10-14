"""Stage 4D offline-only security and exact rollback regression tests."""
import hashlib
import re
import unittest

from canary import stage4d_route_review as review


SOURCE = (
    "server {\n"
    "  listen 18450 ssl;\n"
    "  server_name olivergiangvu.asuscomm.com;\n"
    "  location ^~ /admin/ {\n"
    "    auth_request /__xtream_admin_gate_check;\n"
    "  }\n"
    "  location / { return 404; }\n"
    "}\n"
)
TEMPLATE = (
    "# review-only\n"
    "location = /__xtream_canary_admin_gate_check { internal;"
    " proxy_pass http://__CANARY_ADMIN_IP__:8768/api/auth/gate-check; }\n"
    "location ^~ /canary/admin/ { allow __CANARY_LAN_CIDR__; deny all;"
    " auth_request /__xtream_canary_admin_gate_check;"
    " proxy_pass http://__CANARY_ADMIN_IP__:8768/; }\n"
    "location ^~ /canary/admin-signin/ { allow __CANARY_LAN_CIDR__;"
    " deny all; proxy_pass http://__CANARY_ADMIN_IP__:8768/gateway/; }\n"
    "location ^~ /canary/a/ { allow __CANARY_LAN_CIDR__; deny all;"
    " proxy_pass http://__CANARY_PLAY_IP__:8767/a/; }\n"
    "location ^~ /canary/play/ { allow __CANARY_LAN_CIDR__; deny all;"
    " proxy_pass http://__CANARY_PLAY_IP__:8767/play/; }\n"
    "location ^~ /canary/ { return 404; }\n"
)


class Stage4DTests(unittest.TestCase):
    def test_production_source_is_exactly_reversible(self):
        new, routes, added = review.render(
            SOURCE, TEMPLATE, "172.30.0.3", "172.30.0.2"
        )
        self.assertEqual(new.replace(added, "", 1), SOURCE)
        self.assertEqual(
            hashlib.sha256(new.replace(added, "", 1).encode()).hexdigest(),
            hashlib.sha256(SOURCE.encode()).hexdigest(),
        )
        self.assertEqual(new.count(added), 1)
        self.assertIn(
            "include /etc/nginx/snippets/xtream-canary-18450.conf;",
            new,
        )
        self.assertNotIn("__CANARY_", routes)
        self.assertIn("allow 192.168.50.0/24;", routes)
        self.assertIn("proxy_pass http://172.30.0.3:8768/gateway/;", routes)
        self.assertIn("proxy_pass http://172.30.0.2:8767/play/;", routes)

    def test_refuse_duplicate_or_drifted_production_routes(self):
        mutations = [
            SOURCE + SOURCE,
            SOURCE.replace("ssl;", "http2;"),
            SOURCE.replace("auth_request /__xtream_admin_gate_check", "auth_request off"),
            SOURCE.replace("server {", "http {"),
            SOURCE.replace("location / {", "location ^~ /canary/play/ {"),
        ]
        for mutation in mutations:
            with self.subTest(source=mutation[:70]):
                with self.assertRaises(ValueError):
                    review.render(mutation, TEMPLATE, "172.30.0.3", "172.30.0.2")

    def test_refuse_bad_upstreams_or_missing_access_controls(self):
        with self.assertRaises(ValueError):
            review.render(SOURCE, TEMPLATE, "8.8.8.8", "172.30.0.2")
        with self.assertRaises(ValueError):
            review.render(SOURCE, TEMPLATE, "172.30.0.2", "172.30.0.2")
        with self.assertRaises(ValueError):
            review.render(
                SOURCE, TEMPLATE.replace("deny all;", "", 1),
                "172.30.0.3", "172.30.0.2",
            )
        with self.assertRaises(ValueError):
            review.render(
                SOURCE, TEMPLATE.replace("__CANARY_LAN_CIDR__", "0.0.0.0/0"),
                "172.30.0.3", "172.30.0.2",
            )

    def test_real_repository_template_nginx_syntax_when_available(self):
        import shutil
        import subprocess
        import tempfile
        from pathlib import Path

        template_path = (Path(__file__).resolve().parents[1]
                         / "canary/xtream-canary-18450.nginx.template")
        template = template_path.read_text(encoding="utf-8")
        _, routes, _ = review.render(
            SOURCE, template, "172.30.0.3", "172.30.0.2"
        )
        self.assertEqual(routes.count("allow 192.168.50.0/24;"), 4)
        self.assertEqual(routes.count("deny all;"), 4)
        self.assertEqual(routes.count("internal;"), 1)
        if not shutil.which("nginx"):
            self.skipTest("nginx binary unavailable in CI")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "routes.conf").write_text(routes, encoding="utf-8")
            (root / "nginx.conf").write_text(
                "worker_processes 1;\n"
                f"pid {root / 'nginx.pid'};\n"
                "events { worker_connections 64; }\n"
                f"http {{ access_log off; server {{ listen 127.0.0.1:18888;"
                f" include {root / 'routes.conf'}; }} }}\n",
                encoding="utf-8",
            )
            check = subprocess.run(
                ["nginx", "-t", "-c", str(root / "nginx.conf"), "-p", td + "/"],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(check.returncode, 0, check.stderr)

    def test_git_blob_sha_matches_documented_git_algorithm(self):
        self.assertEqual(
            review.git_blob_sha(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )


if __name__ == "__main__":
    unittest.main()
