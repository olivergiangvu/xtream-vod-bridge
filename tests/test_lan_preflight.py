"""Read-only LAN HTTPS proxy preflight unit tests."""
import unittest
from unittest.mock import patch
from scripts import preflight_lan_admin as p


class LanAdminPreflightTests(unittest.TestCase):
    def test_probe_handles_closed_socket_without_exception(self):
        with patch.object(p.socket, "create_connection", side_effect=ConnectionRefusedError):
            self.assertFalse(p.probe_local_listener("192.168.50.153", 18769))

    def test_dns_requires_exact_lan_ip_not_public_hairpin(self):
        data = [
            (p.socket.AF_INET, p.socket.SOCK_STREAM, 6, "", ("192.168.50.153", 0)),
            (p.socket.AF_INET, p.socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
        ]
        with patch.object(p.socket, "getaddrinfo", return_value=data):
            self.assertTrue(p.resolve_to_lan("myhost.example", "192.168.50.153"))
            self.assertFalse(p.resolve_to_lan("myhost.example", "192.168.50.99"))

    def test_certificate_missing_fails_closed(self):
        from pathlib import Path
        self.assertFalse(p.cert_matches_hostname(Path("/missing/cert.pem"), "myhost.example"))

    def test_no_private_certificate_or_token_logging(self):
        import inspect
        source = inspect.getsource(p.main)
        self.assertIn("certificate_hostname_matches", source)
        self.assertNotIn('"cert_path":', source)
        self.assertNotIn('"key_path":', source)


if __name__ == "__main__":
    unittest.main()
