"""Regression: fingerprint-only probes must never negotiate TLS 1.0/1.1."""
import hashlib
import importlib.util
import ssl
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


class GatewayTLSFloorTests(unittest.TestCase):
    def test_fingerprint_probe_requires_tls12_or_newer(self):
        module_path = Path(__file__).resolve().parents[1] / "scripts" / "install_safari_form_gateway.py"
        spec = importlib.util.spec_from_file_location("gateway_tls_preflight", module_path)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)

        ctx = MagicMock()
        raw = MagicMock()
        conn = ctx.wrap_socket.return_value.__enter__.return_value
        conn.getpeercert.return_value = b"offline-test-cert"

        with patch.object(installer.ssl, "SSLContext", return_value=ctx) as context_factory, \
             patch.object(installer.socket, "create_connection", return_value=raw):
            actual = installer.tls_fingerprint()

        context_factory.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(ctx.check_hostname, False)
        ctx.wrap_socket.assert_called_once_with(raw.__enter__.return_value, server_hostname=installer.DOMAIN)
        self.assertEqual(actual, hashlib.sha256(b"offline-test-cert").hexdigest())


if __name__ == "__main__":
    unittest.main()
