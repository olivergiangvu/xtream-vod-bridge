"""Pure parsing checks for the read-only Linux preflight script."""
import unittest
from scripts.preflight_homedocker import docker_claims_port, listens_on, public_base_url_ok


class PreflightParsingTests(unittest.TestCase):
    def test_both_root_port_and_prefix_public_https_are_supported(self):
        self.assertTrue(public_base_url_ok("https://example.org:18450"))
        self.assertTrue(public_base_url_ok("https://example.org/xtream-vod"))
        self.assertTrue(public_base_url_ok("https://example.org:18450/custom-prefix"))
        for url in ("http://example.org:18450", "https://user:pass@example.org/",
                    "https://example.org:bad", "https://example.org/?token=SECRET",
                    "https://example.org/#fragment", "https://example.org//double"):
            with self.subTest(url=url):
                self.assertFalse(public_base_url_ok(url))

    def test_ss_listener_detection(self):
        ss = "LISTEN 0 4096 127.0.0.1:18767 0.0.0.0:*\nLISTEN 0 128 [::]:443 [::]:*"
        self.assertTrue(listens_on(ss, 18767))
        self.assertFalse(listens_on(ss, 9000))

    def test_docker_published_port_detection(self):
        docker = "portainer|0.0.0.0:9000->9000/tcp\nbridge|127.0.0.1:18767->8767/tcp\nredis|6379/tcp"
        self.assertTrue(docker_claims_port(docker, 18767))
        self.assertFalse(docker_claims_port(docker, 6379))
        self.assertFalse(docker_claims_port(docker, 20000))


if __name__ == "__main__":
    unittest.main()
