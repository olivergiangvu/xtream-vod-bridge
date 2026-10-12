"""Pure parsing checks for the read-only Linux preflight script."""
import unittest
from scripts.preflight_homedocker import docker_claims_port, listens_on


class PreflightParsingTests(unittest.TestCase):
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
