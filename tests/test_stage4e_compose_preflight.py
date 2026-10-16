"""Stage 4E read-only effective Compose and Docker port safety regressions."""
import copy
import unittest
from unittest.mock import patch

from canary import stage4e_compose_preflight as stage


def good_compose():
    services = {}
    for service, (container, image) in stage.SERVICES.items():
        services[service] = {
            "container_name": container, "image": image,
            "ports": [],
            "networks": {"private_canary": None},
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "restart": "no",
            "privileged": False,
            "volumes": [{
                "type": "bind",
                "source": str(stage.ROOT / "data"),
                "target": "/data",
            }],
        }
    return {
        "services": services,
        "networks": {
            "private_canary": {
                "internal": True,
                "name": stage.NETWORK,
            }
        },
    }


class Stage4EComposeTests(unittest.TestCase):
    def test_valid_stage4a_compose_model_has_no_published_ports(self):
        self.assertTrue(stage.validate_effective_config(good_compose()))

    def test_refuse_any_composed_port_or_public_network(self):
        mutators = [
            lambda x: x["services"]["xtream-vod-admin"].update({
                "ports": [{"published": "18770", "target": 8768,
                           "host_ip": "127.0.0.1"}]}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "ports": [{"published": "18769", "target": 8767}]}),
            lambda x: x["networks"]["private_canary"].update({"internal": False}),
            lambda x: x["services"]["xtream-vod-admin"].update({"networks": ["default"]}),
            lambda x: x["services"]["xtream-vod-bridge"].update({"privileged": True}),
            lambda x: x["services"]["xtream-vod-bridge"].update({"read_only": False}),
            lambda x: x["services"]["xtream-vod-admin"].update({"cap_drop": []}),
            lambda x: x["services"]["xtream-vod-bridge"].update({"security_opt": []}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "volumes": [{
                    "type": "bind", "source": "/etc", "target": "/data"
                }]}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "image": "unexpected/test:latest"}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "restart": "always"}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "network_mode": "host"}),
            lambda x: x["services"].update({"unexpected-service": {}}),
        ]
        for mutate in mutators:
            cfg = good_compose()
            mutate(cfg)
            with self.subTest(configuration=repr(cfg)[:100]):
                with self.assertRaises(ValueError):
                    stage.validate_effective_config(cfg)

    def test_real_homedocker_dormant_metadata_is_not_live_publication(self):
        data = [
            ("xtream-vod-canary-admin", "8768/tcp", "18770"),
            ("xtream-vod-canary-playback", "8767/tcp", "18769"),
        ]
        for name, port, host_port in data:
            obj = {
                "NetworkSettings": {"Ports": {
                    "8767/tcp": None, "8768/tcp": None}},
                "HostConfig": {"PortBindings": {port: [{
                    "HostIp": "127.0.0.1", "HostPort": host_port}]}},
            }
            with self.subTest(name=name):
                with patch.object(stage, "run", return_value=""):
                    self.assertEqual(stage.port_state(obj, name), 1)

    def test_effective_or_public_bind_is_refused(self):
        obj = {
            "NetworkSettings": {"Ports": {"8768/tcp": [{
                "HostIp": "127.0.0.1", "HostPort": "18770"}]}},
            "HostConfig": {"PortBindings": {}},
        }
        with self.assertRaisesRegex(ValueError, "Active Canary"):
            stage.port_state(obj, "xtream-vod-canary-admin")
        obj["NetworkSettings"]["Ports"] = {"8768/tcp": None}
        obj["HostConfig"]["PortBindings"] = {"8768/tcp": [{
            "HostIp": "0.0.0.0", "HostPort": "18770"}]}
        with patch.object(stage, "run", return_value=""):
            with self.assertRaisesRegex(ValueError, "Unsafe dormant"):
                stage.port_state(obj, "xtream-vod-canary-admin")

    def test_explicit_docker_port_output_refused(self):
        obj = {
            "NetworkSettings": {"Ports": {"8768/tcp": None}},
            "HostConfig": {"PortBindings": {}},
        }
        with patch.object(stage, "run", return_value="8768/tcp -> 127.0.0.1:18770"):
            with self.assertRaisesRegex(ValueError, "docker port"):
                stage.port_state(obj, "xtream-vod-canary-admin")

    def test_stage4a_override_exactness_is_pinned(self):
        self.assertIn("xtream_canary_admin_session", stage.STAGE4A_OVERRIDE)
        self.assertIn("https://olivergiangvu.asuscomm.com:18451",
                      stage.STAGE4A_OVERRIDE)
        self.assertNotIn("18770", stage.STAGE4A_OVERRIDE)
        self.assertNotIn("18769", stage.STAGE4A_OVERRIDE)

    def test_source_blob_algorithm(self):
        self.assertEqual(
            stage.git_blob(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )


if __name__ == "__main__":
    unittest.main()
