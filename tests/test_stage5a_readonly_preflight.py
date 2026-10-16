"""Stage5A read-only readiness: Compose isolation & runtime port regression tests."""
import copy
import unittest
from unittest.mock import patch

from canary import stage5a_readonly_preflight as stage


def safe_config():
    services = {}
    for service, (name, image) in stage.SERVICES.items():
        services[service] = {
            "image": image, "container_name": name,
            "networks": {"private_canary": None},
            "ports": [],
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "privileged": False,
            "read_only": True,
            "restart": "no",
            "volumes": [{
                "type": "bind",
                "target": "/data",
                "source": str(stage.ROOT / "data"),
            }],
        }
    return {
        "services": services,
        "networks": {
            "private_canary": {
                "name": stage.NETWORK, "internal": True,
                "external": False,
            }
        },
    }


class Stage5AReadOnlyTests(unittest.TestCase):
    def test_strict_safe_compose(self):
        self.assertTrue(stage.check_effective_compose(safe_config()))

    def test_composed_ports_or_other_network_must_stop(self):
        scenarios = [
            lambda x: x["services"]["xtream-vod-admin"].update({
                "ports": [{"target": 8768, "published": "18770",
                           "host_ip": "127.0.0.1"}]}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "ports": [{"target": 8767, "published": "18769"}]}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "networks": {"default": None}}),
            lambda x: x["networks"]["private_canary"].update({
                "internal": False}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "privileged": True}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "read_only": False}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "cap_drop": []}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "volumes": [{"type": "bind", "target": "/data",
                             "source": "/etc"}]}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "restart": "always"}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "image": "custom/not-approved:latest"}),
        ]
        for idx, scenario in enumerate(scenarios):
            with self.subTest(scenario=idx):
                cfg = copy.deepcopy(safe_config())
                scenario(cfg)
                with self.assertRaises(ValueError):
                    stage.check_effective_compose(cfg)

    def test_dormant_ports_are_reported_but_not_live(self):
        for name, internal, published in [
            ("xtream-vod-canary-admin", "8768/tcp", "18770"),
            ("xtream-vod-canary-playback", "8767/tcp", "18769"),
        ]:
            obj = {
                "HostConfig": {
                    "PortBindings": {
                        internal: [{
                            "HostIp": "127.0.0.1", "HostPort": published
                        }]
                    }
                },
                "NetworkSettings": {
                    "Ports": {"8767/tcp": None, "8768/tcp": None}
                },
            }
            with patch.object(stage, "execute", return_value=""):
                self.assertEqual(stage.check_live_ports(obj, name), 1)

    def test_live_or_nonloopback_port_stops(self):
        data = {
            "HostConfig": {"PortBindings": {}},
            "NetworkSettings": {"Ports": {"8768/tcp": [
                {"HostIp": "127.0.0.1", "HostPort": "18770"}]}},
        }
        with self.assertRaises(ValueError):
            stage.check_live_ports(data, "xtream-vod-canary-admin")
        data["NetworkSettings"]["Ports"] = {"8768/tcp": None}
        data["HostConfig"]["PortBindings"] = {
            "8768/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18770"}]
        }
        with patch.object(stage, "execute", return_value=""):
            with self.assertRaises(ValueError):
                stage.check_live_ports(data, "xtream-vod-canary-admin")

    def test_docker_port_output_stops(self):
        data = {
            "HostConfig": {"PortBindings": {}},
            "NetworkSettings": {"Ports": {"8768/tcp": None}},
        }
        with patch.object(stage, "execute", return_value="8768/tcp -> 127.0.0.1:18770"):
            with self.assertRaises(ValueError):
                stage.check_live_ports(data, "xtream-vod-canary-admin")

    def test_pinned_rollback_and_canary_sha(self):
        self.assertEqual(stage.EXPECTED_SHA[stage.BASE],
                         "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354")
        self.assertEqual(stage.EXPECTED_SHA[stage.BACKUP],
                         "79d4cb76db03ae881769339e4e2b851e1c68c1e1bb6133a62661dbdbca49a42e")


if __name__ == "__main__":
    unittest.main()
