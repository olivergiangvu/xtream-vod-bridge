"""Stage 5A.3 read-only Compose candidate and rollback safety regression tests."""
import copy
import unittest
from canary import stage5a3_recreate_plan as stage


def make_model():
    services = {}
    for name, container in (
        ("xtream-vod-admin", "xtream-vod-canary-admin"),
        ("xtream-vod-bridge", "xtream-vod-canary-playback"),
    ):
        env = {
            "CREDENTIAL_FROM_ENV_FILE": "do-not-display",
            "PUBLIC_BASE_URL": "https://olivergiangvu.asuscomm.com:18451",
        }
        if name == "xtream-vod-admin":
            env.update(
                XTREAM_SESSION_COOKIE="xtream_canary_admin_session",
                XTREAM_LOGIN_NONCE_COOKIE="xtream_canary_login_nonce",
                XTREAM_GATEWAY_REFERRER_POLICY="same-origin",
                ADMIN_PUBLIC_ORIGIN="https://olivergiangvu.asuscomm.com:18451",
            )
        services[name] = {
            "container_name": container,
            "image": stage.OLD_ADMIN if name == "xtream-vod-admin" else stage.PLAY_IMAGE,
            "read_only": True,
            "privileged": False,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "networks": {"private_canary": None},
            "ports": [],
            "environment": env,
            "volumes": [{"type": "bind", "source": "/opt/xtream-vod-canary/data",
                         "target": "/data"}],
        }
    return {
        "name": "xtream-vod-canary",
        "networks": {
            "private_canary": {
                "name": stage.NETWORK,
                "internal": True,
                "external": False,
            },
        },
        "services": services,
    }


def make_after(before):
    after = copy.deepcopy(before)
    for service, env in stage.APPROVED_ENV_CHANGES.items():
        after["services"][service]["environment"].update(env)
    after["services"]["xtream-vod-admin"]["image"] = stage.NEW_ADMIN
    return after


class Stage5A3CandidateTests(unittest.TestCase):
    def test_exact_intended_candidate(self):
        self.assertEqual(
            stage.CANDIDATE.count("    image: " + stage.NEW_ADMIN), 1
        )
        self.assertNotIn("ports:", stage.CANDIDATE)
        self.assertNotIn("18769", stage.CANDIDATE)
        self.assertNotIn("18770", stage.CANDIDATE)
        self.assertNotIn("18451", stage.CANDIDATE)
        self.assertIn("XTREAM_URL_PREFIX: /canary", stage.CANDIDATE)
        self.assertTrue(stage.check_composed(make_model(), make_after(make_model())))

    def test_does_not_change_secret_env(self):
        before = make_model()
        after = make_after(before)
        self.assertEqual(
            after["services"]["xtream-vod-admin"]["environment"]["CREDENTIAL_FROM_ENV_FILE"],
            before["services"]["xtream-vod-admin"]["environment"]["CREDENTIAL_FROM_ENV_FILE"],
        )
        self.assertTrue(stage.check_composed(before, after))

    def test_reject_environment_secret_override(self):
        before = make_model()
        after = make_after(before)
        after["services"]["xtream-vod-bridge"]["environment"]["CREDENTIAL_FROM_ENV_FILE"] = "changed"
        with self.assertRaisesRegex(ValueError, "beyond"):
            stage.check_composed(before, after)

    def test_reject_new_host_ports(self):
        before = make_model()
        after = make_after(before)
        after["services"]["xtream-vod-admin"]["ports"] = [
            {"published": "18770", "target": 8768, "host_ip": "127.0.0.1"}
        ]
        with self.assertRaisesRegex(ValueError, "host ports"):
            stage.check_composed(before, after)

    def test_reject_nonprivate_network_and_privileged(self):
        for amend in (
            lambda x: x["networks"]["private_canary"].update(internal=False),
            lambda x: x["services"]["xtream-vod-bridge"].update(
                networks={"bridge": None}),
            lambda x: x["services"]["xtream-vod-admin"].update(
                privileged=True),
            lambda x: x["services"]["xtream-vod-admin"].update(read_only=False),
            lambda x: x["services"]["xtream-vod-admin"].update(
                cap_drop=[]),
            lambda x: x["services"]["xtream-vod-admin"].update(
                security_opt=[]),
        ):
            with self.subTest(amend=str(amend)):
                before = make_model()
                after = make_after(before)
                amend(after)
                with self.assertRaises(ValueError):
                    stage.check_composed(before, after)

    def test_reject_unapproved_image_or_volume(self):
        for key, value in (("image", "unknown:latest"),
                           ("volumes", []),
                           ("container_name", "production-admin")):
            before = make_model()
            after = make_after(before)
            after["services"]["xtream-vod-admin"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                stage.check_composed(before, after)

    def test_reject_missing_service(self):
        before = make_model()
        after = make_after(before)
        after["services"].pop("xtream-vod-bridge")
        with self.assertRaises(ValueError):
            stage.check_composed(before, after)


if __name__ == "__main__":
    unittest.main()
