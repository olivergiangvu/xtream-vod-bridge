"""Stage4E2 exact Canary port-removal dry-run regression coverage."""
import copy
from pathlib import Path
import unittest

from canary import stage4e2_ports_dryrun as stage


REFERENCE = (Path(__file__).resolve().parents[1] / "canary/compose.yaml").read_text()


def injected(quote='"'):
    text = REFERENCE
    edits = [
        ("  xtream-vod-bridge:\n",
         f'  xtream-vod-bridge:\n    ports:\n      - {quote}127.0.0.1:18769:8767{quote}\n'),
        ("  xtream-vod-admin:\n",
         f'  xtream-vod-admin:\n    ports:\n      - {quote}127.0.0.1:18770:8768{quote}\n'),
    ]
    for old, new in edits:
        if text.count(old) != 1:
            raise RuntimeError("Synthetic fixtures changed")
        text = text.replace(old, new, 1)
    return text


def effective(with_ports):
    services = {}
    for service, image in stage.EXPECTED_IMAGES.items():
        item = {
            "image": image,
            "container_name": "xtream-vod-canary-admin"
                if service == "xtream-vod-admin" else "xtream-vod-canary-playback",
            "read_only": True,
            "networks": {"private_canary": None},
            "environment": {"NEVER_PRINT": "secret-fixture"},
        }
        if with_ports:
            published, internal = stage.EXPECTED_PORTS[service]
            item["ports"] = [{
                "published": published,
                "target": int(internal),
                "host_ip": "127.0.0.1",
                "protocol": "tcp",
                "mode": "ingress",
            }]
        services[service] = item
    return {
        "name": "xtream-vod-canary",
        "services": services,
        "networks": {
            "private_canary": {
                "internal": True,
                "name": "xtream-vod-canary_private_canary",
            }
        },
    }


class Stage4E2Tests(unittest.TestCase):
    def test_two_exact_port_stanzas_and_no_other_changes(self):
        for quote in ('"', "'", ""):
            with self.subTest(quote=quote):
                original = injected(quote=quote)
                candidate = stage.preview_remove_ports(original)
                self.assertEqual(candidate, REFERENCE)
                self.assertEqual(stage.significant(candidate),
                                 stage.significant(REFERENCE))
                self.assertTrue(stage.validate_config_pair(
                    effective(True), effective(False)))

    def test_only_comments_can_drift(self):
        altered = injected().replace(
            "# Isolated local-only v0.5 canary;",
            "# Canary local override history;",
        )
        candidate = stage.preview_remove_ports(altered)
        self.assertEqual(stage.significant(candidate),
                         stage.significant(REFERENCE))

    def test_reject_unexpected_or_public_port(self):
        base = injected()
        for source in (
            base.replace("127.0.0.1:18769:8767", "0.0.0.0:18769:8767"),
            base.replace("127.0.0.1:18770:8768", "127.0.0.1:18771:8768"),
            base.replace("    ports:\n      - \"127.0.0.1:18769:8767\"\n", ""),
            base.replace("    ports:\n", "    ports:\n    ports:\n", 1),
            base.replace("127.0.0.1:18770:8768",
                         "127.0.0.1:18770:8768\n      - 127.0.0.1:18772:8768"),
        ):
            with self.subTest(content=source[-90:]):
                try:
                    candidate = stage.preview_remove_ports(source)
                except ValueError:
                    continue
                self.assertNotEqual(
                    stage.significant(candidate), stage.significant(REFERENCE),
                    "An unexpected port/config source was silently accepted"
                )

    def test_effective_compose_rejects_any_unexpected_delta(self):
        before = effective(True)
        after = effective(False)
        good = copy.deepcopy(after)
        bad_cases = [
            lambda x: x["services"]["xtream-vod-admin"].update({
                "ports": [{"published": "18770", "target": 8768}]}),
            lambda x: x["services"]["xtream-vod-bridge"].update({"read_only": False}),
            lambda x: x["networks"]["private_canary"].update({"internal": False}),
            lambda x: x["services"]["xtream-vod-admin"].update({
                "image": "unexpected:image"}),
            lambda x: x["services"]["xtream-vod-bridge"].update({
                "environment": {"NEVER_PRINT": "changed-secret"}}),
        ]
        for change in bad_cases:
            candidate = copy.deepcopy(good)
            change(candidate)
            with self.subTest(delta=repr(candidate)[:60]):
                with self.assertRaises(ValueError):
                    stage.validate_config_pair(before, candidate)

    def test_invalid_orig_port_fails(self):
        obj = effective(True)
        obj["services"]["xtream-vod-admin"]["ports"][0]["host_ip"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            stage.validate_config_pair(obj, effective(False))

    def test_git_blob_reference_identity(self):
        self.assertEqual(
            stage.git_blob(b"hello\n"),
            "ce013625030ba8dba906f756967f9e9ca394464a",
        )


if __name__ == "__main__":
    unittest.main()
