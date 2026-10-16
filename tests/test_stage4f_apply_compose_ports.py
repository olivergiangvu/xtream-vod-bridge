"""Stage4F atomic Canary Compose port repair: pure safety regressions."""
import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from canary import stage4f_apply_compose_ports as stage

ROOT = Path(__file__).resolve().parents[1]
REF = (ROOT / "canary/compose.yaml").read_text()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixture():
    source = REF.replace(
        "  xtream-vod-bridge:\n",
        '  xtream-vod-bridge:\n    ports:\n      - "127.0.0.1:18769:8767"\n',
        1,
    )
    source = source.replace(
        "  xtream-vod-admin:\n",
        '  xtream-vod-admin:\n    ports:\n      - "127.0.0.1:18770:8768"\n',
        1,
    )
    return source.encode()


def model(with_ports):
    services = {}
    for service, image in stage.EXPECTED_IMAGES.items():
        entry = {
            "image": image,
            "networks": {"private_canary": None},
            "read_only": True,
            "environment": {"NO_LOG": "sensitive"},
        }
        if with_ports:
            published = next(
                p for p, (name, _target) in stage.EXPECTED_PORTS.items()
                if name == service
            )
            entry["ports"] = [{
                "published": published,
                "target": stage.EXPECTED_PORTS[published][1],
                "host_ip": "127.0.0.1",
            }]
        services[service] = entry
    return {
        "services": services,
        "networks": {"private_canary": {"internal": True}},
    }


class Stage4FTests(unittest.TestCase):
    def test_strict_patch_only_two_ports(self):
        original = fixture()
        with patch.dict(stage.EXPECTED, {stage.BASE: sha(original)}), \
             patch.object(stage, "CANDIDATE_SHA", sha(REF.encode())):
            self.assertEqual(stage.preview_patch(original), REF.encode())

    def test_reject_missing_unknown_or_duplicate_ports(self):
        source = fixture()
        wrong = [
            source.replace(b"127.0.0.1:18770", b"0.0.0.0:18770"),
            source.replace(b"18769:8767", b"18771:8767"),
            source.replace(b"    ports:\n      - \"127.0.0.1:18769:8767\"\n", b""),
            source.replace(b"      - \"127.0.0.1:18770:8768\"\n",
                           b"      - \"127.0.0.1:18770:8768\"\n"
                           b"    ports:\n      - \"127.0.0.1:18770:8768\"\n"),
        ]
        for bad in wrong:
            with self.subTest(bad=bad[-100:]):
                with patch.dict(stage.EXPECTED, {stage.BASE: sha(bad)}), \
                     patch.object(stage, "CANDIDATE_SHA", sha(REF.encode())):
                    with self.assertRaises(ValueError):
                        stage.preview_patch(bad)

    def test_candidate_sha_prevents_any_other_edit(self):
        source = fixture()
        with patch.dict(stage.EXPECTED, {stage.BASE: sha(source)}), \
             patch.object(stage, "CANDIDATE_SHA", "0" * 64):
            with self.assertRaisesRegex(ValueError, "pinned candidate"):
                stage.preview_patch(source)

    def test_effective_config_change_only_ports(self):
        stage.compare_compose(model(True), model(False))

    def test_refuse_effective_config_non_port_delta(self):
        before, after = model(True), model(False)
        changes = [
            lambda x: x["services"]["xtream-vod-admin"].update(
                {"ports": [{"target": 8768}]}),
            lambda x: x["services"]["xtream-vod-bridge"].update(
                {"read_only": False}),
            lambda x: x["services"]["xtream-vod-admin"].update(
                {"environment": {"NO_LOG": "CHANGED"}}),
            lambda x: x["networks"]["private_canary"].update(
                {"internal": False}),
        ]
        for change in changes:
            candidate = copy.deepcopy(after)
            change(candidate)
            with self.subTest(candidate=str(candidate)[:60]):
                with self.assertRaises(ValueError):
                    stage.compare_compose(before, candidate)


if __name__ == "__main__":
    unittest.main()
