"""Dry-run safety gates for the dedicated Admin Manifest promoter."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
PROMOTER = REPO / "scripts" / "promote_manifest_only.py"


def import_promoter():
    spec = importlib.util.spec_from_file_location("manifest_promoter", PROMOTER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ManifestPromotionTests(unittest.TestCase):
    def fixture(self, folder, module):
        source = Path(folder) / "source"
        local = Path(folder) / "local"
        source.mkdir()
        local.mkdir()
        local_digests = {}
        for path in module.EXPECTED_NEW:
            target = source / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / path).read_bytes())

        for path in module.EXPECTED_OLD_STATIC:
            target = local / path
            target.parent.mkdir(parents=True, exist_ok=True)
            old = ("previous-version:" + path).encode()
            target.write_bytes(old)
            local_digests[path] = module.git_blob(old)

        reviewed = (REPO / "admin_ui.py").read_text()
        start = reviewed.index('@console.get("/api/manifest", dependencies=[Depends(authorize)])')
        end = reviewed.index('@console.get("/api/events", dependencies=[Depends(authorize)])', start)
        legacy = reviewed[:start] + reviewed[end:]
        legacy = legacy.replace(
            'response.headers["Referrer-Policy"] = (\n'
            '        "strict-origin-when-cross-origin" if request.url.path.startswith("/gateway/")\n'
            '        else "no-referrer"\n'
            '    )',
            'response.headers["Referrer-Policy"] = "same-origin"',
        ).replace(
            '<meta name="referrer" content="strict-origin-when-cross-origin">',
            '<meta name="referrer" content="same-origin">',
        )
        (local / "admin_ui.py").write_text(legacy)
        return source, local, local_digests, legacy

    def test_preflight_only_adds_endpoint_and_replaces_reviewed_static_assets(self):
        module = import_promoter()
        with tempfile.TemporaryDirectory() as folder:
            source, local, digests, legacy = self.fixture(folder, module)
            with patch.object(module, "ROOT", local), \
                 patch.dict(module.EXPECTED_OLD_STATIC, digests, clear=True):
                changes = module.prepare(source)
            self.assertEqual(set(changes), set(module.EXPECTED_NEW))
            self.assertEqual((local / "admin_ui.py").read_text(), legacy)
            self.assertIn('@console.get("/api/manifest"', changes["admin_ui.py"])
            self.assertIn('response.headers["Referrer-Policy"] = "same-origin"',
                          changes["admin_ui.py"])
            self.assertIn('<meta name="referrer" content="same-origin">',
                          changes["admin_ui.py"])
            self.assertEqual(
                changes["admin_ui.py"].count('@console.get("/api/manifest"'), 1
            )
            self.assertEqual(
                changes["admin/assets/app.js"],
                (REPO / "admin/assets/app.js").read_text(),
            )

    def test_unreviewed_download_is_rejected(self):
        module = import_promoter()
        with tempfile.TemporaryDirectory() as folder:
            source, local, digests, _ = self.fixture(folder, module)
            (source / "admin/index.html").write_text("modified unexpectedly")
            with patch.object(module, "ROOT", local), \
                 patch.dict(module.EXPECTED_OLD_STATIC, digests, clear=True):
                with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                    module.prepare(source)

    def test_unexpected_live_policy_is_rejected(self):
        module = import_promoter()
        with tempfile.TemporaryDirectory() as folder:
            source, local, digests, legacy = self.fixture(folder, module)
            (local / "admin_ui.py").write_text(
                legacy.replace(
                    'response.headers["Referrer-Policy"] = "same-origin"',
                    'response.headers["Referrer-Policy"] = "no-referrer"',
                )
            )
            with patch.object(module, "ROOT", local), \
                 patch.dict(module.EXPECTED_OLD_STATIC, digests, clear=True):
                with self.assertRaisesRegex(RuntimeError, "Safari origin header"):
                    module.prepare(source)


if __name__ == "__main__":
    unittest.main()
