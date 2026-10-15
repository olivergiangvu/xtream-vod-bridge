"""M3.4: permission-only immutable image repair; no Docker calls in tests."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from canary import stage6_unified_permission_fix_build as fix


def git_blob(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\x00" + raw
    ).hexdigest()


class PermissionFixTests(unittest.TestCase):
    def test_image_tag_changes_without_overwriting_old(self):
        self.assertNotEqual(fix.NEW_IMAGE, fix.OLD_IMAGE)
        self.assertTrue(fix.NEW_IMAGE.endswith("-permfix1"))
        self.assertEqual(len(fix.PIN_REF), 40)
        self.assertEqual(len(fix.PIN_BLOB), 40)

    def test_changes_only_copy_mode_not_python_content(self):
        originals = {
            "unified_app.py": b"application = None\n",
            "admin_ui.py": b"console = None\n",
        }
        source = (
            "FROM homedocker/base:immutable\n"
            "ENV XTREAM_UNIFIED_MODE=1\n"
            "COPY unified_app.py admin_ui.py /srv/\n"
            "EXPOSE 8767\n"
        )
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text(source)
            for name, raw in originals.items():
                path = root / name
                path.write_bytes(raw)
                path.chmod(0o600)
            orig = SimpleNamespace(
                git_blob=git_blob,
                SOURCES={k: git_blob(v) for k, v in originals.items()},
                BASE_IMAGE="homedocker/base:immutable",
            )
            fix.fix_dockerfile(root, orig)
            revised = (root / "Dockerfile").read_text()
            self.assertEqual(revised.replace(fix.NEW_COPY, fix.OLD_COPY), source)
            self.assertNotIn(fix.OLD_COPY, revised)
            for name, raw in originals.items():
                path = root / name
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_reject_dockerfile_missing_original_copy(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Dockerfile").write_text("FROM scratch\n")
            with self.assertRaisesRegex(RuntimeError, "ORIGINAL_COPY_NOT_UNIQUE"):
                fix.fix_dockerfile(root, SimpleNamespace())

    def test_does_not_overwrite_existing_tag(self):
        with patch.object(fix.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
            with self.assertRaisesRegex(RuntimeError, "OVERWRITE"):
                fix.new_image_absent()


if __name__ == "__main__":
    unittest.main()
