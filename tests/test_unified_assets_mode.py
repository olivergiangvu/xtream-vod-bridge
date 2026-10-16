"""Regression check for non-root static JS asset modes in Dockerfile.unified."""
from pathlib import Path
import unittest

class UnifiedAssetsPermissionsTest(unittest.TestCase):
    def test_image_explicitly_makes_js_readable(self):
        source = (Path(__file__).resolve().parents[1] / "Dockerfile.unified").read_text()
        self.assertIn("chmod 0644 /srv/admin/assets/app.js /srv/admin/assets/workspace.js", source)
        self.assertIn("USER 10001:10001", source)

if __name__ == "__main__":
    unittest.main()
