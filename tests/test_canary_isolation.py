"""Isolated canary must NOT boot the production/legacy provider polling loop."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import app as bridge
import ops


class CanaryIsolation(unittest.TestCase):
    def test_disabled_legacy_sync_skips_provider_tasks_at_startup(self):
        with tempfile.TemporaryDirectory() as dirname, \
             patch.object(bridge, "DB_PATH", Path(dirname) / "index.sqlite"), \
             patch.object(bridge, "DATA_DIR", Path(dirname)), \
             patch.object(ops, "PATH", Path(dirname) / "index.sqlite"), \
             patch.object(bridge, "LEGACY_SYNC_ENABLED", False), \
             patch.object(bridge, "loop", new=AsyncMock()) as loop, \
             patch.object(bridge, "series_bootstrap_loop", new=AsyncMock()) as bootstrap:
            with TestClient(bridge.app) as client:
                response = client.get("/health")
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json()["status"], "ok")
                loop.assert_not_awaited()
                bootstrap.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
