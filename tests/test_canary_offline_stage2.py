"""Run real Canary Stage 2 acceptance assertions under CI with synthetic env."""
import os
from unittest.mock import patch

from cryptography.fernet import Fernet

from canary import offline_stage2 as stage2
import app as bridge
import admin_auth


class OfflineCanaryStage2CI(stage2.OfflineStage2):
    @classmethod
    def setUpClass(cls):
        cls._guards = [
            patch.dict(os.environ, {
                "LEGACY_SYNC_ENABLED": "0",
                "PUBLIC_BASE_URL": "https://canary.invalid:18451",
                "SOURCE_SECRETS_KEY": Fernet.generate_key().decode(),
            }),
            patch.object(admin_auth, "PUBLIC_ORIGIN",
                         "https://canary.invalid:18451"),
            patch.object(bridge, "PUBLIC", "https://canary.invalid:18451"),
            patch.object(bridge, "SECRET", "CI-local-strong-test-secret-2026"),
            patch.object(bridge, "LEGACY_SYNC_ENABLED", False),
            patch.object(bridge, "check_settings", return_value=None),
        ]
        for guard in cls._guards:
            guard.start()
        try:
            super().setUpClass()
        except Exception:
            for guard in reversed(cls._guards):
                guard.stop()
            raise

    @classmethod
    def tearDownClass(cls):
        try:
            super().tearDownClass()
        finally:
            for guard in reversed(cls._guards):
                guard.stop()
