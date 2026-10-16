"""Compatibility tests for upgrading v0.4.3's live SQLite schema to v0.5."""
import hashlib
import os
import secrets
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet

import admin_auth
import admin_users
import ops
import personal_index
import personal_manifests


class ExistingDatabaseMigration(unittest.TestCase):
    def test_old_owner_sessions_survive_additive_migration(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "index.sqlite"
            # Pre-existing v0.4.x layout: no username column.
            conn = sqlite3.connect(path)
            conn.execute(
                "CREATE TABLE admin_sessions (session_digest TEXT PRIMARY KEY,"
                " csrf TEXT NOT NULL,expires_at INTEGER NOT NULL,"
                " created_at INTEGER NOT NULL)"
            )
            token = secrets.token_urlsafe(36)
            digest = hashlib.sha256(token.encode()).hexdigest()
            future = int(time.time()) + 3600
            conn.execute(
                "INSERT INTO admin_sessions VALUES(?,?,?,?)",
                (digest, "sample-csrf", future, int(time.time())),
            )
            conn.execute(
                "CREATE TABLE items (kind TEXT,item_id INTEGER)"
            )
            conn.execute(
                "CREATE TABLE episodes (series_id INTEGER,season INTEGER,episode INTEGER)"
            )
            conn.execute("INSERT INTO items VALUES('movie',123)")
            conn.execute("INSERT INTO episodes VALUES(3,1,2)")
            conn.commit()
            conn.close()
            with patch.object(ops, "PATH", path), patch.dict(os.environ, {
                    "SOURCE_SECRETS_KEY": Fernet.generate_key().decode(),
            }):
                admin_users.init()
                personal_index.init()
                personal_manifests.init()
                admin_users.init()
                record = admin_auth.session_info(token)
                self.assertIsNotNone(record)
                self.assertEqual(record["username"], "owner")
                self.assertEqual(record["role"], "admin")
                with ops.database() as con:
                    self.assertEqual(
                        con.execute("SELECT username FROM admin_sessions "
                                    "WHERE session_digest=?", (digest,)).fetchone()[0],
                        "owner",
                    )
                    self.assertEqual(
                        con.execute("SELECT * FROM items").fetchone()["item_id"],
                        123,
                    )
                    self.assertEqual(
                        con.execute("SELECT * FROM episodes").fetchone()["episode"],
                        2,
                    )
                    self.assertEqual(
                        con.execute("SELECT count(*) FROM auth_users").fetchone()[0],
                        0,
                    )
                    # Entire old v0.4 table payload is unchanged.
                    self.assertEqual(
                        con.execute("PRAGMA quick_check").fetchone()[0], "ok"
                    )


if __name__ == "__main__":
    unittest.main()
