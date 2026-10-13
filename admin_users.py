"""Additional human Admin accounts, distinct from Xtream provider profiles.

The current admin password belongs to the built-in Owner account. All
additional users have independent salted password hashes, roles and
revocable sessions. This table contains no IPTV credentials or API keys.
"""
import hashlib
import re
import secrets
import sqlite3
import time

import admin_auth
import ops

USERNAME = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
ROLES = {"admin", "viewer"}
MAX_ACCOUNTS = 12


def init():
    with ops.database() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                digest BLOB NOT NULL,
                rounds INTEGER NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'viewer')),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        # Backward-compatible migration of 0.4.2 sessions to the built-in
        # owner principal. Old cookie sessions remain valid until expiry.
        columns = {row["name"] for row in con.execute("PRAGMA table_info(admin_sessions)")}
        if "username" not in columns:
            con.execute(
                "ALTER TABLE admin_sessions ADD COLUMN username TEXT NOT NULL DEFAULT 'owner'"
            )


def _username(s):
    if not isinstance(s, str):
        raise ValueError("Invalid account username")
    cleaned = s.strip().lower()
    if not USERNAME.fullmatch(cleaned) or cleaned == "owner":
        raise ValueError("Use 3–32 lowercase letters, digits, _ or -, excluding owner")
    return cleaned


def list_users():
    init()
    with ops.database() as con:
        result = con.execute(
            "SELECT username,role,enabled,created_at,updated_at "
            "FROM admin_users ORDER BY username"
        ).fetchall()
    users = [{"username": "owner", "role": "owner", "enabled": True, "built_in": True}]
    users.extend({**dict(row), "enabled": bool(row["enabled"]), "built_in": False}
                 for row in result)
    return users


def get_auth_account(username):
    init()
    with ops.database() as con:
        row = con.execute("SELECT salt,digest,rounds,role,enabled FROM admin_users "
                          "WHERE username=?", (username,)).fetchone()
    if not row or not row["enabled"]:
        return None
    return dict(row)


def principal(username):
    if username == "owner":
        return {"username": "owner", "role": "owner"}
    record = get_auth_account(username)
    if record:
        return {"username": username, "role": record["role"]}
    return None


def add_user(username, password, role):
    username = _username(username)
    if not admin_auth.password_is_strong(password):
        raise ValueError("Choose a passphrase of 14–128 printable characters")
    if role not in ROLES:
        raise ValueError("Role must be admin or viewer")
    init()
    salt = secrets.token_bytes(24)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, admin_auth.ITERATIONS)
    now = int(time.time())
    with ops.database() as con:
        if con.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0] >= MAX_ACCOUNTS:
            raise ValueError("Too many Admin profiles")
        if con.execute("SELECT 1 FROM admin_users WHERE username=?", (username,)).fetchone():
            raise ValueError("Account already exists")
        con.execute(
            "INSERT INTO admin_users"
            "(username,salt,digest,rounds,role,enabled,created_at,updated_at)"
            " VALUES(?,?,?,?,?,1,?,?)",
            (username, salt, digest, admin_auth.ITERATIONS, role, now, now),
        )
    ops.event("config_updated", "admin", "ok")
    return {"username": username, "role": role, "enabled": True}


def modify_user(username, *, role=None, enabled=None, password=None):
    username = _username(username)
    init()
    if role is None and enabled is None and password is None:
        raise ValueError("No account changes")
    if role is not None and role not in ROLES:
        raise ValueError("Role must be admin or viewer")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("Enabled must be a boolean")
    if password is not None and not admin_auth.password_is_strong(password):
        raise ValueError("Choose a passphrase of 14–128 printable characters")
    with ops.database() as con:
        row = con.execute("SELECT * FROM admin_users WHERE username=?", (username,)).fetchone()
        if not row:
            raise KeyError("Account not found")
        new_role = role if role is not None else row["role"]
        new_enabled = enabled if enabled is not None else bool(row["enabled"])
        if password is None:
            con.execute("UPDATE admin_users SET role=?,enabled=?,updated_at=? WHERE username=?",
                        (new_role, int(new_enabled), int(time.time()), username))
        else:
            salt = secrets.token_bytes(24)
            digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                        salt, admin_auth.ITERATIONS)
            con.execute(
                "UPDATE admin_users SET role=?,enabled=?,salt=?,digest=?,"
                "rounds=?,updated_at=? WHERE username=?",
                (new_role, int(new_enabled), salt, digest,
                 admin_auth.ITERATIONS, int(time.time()), username),
            )
        # Role/disable/password changes revoke ALL existing sessions of user.
        con.execute("DELETE FROM admin_sessions WHERE username=?", (username,))
    ops.event("config_updated", "admin", "ok")
    return {"username": username, "role": new_role, "enabled": new_enabled}


def delete_user(username):
    username = _username(username)
    init()
    with ops.database() as con:
        cur = con.execute("DELETE FROM admin_users WHERE username=?", (username,))
        if not cur.rowcount:
            raise KeyError("Account not found")
        con.execute("DELETE FROM admin_sessions WHERE username=?", (username,))
    ops.event("config_updated", "admin", "ok")
