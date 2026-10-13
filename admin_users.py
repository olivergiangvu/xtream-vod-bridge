"""v0.5 human accounts: exactly two roles (admin/user).

Legacy username 'owner' maps to the sole bootstrap admin and keeps its existing
PBKDF2 credential in admin_password. Extra users have independent hashes.
Do not combine user identities with provider credentials.
"""
import hashlib
import re
import secrets
import time

import admin_auth
import ops

USERNAME = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
ROLES = {"user"}  # Admin is the protected bootstrap 'owner' principal.
MAX_USERS = 30


def init():
    admin_auth.init()
    with ops.database() as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS auth_users ("
            "username TEXT PRIMARY KEY, salt BLOB NOT NULL, digest BLOB NOT NULL, "
            "rounds INTEGER NOT NULL, role TEXT NOT NULL CHECK(role='user'), "
            "enabled INTEGER NOT NULL DEFAULT 1, "
            "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
        )
        # Additive migration: every pre-existing cookie belongs to owner.
        cols = {row["name"] for row in con.execute("PRAGMA table_info(admin_sessions)")}
        if "username" not in cols:
            con.execute(
                "ALTER TABLE admin_sessions ADD COLUMN username TEXT "
                "NOT NULL DEFAULT 'owner'"
            )


def validate_username(username):
    if (not isinstance(username, str) or not USERNAME.fullmatch(username)
            or username == "owner"):
        raise ValueError("Invalid username")
    return username


def principal(username):
    if username == "owner":
        return {"username": "owner", "role": "admin"}
    if not isinstance(username, str) or not USERNAME.fullmatch(username):
        return None
    with ops.database() as con:
        record = con.execute(
            "SELECT role FROM auth_users WHERE username=? AND enabled=1",
            (username,),
        ).fetchone()
    return {"username": username, "role": record["role"]} if record else None


def find_for_login(username):
    init()
    if not isinstance(username, str) or not USERNAME.fullmatch(username):
        return None
    with ops.database() as con:
        return con.execute(
            "SELECT salt,digest,rounds FROM auth_users WHERE "
            "username=? AND enabled=1", (username,),
        ).fetchone()


def list_users():
    init()
    with ops.database() as con:
        rows = con.execute(
            "SELECT username,role,enabled,created_at,updated_at "
            "FROM auth_users ORDER BY username"
        ).fetchall()
    return [
        {"username": "owner", "role": "admin", "enabled": True, "built_in": True},
        *[{**dict(r), "enabled": bool(r["enabled"]), "built_in": False} for r in rows],
    ]


def create_user(username, password):
    init()
    validate_username(username)
    if not admin_auth.password_is_strong(password):
        raise ValueError("Use a strong password (14–128 printable characters)")
    salt = secrets.token_bytes(24)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, admin_auth.ITERATIONS
    )
    stamp = int(time.time())
    with ops.database() as con:
        if con.execute("SELECT COUNT(*) FROM auth_users").fetchone()[0] >= MAX_USERS:
            raise ValueError("Account limit reached")
        if con.execute(
            "SELECT 1 FROM auth_users WHERE username=?", (username,)
        ).fetchone():
            raise ValueError("Username unavailable")
        con.execute(
            "INSERT INTO auth_users (username,salt,digest,rounds,role,enabled,"
            "created_at,updated_at) VALUES(?,?,?,?,'user',1,?,?)",
            (username, salt, digest, admin_auth.ITERATIONS, stamp, stamp),
        )
    return {"username": username, "role": "user", "enabled": True}


def change_user(username, *, enabled=None, password=None):
    init()
    validate_username(username)
    if enabled is None and password is None:
        raise ValueError("No changes")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("Invalid enabled status")
    if password is not None and not admin_auth.password_is_strong(password):
        raise ValueError("Invalid password")
    with ops.database() as con:
        current = con.execute(
            "SELECT 1 FROM auth_users WHERE username=?", (username,)
        ).fetchone()
        if not current:
            raise KeyError("User not found")
        if enabled is not None:
            con.execute(
                "UPDATE auth_users SET enabled=?,updated_at=? WHERE username=?",
                (int(enabled), int(time.time()), username),
            )
        if password is not None:
            salt = secrets.token_bytes(24)
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, admin_auth.ITERATIONS
            )
            con.execute(
                "UPDATE auth_users SET salt=?,digest=?,rounds=?,updated_at=? "
                "WHERE username=?",
                (salt, digest, admin_auth.ITERATIONS, int(time.time()), username),
            )
        # Status or credentials change invalidates all active browser sessions.
        con.execute("DELETE FROM admin_sessions WHERE username=?", (username,))
    return {"username": username, "role": "user", "updated": True}


def delete_user(username):
    init()
    validate_username(username)
    with ops.database() as con:
        # v0.5 foreign-key source ownership is retained on account deletion;
        # users with sources must first have their sources removed explicitly.
        if con.execute(
            "SELECT 1 FROM vod_sources WHERE owner=? LIMIT 1", (username,)
        ).fetchone():
            raise ValueError("Delete personal sources first")
        if con.execute(
            "DELETE FROM auth_users WHERE username=?", (username,)
        ).rowcount != 1:
            raise KeyError("User not found")
        con.execute("DELETE FROM admin_sessions WHERE username=?", (username,))
    return True
