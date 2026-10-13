"""Encrypted, *staged* Xtream provider registry.

Security boundaries:
  - Existing legacy Xtream .env / index / signed playback remain untouched.
  - New profiles are stored disabled for streaming until a provider-aware
    index + HMAC URL router has been tested and explicitly enabled.
  - Only admins can call this module via admin_ui.
  - URL/username/password are encrypted at rest, never returned as ciphertext
    or as password plaintext by any list/read API.
  - Encryption key lives in a root-provisioned, outside-DB Docker secret file.
"""
import ipaddress
import json
import os
import re
import sqlite3
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken
import ops

KEY_FILE = Path(os.getenv("XTREAM_PROVIDER_KEY_FILE", "/run/secrets/xtream-provider.key"))
LABEL = re.compile(r"^[^\x00-\x1f\x7f<>]{1,48}$")
USERNAME = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
MAX_PROVIDERS = 12


class RegistryUnavailable(RuntimeError):
    """A missing/invalid decryption key is fatal for provider editing."""


def _cipher():
    try:
        key = KEY_FILE.read_bytes().strip()
        if (not KEY_FILE.is_file() or len(key) != 44 or
                (KEY_FILE.stat().st_mode & 0o077)):
            raise ValueError("Invalid or insecure key file")
        return Fernet(key)
    except (OSError, ValueError) as exc:
        raise RegistryUnavailable("Provider key is not configured") from None


def installed():
    try:
        _cipher()
        return True
    except RegistryUnavailable:
        return False


def init():
    with ops.database() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS provider_profiles (
                provider_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                config_blob BLOB NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                credential_revision INTEGER NOT NULL DEFAULT 0,
                priority INTEGER NOT NULL DEFAULT 100,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS provider_priority_idx "
                    "ON provider_profiles(enabled, priority, provider_id)")
        # Additive schema only. Legacy index.sqlite, items and episodes
        # primary keys are not changed until a separate reviewed migration.
        con.execute("""
            CREATE TABLE IF NOT EXISTS provider_items (
                provider_id TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('movie','series')),
                item_id INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                extension TEXT NOT NULL DEFAULT 'mp4',
                imdb_id TEXT,
                tmdb_id TEXT,
                checked_at INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(provider_id, kind, item_id)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS provider_item_imdb_idx "
                    "ON provider_items(kind, imdb_id, provider_id)")
        con.execute("CREATE INDEX IF NOT EXISTS provider_item_tmdb_idx "
                    "ON provider_items(kind, tmdb_id, provider_id)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS provider_episodes (
                provider_id TEXT NOT NULL,
                series_id INTEGER NOT NULL,
                season INTEGER NOT NULL,
                episode INTEGER NOT NULL,
                stream_id INTEGER NOT NULL,
                extension TEXT NOT NULL DEFAULT 'mp4',
                name TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(provider_id, series_id, season, episode, stream_id)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS provider_episode_idx "
                    "ON provider_episodes(provider_id, series_id, season, episode)")


def normalize_url(value):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("Provider URL must be HTTPS and at most 512 characters")
    try:
        p = urlsplit(value.strip())
        # Disallow HTTP until network pinning is implemented; avoid sending
        # credentials over plaintext or to userinfo/path injection destinations.
        if (p.scheme != "https" or not p.hostname or p.username or p.password
                or p.query or p.fragment or p.path not in ("", "/")):
            raise ValueError()
        hostname = p.hostname.lower().rstrip(".")
        if (len(hostname) > 253 or "." not in hostname or
                any(len(label) > 63 or not re.fullmatch(r"[a-z0-9-]+", label)
                    or label.startswith("-") or label.endswith("-")
                    for label in hostname.split("."))):
            raise ValueError()
        try:
            # No raw IP literals; internal/rfc1918 provider addresses require a
            # separate explicit administrative SSRF policy in a future version.
            ipaddress.ip_address(hostname)
            raise ValueError()
        except ValueError:
            # IP validator and policy exceptions must be distinguished.
            if re.fullmatch(r"\d+(?:\.\d+){3}", hostname):
                raise ValueError()
        port = p.port
        if port is not None and port not in (443, 8443):
            raise ValueError()
        return urlunsplit(("https", hostname + (f":{port}" if port else ""), "", "", ""))
    except (ValueError, AttributeError):
        raise ValueError("Provider URL must be a public HTTPS DNS hostname with no path or credentials") from None


def _validate_label(value):
    if not isinstance(value, str) or not LABEL.fullmatch(value.strip()):
        raise ValueError("Invalid provider name")
    return value.strip()


def _validate_username(value):
    if not isinstance(value, str) or not USERNAME.fullmatch(value):
        raise ValueError("Invalid provider username")
    return value


def _validate_password(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512:
        raise ValueError("Password must be between 1 and 512 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError("Invalid provider password")
    return value


def _validate_priority(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1000:
        raise ValueError("Priority must be a number from 0 to 1000")
    return value


def _validate_enabled(value):
    if not isinstance(value, bool):
        raise ValueError("Enabled must be boolean")
    return value


def _decode(row, cipher):
    try:
        clear = cipher.decrypt(row["config_blob"])
        return json.loads(clear.decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeError, KeyError, TypeError):
        raise RegistryUnavailable("Provider credentials cannot be decrypted") from None


def _present(row, data):
    return {
        "id": row["provider_id"],
        "label": row["label"],
        "base_url": data["base_url"],
        "username": data["username"],
        "password_configured": bool(data.get("password")),
        "enabled": bool(row["enabled"]),
        "priority": row["priority"],
        "status": "active" if row["enabled"] else "staged_not_active",
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_profiles():
    cipher = _cipher()
    init()
    with ops.database() as con:
        rows = con.execute("SELECT * FROM provider_profiles "
                           "ORDER BY priority ASC, created_at ASC").fetchall()
    return [_present(r, _decode(r, cipher)) for r in rows]


def get_credentials(provider_id):
    """Internal only; NEVER return from an HTTP response."""
    cipher = _cipher()
    with ops.database() as con:
        row = con.execute("SELECT * FROM provider_profiles WHERE provider_id=?",
                          (provider_id,)).fetchone()
    if not row:
        raise KeyError("Provider not found")
    return _decode(row, cipher)


def create_profile(value):
    cipher = _cipher()
    allowed = {"label", "base_url", "username", "password", "priority"}
    if not isinstance(value, dict) or set(value) != set(allowed) - {"priority"} and set(value) != allowed:
        raise ValueError("Provide label, base_url, username and password")
    label = _validate_label(value["label"])
    credentials = {
        "base_url": normalize_url(value["base_url"]),
        "username": _validate_username(value["username"]),
        "password": _validate_password(value["password"]),
    }
    priority = _validate_priority(value.get("priority", 100))
    now = int(time.time())
    uid = uuid.uuid4().hex
    blob = cipher.encrypt(json.dumps(credentials, separators=(",", ":")).encode())
    init()
    with ops.database() as con:
        if con.execute("SELECT COUNT(*) FROM provider_profiles").fetchone()[0] >= MAX_PROVIDERS:
            raise ValueError("Maximum configured providers reached")
        con.execute(
            "INSERT INTO provider_profiles(provider_id,label,config_blob,enabled,"
            "priority,created_at,updated_at) VALUES(?,?,?,0,?,?,?)",
            (uid, label, blob, priority, now, now),
        )
    ops.event("config_updated", "admin", "ok")
    return {"id": uid, "label": label, "status": "staged_not_active"}


def update_profile(uid, value):
    cipher = _cipher()
    allowed = {"label", "base_url", "username", "password", "priority"}
    if not isinstance(value, dict) or not value or set(value) - allowed:
        raise ValueError("Invalid provider fields")
    with ops.database() as con:
        row = con.execute("SELECT * FROM provider_profiles WHERE provider_id=?",
                          (uid,)).fetchone()
    if not row:
        raise KeyError("Provider not found")
    previous = _decode(row, cipher)
    credential_change = bool({"base_url", "username", "password"} & set(value))
    if row["enabled"] and credential_change:
        raise ValueError("Disable provider before changing URL or credentials")
    replacement = dict(previous)
    for k in ("base_url", "username", "password"):
        if k in value:
            replacement[k] = {
                "base_url": normalize_url,
                "username": _validate_username,
                "password": _validate_password,
            }[k](value[k])
    label = _validate_label(value["label"]) if "label" in value else row["label"]
    priority = _validate_priority(value["priority"]) if "priority" in value else row["priority"]
    blob = cipher.encrypt(json.dumps(replacement, separators=(",", ":")).encode())
    with ops.database() as con:
        con.execute(
            "UPDATE provider_profiles SET label=?, config_blob=?, priority=?, "
            "credential_revision=credential_revision+?, updated_at=? WHERE provider_id=?",
            (label, blob, priority, int(credential_change), int(time.time()), uid),
        )
        if credential_change:
            # Numeric stream IDs are only meaningful inside the old account.
            # Reset scope and require re-index before reactivation.
            con.execute("DELETE FROM provider_episodes WHERE provider_id=?", (uid,))
            con.execute("DELETE FROM provider_items WHERE provider_id=?", (uid,))
    ops.event("config_updated", "admin", "ok")
    return {"id": uid, "label": label, "status": "staged_not_active"}


def delete_profile(uid):
    _cipher()
    with ops.database() as con:
        found = con.execute("SELECT enabled FROM provider_profiles WHERE provider_id=?",
                            (uid,)).fetchone()
        if not found:
            raise KeyError("Provider not found")
        if found["enabled"]:
            raise ValueError("Disable provider before deletion")
        con.execute("DELETE FROM provider_profiles WHERE provider_id=?", (uid,))
        # Future implementation must consider active provider stream links.
        # Staged profiles have never generated public links, so can be removed.
        con.execute("DELETE FROM provider_items WHERE provider_id=?", (uid,))
        con.execute("DELETE FROM provider_episodes WHERE provider_id=?", (uid,))
    ops.event("config_updated", "admin", "ok")



def active_profiles():
    """For streaming internals only. Never expose decrypted records to the UI."""
    cipher = _cipher()
    with ops.database() as con:
        rows = con.execute("SELECT * FROM provider_profiles WHERE enabled=1 "
                           "ORDER BY priority ASC, created_at ASC").fetchall()
    return [(dict(row), _decode(row, cipher)) for row in rows]


def active_profile(uid):
    cipher = _cipher()
    with ops.database() as con:
        row = con.execute(
            "SELECT * FROM provider_profiles WHERE provider_id=? AND enabled=1", (uid,)
        ).fetchone()
    if not row:
        raise KeyError("Provider is disabled or missing")
    return dict(row), _decode(row, cipher)


def set_active(uid, enabled):
    if not isinstance(enabled, bool):
        raise ValueError("Enabled must be boolean")
    _cipher()
    with ops.database() as con:
        row = con.execute("SELECT provider_id FROM provider_profiles WHERE provider_id=?",
                          (uid,)).fetchone()
        if not row:
            raise KeyError("Provider not found")
        if enabled:
            count = con.execute(
                "SELECT COUNT(*) FROM provider_items WHERE provider_id=?", (uid,)
            ).fetchone()[0]
            if not count:
                raise ValueError("Provider must be indexed and validated before activation")
        con.execute(
            "UPDATE provider_profiles SET enabled=?, updated_at=? WHERE provider_id=?",
            (int(enabled), int(time.time()), uid)
        )
    return {"id": uid, "enabled": enabled}



def credential_revision(uid):
    with ops.database() as con:
        row = con.execute(
            "SELECT credential_revision FROM provider_profiles "
            "WHERE provider_id=? AND enabled=1", (uid,)
        ).fetchone()
    if row is None:
        raise KeyError("Provider inactive or missing")
    return int(row[0])
