"""SQLite-backed non-secret runtime options and redacted operational events.

Never store Xtream credentials, TMDb keys, playback secrets or addon/admin tokens
here. All values originate from a small, validated allowlist.
"""
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

PATH = Path(os.getenv("DATA_DIR", "/data")) / "index.sqlite"
LABEL_PATTERN = re.compile(r"^[^\x00-\x1f\x7f<>]{1,48}$")
SCHEMA = {
    "source_label": {"type": "label", "min": 1, "max": 48},
    "series_on_demand": {"type": "bool"},
    "series_jit_timeout_seconds": {"type": "int", "min": 2, "max": 15},
    "series_jit_ttl_hours": {"type": "int", "min": 1, "max": 168},
    "series_jit_retry_seconds": {"type": "int", "min": 30, "max": 3600},
    "series_jit_max_variants": {"type": "int", "min": 1, "max": 8},
    "series_enrich_per_sync": {"type": "int", "min": 0, "max": 500},
}
DEFAULTS = {
    "source_label": os.getenv("STREAM_SOURCE_LABEL", "IPTV VOD"),
    "series_on_demand": os.getenv("SERIES_ON_DEMAND", "0") == "1",
    "series_jit_timeout_seconds": int(float(os.getenv("SERIES_JIT_TIMEOUT_SECONDS", "8"))),
    "series_jit_ttl_hours": int(os.getenv("SERIES_JIT_TTL_HOURS", "6")),
    "series_jit_retry_seconds": int(os.getenv("SERIES_JIT_RETRY_SECONDS", "120")),
    "series_jit_max_variants": int(os.getenv("SERIES_JIT_MAX_VARIANTS", "8")),
    "series_enrich_per_sync": int(os.getenv("SERIES_ENRICH_PER_SYNC", "40")),
}


@contextmanager
def database():
    con = sqlite3.connect(PATH, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA busy_timeout=5000")
        with con:
            yield con
    finally:
        con.close()


def init():
    PATH.parent.mkdir(parents=True, exist_ok=True)
    with database() as con:
        con.execute("CREATE TABLE IF NOT EXISTS runtime_settings "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS diagnostic_events "
                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, "
                    " event TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, "
                    " duration_ms INTEGER NOT NULL DEFAULT 0, amount INTEGER NOT NULL DEFAULT 0)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_diag_ts ON diagnostic_events(ts)")


def validate(key, value):
    if key not in SCHEMA:
        raise ValueError("Unsupported setting")
    rule = SCHEMA[key]
    if rule["type"] == "label":
        if not isinstance(value, str) or not LABEL_PATTERN.fullmatch(value.strip()):
            raise ValueError("Source label must be 1–48 printable characters without angle brackets")
        return value.strip()
    if rule["type"] == "bool":
        if not isinstance(value, bool):
            raise ValueError("Expected a boolean")
        return value
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Expected an integer")
    if not rule["min"] <= value <= rule["max"]:
        raise ValueError("Value outside permitted safety bounds")
    return value


def serialize(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value)


def deserialize(key, value):
    if key == "series_on_demand":
        return value == "1"
    if SCHEMA[key]["type"] == "int":
        return int(value)
    return value


def get(key):
    if key not in SCHEMA:
        raise ValueError("Unsupported setting")
    try:
        with database() as con:
            row = con.execute("SELECT value FROM runtime_settings WHERE key=?", (key,)).fetchone()
        if row is not None:
            return validate(key, deserialize(key, row["value"]))
    except (sqlite3.Error, ValueError, OSError):
        pass
    return DEFAULTS[key]


def all_settings():
    return {key: get(key) for key in SCHEMA}


def update(values):
    """All-or-nothing write. Never pass arbitrary dictionary keys to SQLite."""
    if not isinstance(values, dict) or not values or len(values) > len(SCHEMA):
        raise ValueError("Expected a non-empty settings object")
    validated = {key: validate(key, value) for key, value in values.items()}
    now = int(time.time())
    with database() as con:
        con.executemany(
            "INSERT INTO runtime_settings(key,value,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,"
            "updated_at=excluded.updated_at",
            [(key, serialize(val), now) for key, val in validated.items()],
        )
    event("config_updated", "admin", "ok", amount=len(validated))
    return all_settings()


def event(name, kind, status, *, duration_ms=0, amount=0):
    """No URLs, IDs, credentials, provider errors, or arbitrary text in events."""
    allowed_names = {"stream_request", "series_jit", "config_updated", "sync"}
    allowed_kinds = {"movie", "series", "admin", "system"}
    allowed_statuses = {"ok", "empty", "error", "timeout", "cached"}
    if name not in allowed_names or kind not in allowed_kinds or status not in allowed_statuses:
        return
    try:
        with database() as con:
            con.execute(
                "INSERT INTO diagnostic_events(ts,event,kind,status,duration_ms,amount) "
                "VALUES(?,?,?,?,?,?)",
                (int(time.time()), name, kind, status,
                 max(0, min(60000, int(duration_ms))), max(0, min(1000000, int(amount)))),
            )
            # Periodic bounded retention, not a separate daemon.
            con.execute("DELETE FROM diagnostic_events WHERE id < "
                        "(SELECT COALESCE(MAX(id),0)-2000 FROM diagnostic_events)")
    except (sqlite3.Error, OSError, ValueError):
        # Logging must never interrupt signed playback.
        return


def events(limit=60):
    limit = max(1, min(200, int(limit)))
    with database() as con:
        rows = con.execute(
            "SELECT ts,event,kind,status,duration_ms,amount "
            "FROM diagnostic_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]
