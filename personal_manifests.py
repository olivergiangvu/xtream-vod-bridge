"""Private manifest lifecycle for provider-scoped VOD streams (v0.5c).

The raw personal token is returned ONLY once at creation/rotation, never stored
in SQLite. Existing ADDON_TOKEN/global /a/ playback remains fully supported.
"""
import hashlib
import re
import secrets
import time

import admin_users
import ops
import user_sources

TOKEN_PREFIX = "v5_"
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,64}$")
MAX_MANIFESTS = 8


def init():
    user_sources.init()
    with ops.database() as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS personal_manifests ("
            "manifest_id TEXT PRIMARY KEY, owner TEXT NOT NULL,"
            "name TEXT NOT NULL, token_digest TEXT NOT NULL UNIQUE,"
            "enabled INTEGER NOT NULL DEFAULT 1,"
            "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS manifest_sources ("
            "manifest_id TEXT NOT NULL, source_id TEXT NOT NULL,"
            "PRIMARY KEY(manifest_id,source_id))"
        )
        con.execute(
            "CREATE INDEX IF NOT EXISTS idx_personal_manifests_owner "
            "ON personal_manifests(owner)"
        )


def _token():
    return TOKEN_PREFIX + secrets.token_urlsafe(36)


def _digest(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _public_url(token):
    import app as bridge
    from urllib.parse import urlsplit

    uri = urlsplit(bridge.PUBLIC)
    if (uri.scheme != "https" or not uri.hostname
            or uri.username or uri.password or uri.query or uri.fragment):
        raise RuntimeError("Public HTTPS addon base is not configured")
    return bridge.PUBLIC.rstrip("/") + "/a/" + token + "/manifest.json"


def _validate_source_selection(con, owner, source_ids):
    if (not isinstance(source_ids, list) or not 1 <= len(source_ids) <= 8
            or len(set(map(str, source_ids))) != len(source_ids)
            or not all(isinstance(s, str) and re.fullmatch(r"[a-f0-9]{32}", s)
                       for s in source_ids)):
        raise ValueError("Select 1–8 unique personal source IDs")
    placeholders = ",".join("?" for _ in source_ids)
    rows = con.execute(
        f"SELECT source_id FROM vod_sources "
        f"WHERE owner=? AND enabled=1 AND source_id IN ({placeholders})",
        [owner, *source_ids],
    ).fetchall()
    if len(rows) != len(source_ids):
        raise ValueError("A source is unavailable or does not belong to this account")


def _summary(row, sources):
    return {
        "manifest_id": row["manifest_id"],
        "name": row["name"],
        "enabled": bool(row["enabled"]),
        "sources": sources,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "url": None,  # never reproduce raw token
    }


def create(owner, name, source_ids):
    if not isinstance(name, str) or not NAME_RE.fullmatch(name.strip()):
        raise ValueError("Invalid manifest name")
    # Fail closed *before* writing anything if public HTTPS isn't configured.
    new_token = _token()
    url = _public_url(new_token)
    init()
    now = int(time.time())
    mid = secrets.token_hex(16)
    with ops.database() as con:
        if con.execute(
            "SELECT COUNT(*) FROM personal_manifests WHERE owner=?", (owner,)
        ).fetchone()[0] >= MAX_MANIFESTS:
            raise ValueError("Manifest limit reached")
        _validate_source_selection(con, owner, source_ids)
        con.execute(
            "INSERT INTO personal_manifests "
            "(manifest_id,owner,name,token_digest,enabled,created_at,updated_at)"
            "VALUES(?,?,?,?,1,?,?)",
            (mid, owner, name.strip(), _digest(new_token), now, now),
        )
        con.executemany(
            "INSERT INTO manifest_sources(manifest_id,source_id) VALUES(?,?)",
            [(mid, sid) for sid in source_ids],
        )
        row = con.execute(
            "SELECT * FROM personal_manifests WHERE manifest_id=?", (mid,)
        ).fetchone()
    return {**_summary(row, source_ids), "url": url, "one_time_only": True}


def list_owned(owner):
    init()
    with ops.database() as con:
        manifests = con.execute(
            "SELECT * FROM personal_manifests WHERE owner=? "
            "ORDER BY created_at DESC", (owner,)
        ).fetchall()
        result = []
        for row in manifests:
            sources = [
                r["source_id"] for r in con.execute(
                    "SELECT source_id FROM manifest_sources WHERE manifest_id=?",
                    (row["manifest_id"],),
                )
            ]
            result.append(_summary(row, sources))
    return result


def _get_owned(con, owner, manifest_id):
    row = con.execute(
        "SELECT * FROM personal_manifests WHERE owner=? AND manifest_id=?",
        (owner, manifest_id),
    ).fetchone()
    if row is None:
        raise KeyError("Manifest not found")
    return row


def rotate(owner, manifest_id):
    new_token = _token()
    url = _public_url(new_token)
    init()
    with ops.database() as con:
        _get_owned(con, owner, manifest_id)
        con.execute(
            "UPDATE personal_manifests SET token_digest=?,enabled=1,updated_at=? "
            "WHERE manifest_id=? AND owner=?",
            (_digest(new_token), int(time.time()), manifest_id, owner),
        )
    return {"manifest_id": manifest_id, "url": url, "one_time_only": True}


def update(owner, manifest_id, *, name=None, enabled=None, source_ids=None):
    init()
    if name is None and enabled is None and source_ids is None:
        raise ValueError("No changes")
    if name is not None and (not isinstance(name, str) or
                             not NAME_RE.fullmatch(name.strip())):
        raise ValueError("Invalid manifest name")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("Invalid enabled flag")
    with ops.database() as con:
        row = _get_owned(con, owner, manifest_id)
        if source_ids is not None:
            _validate_source_selection(con, owner, source_ids)
            con.execute("DELETE FROM manifest_sources WHERE manifest_id=?", (manifest_id,))
            con.executemany(
                "INSERT INTO manifest_sources(manifest_id,source_id) VALUES(?,?)",
                [(manifest_id, sid) for sid in source_ids],
            )
        con.execute(
            "UPDATE personal_manifests SET name=?,enabled=?,updated_at=? "
            "WHERE owner=? AND manifest_id=?",
            (name.strip() if name is not None else row["name"],
             int(enabled) if enabled is not None else row["enabled"],
             int(time.time()), owner, manifest_id),
        )
    return next(r for r in list_owned(owner) if r["manifest_id"] == manifest_id)


def delete(owner, manifest_id):
    init()
    with ops.database() as con:
        _get_owned(con, owner, manifest_id)
        con.execute("DELETE FROM manifest_sources WHERE manifest_id=?", (manifest_id,))
        con.execute("DELETE FROM personal_manifests "
                    "WHERE owner=? AND manifest_id=?", (owner, manifest_id))


def resolve_token(token):
    if (not isinstance(token, str) or not token.startswith(TOKEN_PREFIX)
            or not 40 <= len(token) <= 120):
        return None
    init()
    with ops.database() as con:
        row = con.execute(
            "SELECT * FROM personal_manifests WHERE token_digest=? AND enabled=1",
            (_digest(token),),
        ).fetchone()
        if not row or not admin_users.principal(row["owner"]):
            return None
        return {
            "manifest_id": row["manifest_id"],
            "owner": row["owner"],
            "name": row["name"],
            "sources": [
                src["source_id"] for src in con.execute(
                    "SELECT ms.source_id FROM manifest_sources ms "
                    "JOIN vod_sources s ON s.source_id=ms.source_id "
                    "WHERE ms.manifest_id=? AND s.owner=? AND s.enabled=1",
                    (row["manifest_id"], row["owner"]),
                )
            ],
        }


def resolve_id(manifest_id, source_id):
    """Every signed playback request rechecks manifest/source/owner state."""
    init()
    with ops.database() as con:
        row = con.execute(
            "SELECT pm.owner FROM personal_manifests pm "
            "JOIN manifest_sources ms ON pm.manifest_id=ms.manifest_id "
            "JOIN vod_sources src ON src.source_id=ms.source_id "
            "WHERE pm.manifest_id=? AND pm.enabled=1 AND ms.source_id=? "
            "AND src.enabled=1 AND src.owner=pm.owner",
            (manifest_id, source_id),
        ).fetchone()
    return row["owner"] if row and admin_users.principal(row["owner"]) else None
