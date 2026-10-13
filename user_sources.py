"""v0.5a user-owned VOD sources: encrypted configs and guarded test/probe.

No indexing/playback changes in this phase. A source is not yet a playable addon.
The existing global Xtream provider and live legacy manifest are untouched.
"""
import asyncio
import ipaddress
import json
import os
import re
import secrets
import socket
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken

import ops

NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,64}$")
MAX_SOURCES = 8
MAX_JSON = 1024 * 1024
MAX_M3U = 2 * 1024 * 1024
PORTS = {443, 8443, 9443, 8080, 8000}
KINDS = {"xtream", "m3u"}


def init():
    with ops.database() as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS vod_sources ("
            "source_id TEXT PRIMARY KEY, owner TEXT NOT NULL, kind TEXT NOT NULL "
            "CHECK(kind IN ('xtream','m3u')), title TEXT NOT NULL, "
            "config_ciphertext BLOB NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,"
            "status TEXT NOT NULL DEFAULT 'untested', "
            "created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)"
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_vod_sources_owner "
                    "ON vod_sources(owner)")


def _cipher():
    key = os.getenv("SOURCE_SECRETS_KEY", "")
    if not key:
        raise RuntimeError("SOURCE_SECRETS_KEY is not configured")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("Invalid SOURCE_SECRETS_KEY") from exc


def _validated_url(raw, *, playlist=False):
    if not isinstance(raw, str) or not 12 <= len(raw) <= 2048:
        raise ValueError("Invalid source URL")
    if any(ord(c) < 33 or ord(c) == 127 for c in raw):
        raise ValueError("Invalid source URL")
    try:
        url = urlsplit(raw)
        port = url.port
        host = url.hostname
    except ValueError as exc:
        raise ValueError("Invalid source URL") from exc
    if (url.scheme != "https" or not host or url.username or url.password
            or url.fragment or (port or 443) not in PORTS):
        raise ValueError("Only HTTPS public-provider URLs on approved ports are supported")
    hostname = host.lower().rstrip(".")
    if (hostname != host.lower() or len(hostname) > 253
            or hostname.endswith((".local", ".localhost", ".internal"))
            or hostname in {"localhost", "metadata.google.internal"}):
        raise ValueError("Invalid public hostname")
    # Reject literal non-global addresses even before DNS.
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        if (not re.fullmatch(r"[a-zA-Z0-9.-]+", hostname)
                or not all(label and len(label) <= 63 for label in hostname.split("."))):
            raise ValueError("Invalid hostname") from None
    else:
        if not literal.is_global:
            raise ValueError("Non-public source IP rejected")
    if not playlist and (url.query or url.path not in ("", "/")):
        raise ValueError("Xtream server must be a base URL without path/query")
    return raw.rstrip("/") if not playlist else raw


def _validate_config(kind, fields):
    if kind not in KINDS or not isinstance(fields, dict):
        raise ValueError("Invalid source type")
    if kind == "xtream":
        if set(fields) != {"base_url", "username", "password"}:
            raise ValueError("Expected Xtream URL and credentials")
        base = _validated_url(fields["base_url"])
        username, password = fields["username"], fields["password"]
        if (not isinstance(username, str) or not isinstance(password, str)
                or not 1 <= len(username) <= 128 or not 1 <= len(password) <= 256
                or any(ord(c) < 32 or ord(c) == 127 for c in username + password)):
            raise ValueError("Invalid Xtream credentials")
        return {"base_url": base, "username": username, "password": password}
    if set(fields) != {"playlist_url"}:
        raise ValueError("Expected M3U playlist URL")
    return {"playlist_url": _validated_url(fields["playlist_url"], playlist=True)}


def _metadata(row):
    return {
        "source_id": row["source_id"], "owner": row["owner"],
        "kind": row["kind"], "name": row["title"],
        "enabled": bool(row["enabled"]), "status": row["status"],
        "updated_at": row["updated_at"],
        "credentials": "configured",  # No raw URL/username/password in APIs.
    }


def list_owned(owner):
    init()
    with ops.database() as con:
        records = con.execute(
            "SELECT source_id,owner,kind,title,enabled,status,updated_at "
            "FROM vod_sources WHERE owner=? ORDER BY created_at DESC", (owner,)
        ).fetchall()
    return [_metadata(r) for r in records]


def add_source(owner, kind, name, config):
    if not isinstance(owner, str) or len(owner) > 32:
        raise ValueError("Invalid owner")
    if not isinstance(name, str) or not NAME_RE.fullmatch(name.strip()):
        raise ValueError("Invalid source name")
    validated = _validate_config(kind, config)
    cipher = _cipher()
    ciphertext = cipher.encrypt(json.dumps(validated, separators=(",", ":")).encode())
    source_id = secrets.token_hex(16)
    stamp = int(time.time())
    init()
    with ops.database() as con:
        if con.execute(
            "SELECT COUNT(*) FROM vod_sources WHERE owner=?", (owner,)
        ).fetchone()[0] >= MAX_SOURCES:
            raise ValueError("Source limit reached")
        con.execute(
            "INSERT INTO vod_sources(source_id,owner,kind,title,config_ciphertext,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
            (source_id, owner, kind, name.strip(), ciphertext, stamp, stamp),
        )
        row = con.execute(
            "SELECT * FROM vod_sources WHERE source_id=?", (source_id,)
        ).fetchone()
    return _metadata(row)


def get_owned(owner, source_id):
    init()
    with ops.database() as con:
        row = con.execute(
            "SELECT * FROM vod_sources WHERE source_id=? AND owner=?",
            (source_id, owner),
        ).fetchone()
    if row is None:
        raise KeyError("Source not found")
    return row


def _invalidate_index(con, source_id, *, remove_manifest_mapping=False):
    # These tables are created only in the v0.5c playback stage; source
    # management still works in the earlier v0.5a code.
    tables = {row["name"] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    for table in ("tenant_media", "tenant_episodes", "tenant_sync_guard"):
        if table in tables:
            con.execute(f"DELETE FROM {table} WHERE source_id=?", (source_id,))
    if remove_manifest_mapping and "manifest_sources" in tables:
        con.execute(
            "DELETE FROM manifest_sources WHERE source_id=?", (source_id,)
        )


def remove_owned(owner, source_id):
    init()
    with ops.database() as con:
        existing = con.execute(
            "SELECT 1 FROM vod_sources WHERE owner=? AND source_id=?",
            (owner, source_id),
        ).fetchone()
        if not existing:
            raise KeyError("Source not found")
        _invalidate_index(con, source_id, remove_manifest_mapping=True)
        con.execute(
            "DELETE FROM vod_sources WHERE owner=? AND source_id=?",
            (owner, source_id),
        )


def change_owned(owner, source_id, *, name=None, enabled=None, config=None):
    row = get_owned(owner, source_id)
    if name is None and enabled is None and config is None:
        raise ValueError("No changes")
    if name is not None and (not isinstance(name, str) or
                             not NAME_RE.fullmatch(name.strip())):
        raise ValueError("Invalid source name")
    if enabled is not None and not isinstance(enabled, bool):
        raise ValueError("Invalid enabled flag")
    ciphertext = row["config_ciphertext"]
    status = row["status"]
    if config is not None:
        ciphertext = _cipher().encrypt(
            json.dumps(_validate_config(row["kind"], config),
                       separators=(",", ":")).encode()
        )
        status = "untested"
    with ops.database() as con:
        if config is not None:
            # Old Stremio links must no longer resolve to previous provider
            # rows after a source's credentials or upstream URL is replaced.
            _invalidate_index(con, source_id)
        con.execute(
            "UPDATE vod_sources SET title=?,enabled=?,config_ciphertext=?,"
            "status=?,updated_at=? WHERE source_id=? AND owner=?",
            (name.strip() if name is not None else row["title"],
             int(enabled) if enabled is not None else row["enabled"],
             ciphertext, status, int(time.time()), source_id, owner),
        )
        result = con.execute(
            "SELECT * FROM vod_sources WHERE owner=? AND source_id=?",
            (owner, source_id),
        ).fetchone()
    return _metadata(result)


def _config(row):
    try:
        content = _cipher().decrypt(row["config_ciphertext"])
        return json.loads(content.decode("utf-8"))
    except (InvalidToken, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Cannot decrypt source configuration") from exc


async def _resolve_public(hostname, port):
    # DNS happens only for the intended public host. All returned IPs must be
    # globally routable, not loopback/LAN/link-local/cloud metadata.
    result = await asyncio.to_thread(
        socket.getaddrinfo, hostname, port, type=socket.SOCK_STREAM
    )
    addresses = {item[4][0] for item in result}
    if not addresses or len(addresses) > 16:
        raise ValueError("Public DNS resolution failed")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("Non-public provider DNS result rejected")
    return sorted(addresses)[0]


async def _bounded_https(url, *, params=None, limit=MAX_JSON):
    """Pin the resolved public IP for the actual TLS connection.

    No redirects, environment proxies, or cookies; cert hostname validated
    via SNI and Host while TCP goes to pinned public IP.
    """
    target = urlsplit(_validated_url(url, playlist=True))
    host = target.hostname
    port = target.port or 443
    address = await _resolve_public(host, port)
    # httpx uses the IP as the actual TCP destination. The SNI extension
    # ensures the TLS peer cert is verified against the original hostname.
    netloc = f"[{address}]" if ":" in address else address
    netloc += f":{port}"
    pinned = urlunsplit(("https", netloc, target.path or "/", target.query, ""))
    headers = {"Host": target.netloc, "Accept": "application/json, */*"}
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(12.0, connect=4.0),
        follow_redirects=False, trust_env=False,
    ) as client:
        async with client.stream(
            "GET", pinned, params=params, headers=headers,
            extensions={"sni_hostname": host},
        ) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                raise ValueError("Provider redirects are not permitted")
            response.raise_for_status()
            chunks = bytearray()
            async for part in response.aiter_bytes():
                chunks.extend(part)
                if len(chunks) > limit:
                    raise ValueError("Provider response too large")
            return bytes(chunks)


def _m3u_preview(raw):
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("M3U must use UTF-8") from exc
    lines = text.splitlines()
    if not lines or lines[0].strip() != "#EXTM3U":
        raise ValueError("Invalid M3U header")
    if len(lines) > 20000 or any(len(line) > 4096 for line in lines):
        raise ValueError("Playlist exceeds limits")
    # Only count candidate EXTINF entries; a separate later release
    # will implement VOD identity matching and provider-scoped indexing.
    total = sum(line.startswith("#EXTINF:") for line in lines)
    return {"entries": total, "vod_ready": False}


async def test_owned(owner, source_id):
    row = get_owned(owner, source_id)
    if not row["enabled"]:
        raise ValueError("Source disabled")
    config = _config(row)
    if row["kind"] == "xtream":
        payload = await _bounded_https(
            config["base_url"] + "/player_api.php",
            params={"username": config["username"],
                    "password": config["password"]},
        )
        try:
            data = json.loads(payload)
        except ValueError as exc:
            raise ValueError("Xtream returned invalid JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("user_info"), dict):
            raise ValueError("Invalid Xtream response")
        ok = str(data["user_info"].get("auth", "0")) == "1"
        if not ok:
            raise ValueError("Xtream authentication failed")
        summary = {"status": "connected", "type": "xtream", "vod_ready": False}
    else:
        raw = await _bounded_https(config["playlist_url"], limit=MAX_M3U)
        summary = {"status": "connected", "type": "m3u", **_m3u_preview(raw)}
    with ops.database() as con:
        con.execute(
            "UPDATE vod_sources SET status='connected',updated_at=? "
            "WHERE source_id=? AND owner=?",
            (int(time.time()), source_id, owner),
        )
    return summary
