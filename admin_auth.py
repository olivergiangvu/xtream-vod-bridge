"""Password login for the private admin UI, with opaque HttpOnly sessions.

No default password. Provision/rotate by CLI on the Docker host:
    docker exec -it xtream-vod-admin python -m admin_auth set-password

The legacy ADMIN_TOKEN remains an emergency service-to-service API bearer
credential; it is never shown in browser UI or automatically accepted as a
password. New browser login uses a strong passphrase + cookie + CSRF.
"""
import getpass
import hashlib
import hmac
import os
import secrets
import sqlite3
import sys
import time
from urllib.parse import urlsplit
import ops

COOKIE = "xtream_admin_session"
COOKIE_PATH = "/admin/"
SESSION_SECONDS = 12 * 3600
ITERATIONS = 600_000
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 10 * 60
LOCK_SECONDS = 15 * 60

# Prefer explicitly configured admin HTTPS origin. For the existing
# HomeDocker same-port deployment, derive it from PUBLIC_BASE_URL, dropping
# any addon path prefix; avoids another .env edit for routine Admin setup.
# Empty/HTTP origin fails closed: browser-password-login stays disabled.
def _public_origin():
    explicit = os.getenv("ADMIN_PUBLIC_ORIGIN", "").strip().rstrip("/")
    if explicit:
        return explicit
    try:
        url = urlsplit(os.getenv("PUBLIC_BASE_URL", ""))
        if url.scheme == "https" and url.hostname and not url.username and not url.password:
            return url.scheme + "://" + url.netloc
    except ValueError:
        pass
    return ""


PUBLIC_ORIGIN = _public_origin()


def init():
    with ops.database() as con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS admin_password ("
            "id INTEGER PRIMARY KEY CHECK(id=1),"
            "salt BLOB NOT NULL, digest BLOB NOT NULL,"
            "rounds INTEGER NOT NULL, changed_at INTEGER NOT NULL)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS admin_sessions ("
            "session_digest TEXT PRIMARY KEY, csrf TEXT NOT NULL,"
            "expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)"
        )
        con.execute(
            "CREATE TABLE IF NOT EXISTS admin_login_guard ("
            "id INTEGER PRIMARY KEY CHECK(id=1),"
            "attempts INTEGER NOT NULL DEFAULT 0,"
            "window_start INTEGER NOT NULL DEFAULT 0,"
            "locked_until INTEGER NOT NULL DEFAULT 0)"
        )


def configured():
    init()
    with ops.database() as con:
        return con.execute("SELECT 1 FROM admin_password WHERE id=1").fetchone() is not None


def origin_configured():
    try:
        u = urlsplit(PUBLIC_ORIGIN)
        return (u.scheme == "https" and bool(u.hostname)
                and not (u.path or u.query or u.fragment or u.username or u.password))
    except ValueError:
        return False


def same_origin(request):
    # Validate the Origin of each password-login attempt and every cookie-backed
    # mutation, even when served by a reverse proxy with a forwarded Host.
    return origin_configured() and request.headers.get("origin", "") == PUBLIC_ORIGIN


def password_is_strong(password):
    return (isinstance(password, str) and 14 <= len(password) <= 128
            and not any(ord(c) < 32 or ord(c) == 127 for c in password)
            and bool(password.strip()))


def set_password(password):
    if not password_is_strong(password):
        raise ValueError("Choose a passphrase of 14–128 printable characters")
    init()
    salt = secrets.token_bytes(24)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                salt, ITERATIONS)
    with ops.database() as con:
        con.execute(
            "INSERT INTO admin_password(id,salt,digest,rounds,changed_at)"
            " VALUES (1,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "salt=excluded.salt,digest=excluded.digest,"
            "rounds=excluded.rounds,changed_at=excluded.changed_at",
            (salt, digest, ITERATIONS, int(time.time())),
        )
        # A password rotation immediately invalidates ALL browser sessions.
        con.execute("DELETE FROM admin_sessions")
        con.execute("DELETE FROM admin_login_guard")
    return True


def _verify(password, row):
    salt, digest, rounds = row
    if rounds < ITERATIONS or rounds > 2_000_000:
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(candidate, digest)


class LoginThrottled(Exception):
    pass


def login(password):
    if not origin_configured():
        raise RuntimeError("HTTPS public origin not configured")
    if not isinstance(password, str) or len(password) > 256:
        raise ValueError("Invalid credentials")
    init()
    now = int(time.time())
    with ops.database() as con:
        status = con.execute(
            "SELECT attempts,window_start,locked_until "
            "FROM admin_login_guard WHERE id=1"
        ).fetchone()
        if status and status["locked_until"] > now:
            raise LoginThrottled()
        account = con.execute(
            "SELECT salt,digest,rounds FROM admin_password WHERE id=1"
        ).fetchone()
        if account is None:
            raise RuntimeError("Admin password not provisioned")
        good = _verify(password, account)
        if not good:
            attempts = 1
            if status and now - status["window_start"] <= WINDOW_SECONDS:
                attempts = status["attempts"] + 1
            window_start = (status["window_start"] if status and
                            now - status["window_start"] <= WINDOW_SECONDS else now)
            locked_until = now + LOCK_SECONDS if attempts >= MAX_ATTEMPTS else 0
            con.execute(
                "INSERT INTO admin_login_guard(id,attempts,window_start,locked_until)"
                " VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "attempts=excluded.attempts,window_start=excluded.window_start,"
                "locked_until=excluded.locked_until",
                (attempts, window_start, locked_until),
            )
            # Do NOT throw while inside the transaction: it would roll back
            # the failed-attempt counter, silently disabling lockout.
        else:
            con.execute("DELETE FROM admin_login_guard")
            session = secrets.token_urlsafe(36)
            csrf = secrets.token_urlsafe(32)
            digest = hashlib.sha256(session.encode()).hexdigest()
            con.execute("DELETE FROM admin_sessions WHERE expires_at <= ?", (now,))
            con.execute(
                "INSERT INTO admin_sessions(session_digest,csrf,expires_at,created_at) "
                "VALUES(?,?,?,?)",
                (digest, csrf, now + SESSION_SECONDS, now),
            )
    if not good:
        raise ValueError("Invalid credentials")
    return session, csrf


def session_info(session):
    if not isinstance(session, str) or len(session) < 32 or len(session) > 200:
        return None
    digest = hashlib.sha256(session.encode()).hexdigest()
    with ops.database() as con:
        row = con.execute(
            "SELECT csrf,expires_at FROM admin_sessions "
            "WHERE session_digest=? AND expires_at>?",
            (digest, int(time.time())),
        ).fetchone()
    return dict(row) if row else None


def delete_session(session):
    if not session:
        return
    digest = hashlib.sha256(session.encode()).hexdigest()
    with ops.database() as con:
        con.execute("DELETE FROM admin_sessions WHERE session_digest=?", (digest,))


def command_line():
    if sys.argv[1:] != ["set-password"]:
        raise SystemExit("Usage: python -m admin_auth set-password")
    try:
        p = getpass.getpass("New Admin password (14+ characters): ")
        q = getpass.getpass("Confirm Admin password: ")
        if p != q:
            raise ValueError("Passwords do not match")
        set_password(p)
    except (KeyboardInterrupt, EOFError, ValueError) as exc:
        raise SystemExit("Password setup cancelled or rejected") from None
    finally:
        p = q = None
    print("ADMIN_PASSWORD_SET=PASS; browser sessions revoked")


if __name__ == "__main__":
    command_line()
