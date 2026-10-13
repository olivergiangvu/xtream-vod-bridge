#!/usr/bin/env python3
"""Safely promote only the v0.4.2.6 username-login change onto HomeDocker.

Download the reviewed admin_ui.py and admin_auth.py at the pinned Git commit,
verify their Git blob SHA-1 values, then execute this helper with --source-dir.
Runs preflight without writes unless --apply is explicitly supplied.

The HomeDocker login page/header uses same-origin rather than the PR's
strict-origin-when-cross-origin. Preserve the already-verified live policy.
Never modify nginx, .env, SQLite, Compose or playback.
"""
import argparse
import hashlib
import os
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path

EXPECTED_BLOBS = {
    "admin_ui.py": "af816e9f9f40c02b7dcb3dc2217de3898103d19c",
    "admin_auth.py": "ecd3cd695c2046357d7fe36cd4458bff5ddd7774",
}
HOST_ROOT = Path("/opt/xtream-vod-bridge")


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def read_reviewed(source_dir: Path, filename: str) -> str:
    data = (source_dir / filename).read_bytes()
    actual = blob_sha(data)
    if actual != EXPECTED_BLOBS[filename]:
        raise RuntimeError(f"STOP: Git blob checksum mismatch for {filename} ({actual})")
    return data.decode("utf-8")


def replace_one(source: str, old: str, new: str, label: str) -> str:
    matches = source.count(old)
    if matches != 1:
        raise RuntimeError(f"STOP: {label}: expected 1 source match, found {matches}")
    return source.replace(old, new, 1)


def section(text: str, begin: str, end: str, label: str) -> str:
    if text.count(begin) != 1 or text.count(end) != 1:
        raise RuntimeError(f"STOP: unexpected {label} anchors")
    i = text.index(begin)
    j = text.index(end, i)
    return text[i:j]


def prepare(root: Path, source_dir: Path):
    local_ui = (root / "admin_ui.py").read_text()
    local_auth = (root / "admin_auth.py").read_text()
    reviewed_ui = read_reviewed(source_dir, "admin_ui.py")
    reviewed_auth = read_reviewed(source_dir, "admin_auth.py")

    if ('response.headers["Referrer-Policy"] = "same-origin"' not in local_ui or
            '<meta name="referrer" content="same-origin">' not in local_ui):
        raise RuntimeError("STOP: unexpected live Safari Referrer-Policy baseline")
    if ('name="username"' in local_ui or 'def login(password, username="owner"):' in local_auth):
        raise RuntimeError("STOP: login patch seems already installed")

    original_form = section(
        local_ui, "def _gate_page(message: str, nonce: str):",
        '@console.get("/gateway/"', "local login form",
    )
    new_form = section(
        reviewed_ui, 'def _gate_page(message: str, nonce: str, username: str = "owner"):',
        '@console.get("/gateway/"', "reviewed login form",
    )
    new_form = replace_one(
        new_form,
        '<meta name="referrer" content="strict-origin-when-cross-origin">',
        '<meta name="referrer" content="same-origin">',
        "preserve Safari meta",
    )
    local_ui = replace_one(local_ui, original_form, new_form, "login HTML/UI")

    changes = [
        (
            'if set(fields) != {"password", "nonce"} or any(len(v) != 1 for v in fields.values()):',
            'if set(fields) not in ({"password", "nonce"}, {"password", "nonce", "username"}) or any(len(v) != 1 for v in fields.values()):',
            "form shape",
        ),
        (
            '        password = fields["password"][0]\n',
            '        password = fields["password"][0]\n'
            '        # Backwards-compatible with an already-open, password-only form.\n'
            '        username = fields.get("username", ["owner"])[0]\n',
            "username parsing",
        ),
        (
            '        session, _csrf = admin_auth.login(password)\n',
            '        session, _csrf = admin_auth.login(password, username=username)\n',
            "form Owner verification",
        ),
        (
            '        response = HTMLResponse(_gate_page("Incorrect password.", new_nonce),\n',
            '        response = HTMLResponse(_gate_page("Incorrect username or password.", new_nonce, username),\n',
            "generic login failure",
        ),
        (
            '    if set(payload) != {"password"}:\n'
            '        raise HTTPException(status_code=422, detail="Expected password only")',
            '    if set(payload) not in ({"password"}, {"password", "username"}):\n'
            '        raise HTTPException(status_code=422, detail="Expected password and optional username")',
            "JSON backward compatibility",
        ),
        (
            '        session, csrf = admin_auth.login(payload["password"])\n',
            '        session, csrf = admin_auth.login(payload["password"], username=payload.get("username", "owner"))\n',
            "JSON optional username",
        ),
    ]
    for old, new, label in changes:
        if reviewed_ui.count(new) != 1:
            raise RuntimeError(f"STOP: reviewed source mismatch: {label}")
        local_ui = replace_one(local_ui, old, new, label)

    replacements = [
        (
            "def login(password):\n    if not origin_configured():",
            'def login(password, username="owner"):\n'
            '    # Existing single Owner account. Keep the username check inside the\n'
            '    # password-verification flow so invalid usernames share rate limiting.\n'
            '    if not origin_configured():',
            "Owner login signature",
        ),
        (
            '        good = _verify(password, account)\n        if not good:\n',
            '        valid_username = (isinstance(username, str) and len(username) <= 64\n'
            '                          and hmac.compare_digest(username.encode("utf-8"), b"owner"))\n'
            '        good = _verify(password, account) and valid_username\n'
            '        if not good:\n',
            "rate-limited username matching",
        ),
    ]
    for old, new, label in replacements:
        if reviewed_auth.count(new) != 1:
            raise RuntimeError(f"STOP: reviewed auth mismatch: {label}")
        local_auth = replace_one(local_auth, old, new, label)

    if ('autocomplete="username"' not in local_ui or
            'autocomplete="current-password"' not in local_ui or
            '<meta name="referrer" content="same-origin">' not in local_ui):
        raise RuntimeError("STOP: login safety assertions failed")
    for name, text in (("admin_ui.py", local_ui), ("admin_auth.py", local_auth)):
        compile(text, str(root / name), "exec")
    return {"admin_ui.py": local_ui, "admin_auth.py": local_auth}


def apply(root: Path, prepared: dict):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backups = {}
    for filename in prepared:
        original = root / filename
        backup = original.with_name(filename + ".bak-login-ux-" + stamp)
        shutil.copy2(original, backup)
        backup.chmod(0o600)
        backups[filename] = backup
    updated = []
    try:
        for filename, source in prepared.items():
            target = root / filename
            st = target.stat()
            fd, name = tempfile.mkstemp(prefix=".xtream-login-", dir=str(root))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    out.write(source)
                    out.flush()
                    os.fsync(out.fileno())
                os.chmod(name, stat.S_IMODE(st.st_mode))
                os.chown(name, st.st_uid, st.st_gid)
                os.replace(name, target)
                updated.append(filename)
            finally:
                if os.path.exists(name):
                    os.unlink(name)
    except Exception:
        for filename in updated:
            shutil.copy2(backups[filename], root / filename)
        raise
    for filename, backup in backups.items():
        print(f"BACKUP_{filename}={backup}")
    print("PATCH_SOURCE=PASS")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    prepared = prepare(HOST_ROOT, args.source_dir)
    print("SOURCE_AND_SYNTAX_PRECHECK=PASS")
    print("TARGETS=admin_ui.py,admin_auth.py")
    print("NGINX_SQLITE_PLAYBACK_MODIFICATIONS=NONE")
    if args.apply:
        if os.geteuid() != 0:
            raise SystemExit("STOP: --apply requires sudo")
        apply(HOST_ROOT, prepared)
    else:
        print("DRY_RUN=PASS (no files changed)")


if __name__ == "__main__":
    main()
