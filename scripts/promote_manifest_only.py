#!/usr/bin/env python3
"""Guarded manifest-only UI promotion onto the running HomeDocker tree.

Stage verified reviewed source files before running:
    python3 promote_manifest_only.py --source-dir /tmp/reviewed
    sudo python3 promote_manifest_only.py --source-dir /tmp/reviewed --apply

Keep the existing HomeDocker admin_ui.py (same-origin Safari fix) intact,
adding only the authenticated manifest endpoint. No nginx, .env, SQLite,
Compose, or playback changes. Fail closed on unexpected local source state.
"""
import argparse
import hashlib
import os
import shutil
import stat
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path("/opt/xtream-vod-bridge")
EXPECTED_NEW = {
    "admin_ui.py": "fc3b407a133106bb572bd3f25d09ffdb4fc8b6ef",
    "admin/index.html": "1f884ba5671680ee3f2b8c2d260399db8a967ee5",
    "admin/assets/app.js": "92b4964df4048d2e0e713469fb373778a270b0a1",
    "admin/assets/style.css": "d24a2926a6dc8d780e8f4b482b01a336a25d84f5",
}
EXPECTED_OLD_STATIC = {
    "admin/index.html": "585dc5ab332c0027fb04da2ffd76a0ea01275877",
    "admin/assets/app.js": "7b078c78219b841fb7938a4cf7e0c851dbbaa40d",
    "admin/assets/style.css": "693b1c758c25475a619586dfd78b66415a11962e",
}


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def checked_source(source_dir, path):
    data = (source_dir / path).read_bytes()
    actual = git_blob(data)
    if actual != EXPECTED_NEW[path]:
        raise RuntimeError("STOP: reviewed source digest mismatch: " + path)
    return data.decode("utf-8")


def prepare(source_dir):
    reviewed = {p: checked_source(source_dir, p) for p in EXPECTED_NEW}
    changes = {}

    for path, expected in EXPECTED_OLD_STATIC.items():
        old = (ROOT / path).read_bytes()
        if git_blob(old) != expected:
            raise RuntimeError("STOP: HomeDocker static asset differs: " + path)
        changes[path] = reviewed[path]

    path = "admin_ui.py"
    old = (ROOT / path).read_text()
    if old.count('response.headers["Referrer-Policy"] = "same-origin"') != 1:
        raise RuntimeError("STOP: local Safari origin header differs")
    if old.count('<meta name="referrer" content="same-origin">') != 1:
        raise RuntimeError("STOP: local Safari HTML meta differs")
    if "/api/manifest" in old:
        raise RuntimeError("STOP: manifest endpoint already installed")

    before = '@console.get("/api/events", dependencies=[Depends(authorize)])'
    endpoint = '@console.get("/api/manifest", dependencies=[Depends(authorize)])'
    reviewed_ui = reviewed[path]
    if (old.count(before) != 1 or
            reviewed_ui.count(before) != 1 or
            reviewed_ui.count(endpoint) != 1):
        raise RuntimeError("STOP: unexpected admin backend structure")
    i = reviewed_ui.index(endpoint)
    j = reviewed_ui.index(before, i)
    addition = reviewed_ui[i:j]
    if 'bridge.ADDON_TOKEN' not in addition or 'Depends(authorize)' not in addition:
        raise RuntimeError("STOP: reviewed endpoint guard is missing")
    new = old.replace(before, addition + before, 1)
    compile(new, str(ROOT / path), "exec")
    changes[path] = new
    return changes


def promote(changes):
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backups = {}
    for relative in changes:
        src = ROOT / relative
        backup = src.with_name(src.name + ".bak-manifest-" + stamp)
        shutil.copy2(src, backup)
        backup.chmod(0o600)
        backups[relative] = backup

    installed = []
    try:
        for relative, content in changes.items():
            target = ROOT / relative
            original = target.stat()
            fd, temp = tempfile.mkstemp(prefix=".manifest-", dir=target.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    output.write(content)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temp, stat.S_IMODE(original.st_mode))
                os.chown(temp, original.st_uid, original.st_gid)
                os.replace(temp, target)
                installed.append(relative)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
    except Exception:
        for relative in installed:
            shutil.copy2(backups[relative], ROOT / relative)
        raise

    print("SOURCE_PATCH=PASS")
    for relative, backup in backups.items():
        print("BACKUP:", relative, "=>", backup)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    changes = prepare(args.source_dir)
    print("MANIFEST_PRECHECK=PASS")
    print("FILES=" + ",".join(changes))
    print("NGINX_SQLITE_PLAYBACK_MUTATIONS=NONE")
    if args.apply:
        if os.geteuid() != 0:
            raise SystemExit("STOP: sudo required")
        promote(changes)
    else:
        print("DRY_RUN=PASS")


if __name__ == "__main__":
    main()
