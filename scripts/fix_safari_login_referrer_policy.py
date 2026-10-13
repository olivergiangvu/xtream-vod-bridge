#!/usr/bin/env python3
"""Safely fix Referrer-Policy: no-referrer causing Origin:null on Safari HTML POST.

Only patches the ACTIVE /admin-signin/ nginx snippet. Does not touch:
  - public DDNS TLS, /admin/ session gate, /a/, /play/, Docker or credentials
  - Safari/iCloud Private Relay settings
Precondition: updated 0.4.2.3 Admin backend already running.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SNIPPET = Path("/etc/nginx/snippets/xtream-admin-form-gateway.conf")
VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
BACKUPS = Path("/etc/homedocker-backup/xtream-admin-18450")
OLD = '    add_header Referrer-Policy "no-referrer" always;'
NEW = '    add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
DOMAIN = "olivergiangvu.asuscomm.com"
BASE = "https://" + DOMAIN + ":18450"
LAN_IP = "192.168.50.153"


def cmd(*args):
    return subprocess.run(args, capture_output=True, text=True, timeout=15)


def headers_url(url, resolve=False):
    args = ["curl", "--noproxy", "*", "-sS", "--max-time", "8"]
    if resolve:
        args += ["--resolve", DOMAIN + ":18450:" + LAN_IP]
    args += ["-D", "-", "-o", "/dev/null", url]
    out = cmd(*args)
    if out.returncode:
        raise RuntimeError("HTTPS response unavailable")
    return out.stdout


def login_policy(headers):
    matches = re.findall(r"(?im)^referrer-policy:\s*([^\r\n]+)", headers)
    return [s.strip().lower() for s in matches]


def write_atomic(path, source):
    fd, p = tempfile.mkstemp(prefix=".xtream-referrer-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "w") as w:
            w.write(source)
            w.flush()
            os.fsync(w.fileno())
        os.replace(p, path)
    finally:
        if os.path.exists(p):
            os.unlink(p)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo on HomeDocker")
    if not SNIPPET.is_file() or not VHOST.is_file():
        raise RuntimeError("STOP: active nginx form gateway files missing")
    if "include /etc/nginx/snippets/xtream-admin-form-gateway.conf;" not in VHOST.read_text():
        raise RuntimeError("STOP: snippet not referenced by active DDNS vhost")
    contents = SNIPPET.read_text()
    if contents.count(OLD) != 1 or "location ^~ /admin-signin/" not in contents:
        raise RuntimeError("STOP: installed gateway differs from expected version")
    if "location = /__xtream_admin_gate_check" not in contents:
        raise RuntimeError("STOP: internal session gate missing")

    # Backend first: prevent nginx changing the header before the patched
    # HTML/meta/app header is running, which would leave mixed policy values.
    backend = cmd("curl", "--noproxy", "*", "-sS", "--max-time", "7",
                  "-D", "-", "http://127.0.0.1:18768/gateway/")
    if backend.returncode or "strict-origin-when-cross-origin" not in backend.stdout:
        raise RuntimeError("STOP: updated Admin backend 0.4.2.3 not ready")
    if 'content="strict-origin-when-cross-origin"' not in backend.stdout:
        raise RuntimeError("STOP: updated login page meta policy missing")

    before = login_policy(headers_url(BASE + "/admin-signin/", resolve=True))
    if "no-referrer" not in before:
        raise RuntimeError("STOP: expected old Referrer-Policy not observed; inspect nginx")
    if cmd("nginx", "-t").returncode:
        raise RuntimeError("STOP: nginx config baseline invalid")

    BACKUPS.mkdir(parents=True, exist_ok=True)
    BACKUPS.chmod(0o700)
    backup = BACKUPS / (
        "xtream-admin-form-gateway-pre-referrer-"
        + time.strftime("%Y%m%d-%H%M%S") + ".conf.bak"
    )
    if backup.exists():
        raise RuntimeError("STOP: backup collision")
    shutil.copy2(SNIPPET, backup)
    backup.chmod(0o600)

    try:
        write_atomic(SNIPPET, contents.replace(OLD, NEW))
        if cmd("nginx", "-t").returncode:
            raise RuntimeError("nginx validation failed")
        if cmd("systemctl", "reload", "nginx").returncode:
            raise RuntimeError("nginx reload failed")
        ok = False
        for i in range(1, 16):
            time.sleep(0.8)
            try:
                policies = login_policy(headers_url(BASE + "/admin-signin/", resolve=True))
                if (policies and all(x == "strict-origin-when-cross-origin" for x in policies)):
                    ok = True
                    break
            except RuntimeError:
                pass
        if not ok:
            raise RuntimeError("HTTPS response has wrong or duplicated Referrer-Policy")
        # Session protection MUST remain enforced.
        r = cmd("curl", "--noproxy", "*", "-sS", "--max-time", "7",
                "--resolve", DOMAIN + ":18450:" + LAN_IP,
                "-o", "/dev/null", "-w", "%{http_code}", BASE + "/admin/")
        if r.returncode or r.stdout.strip() != "302":
            raise RuntimeError("Admin session gate regression")
        print("LOGIN_REFERRER_POLICY=strict-origin-when-cross-origin")
        print("ANONYMOUS_ADMIN=302")
        print("SAFARI_NULL_ORIGIN_FIX=PASS")
        print("BACKUP_PATH=" + str(backup))
    except Exception:
        shutil.copy2(backup, SNIPPET)
        if cmd("nginx", "-t").returncode == 0:
            cmd("systemctl", "reload", "nginx")
        print("ROLLBACK_ATTEMPTED=True")
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never print request bodies, cookies or password on error.
        print("STOP:", type(exc).__name__, str(exc))
        sys.exit(1)
