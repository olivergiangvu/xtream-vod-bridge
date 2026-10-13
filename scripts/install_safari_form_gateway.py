#!/usr/bin/env python3
"""Replace nginx HTTP Basic prompt with authenticated form/session gateway.

Only changes the existing Xtream /admin/ location and adds three private
gateway locations to the SAME 18450 vhost. No /a/ or /play/ changes.
Requires the updated Admin container (with /gateway/ and gate-check routes)
to be running and an already provisioned Owner password.

Run: sudo python3 scripts/install_safari_form_gateway.py
Rollback: the script prints a root-only vhost backup path on PASS.
"""
import hashlib
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
SNIPPET = Path("/etc/nginx/snippets/xtream-admin-form-gateway.conf")
BACKUPS = Path("/etc/homedocker-backup/xtream-admin-18450")
DOMAIN = "olivergiangvu.asuscomm.com"
IP = "192.168.50.153"
PORT = 18450
CERT = Path("/etc/nginx/ssl/olivergiangvu.asuscomm.com/fullchain.pem")
OLD_MARKER = "# HomeDocker Safari Private Relay gateway v2 (Basic required for ALL clients)"
NEW_MARKER = "# HomeDocker Safari form gateway (auth_request session required)"
INCLUDE = "include /etc/nginx/snippets/xtream-admin-form-gateway.conf;"


NGINX_SNIPPET = r"""
# Protected by the existing Owner password and a signed, server-side session.
# These are included ONLY in the 18450 HTTPS DDNS server block.
location = /__xtream_admin_gate_check {
    internal;
    auth_basic off;
    auth_request off;
    proxy_pass http://127.0.0.1:18768/api/auth/gate-check;
    proxy_http_version 1.1;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Cookie $http_cookie;
    proxy_set_header Authorization "";
    proxy_set_header X-Forwarded-Proto https;
    access_log off;
}

location @xtream_admin_to_login {
    return 302 /admin-signin/;
}

location ^~ /admin-signin/ {
    auth_basic off;
    auth_request off;
    allow all;
    proxy_pass http://127.0.0.1:18768/gateway/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For "";
    proxy_set_header Authorization "";
    proxy_set_header Connection "";
    proxy_connect_timeout 5s;
    proxy_read_timeout 30s;
    client_max_body_size 4k;
    access_log off;
    add_header Cache-Control "no-store" always;
    # Native login form POST needs Origin != null; never use no-referrer here.
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}
"""


def proc(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=18)


def code(path):
    r = proc("curl", "--noproxy", "*", "-sS", "--max-time", "7",
             "--resolve", f"{DOMAIN}:{PORT}:{IP}",
             "-o", "/dev/null", "-w", "%{http_code}",
             f"https://{DOMAIN}:{PORT}{path}")
    return r.stdout.strip() if r.returncode == 0 else "000"


def local_code(path):
    r = proc("curl", "--noproxy", "*", "-sS", "--max-time", "4",
             "-o", "/dev/null", "-w", "%{http_code}",
             f"http://127.0.0.1:18768{path}")
    return r.stdout.strip() if r.returncode == 0 else "000"


def fingerprint(cert):
    r = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"],
                       capture_output=True, timeout=10, check=True)
    return hashlib.sha256(r.stdout).hexdigest()


def tls_fingerprint():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False   # Fingerprint-only preflight, not HTTP trust bypass
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((IP, PORT), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=DOMAIN) as conn:
            return hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()


def slice_admin(source):
    matches = list(re.finditer(r"(?m)^[ \t]*location\s+\^~\s+/admin/\s*\{", source))
    if len(matches) != 1:
        raise RuntimeError("Exactly one /admin/ location required")
    opening = matches[0]
    depth = 1
    pos = opening.end()
    while pos < len(source) and depth:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    if depth:
        raise RuntimeError("Unbalanced /admin/ location")
    return opening.start(), opening.end(), pos


def build_config(source):
    if NEW_MARKER in source or SNIPPET.exists() or INCLUDE in source:
        raise RuntimeError("Form gateway already installed or partial install detected")
    if source.count(OLD_MARKER) != 1:
        raise RuntimeError("Expected installed Basic gateway v2 marker")
    if len(re.findall(r"(?m)^[ \t]*listen\s+18450\s+ssl\s*;", source)) != 1:
        raise RuntimeError("Unexpected HTTPS listener count")
    if len(re.findall(
        r"(?m)^[ \t]*server_name\s+olivergiangvu\.asuscomm\.com\s*;", source
    )) != 1:
        raise RuntimeError("Unexpected HTTPS server name")
    start, body_start, end = slice_admin(source)
    old_body = source[body_start:end - 1]
    for expected in (
        "proxy_pass http://127.0.0.1:18768/;",
        "auth_basic_user_file",
        "auth_basic",
        "satisfy all;",
    ):
        if expected not in old_body:
            raise RuntimeError("Existing /admin/ no longer matches Gateway v2")
    # Preserve all proxy settings; remove the old Basic directives only.
    clean = re.sub(
        r"(?m)^\s*(?:auth_basic(?:_user_file)?|satisfy|allow|deny)\s+[^;\n]+;\s*\n",
        "\n", old_body
    )
    clean = clean.replace(OLD_MARKER, "")
    head = (
        f"\n        {NEW_MARKER}\n"
        "        satisfy all;\n"
        "        allow all;\n"
        "        auth_basic off;\n"
        "        auth_request /__xtream_admin_gate_check;\n"
        "        error_page 401 = @xtream_admin_to_login;\n"
    )
    new_location = source[start:body_start] + head + clean + "}"
    changed = source[:start] + new_location + source[end:]
    server = list(re.finditer(r"(?m)^[ \t]*server\s*\{", changed))
    if len(server) != 1:
        raise RuntimeError("Expected exactly one 18450 server block")
    insert_at = server[0].end()
    changed = changed[:insert_at] + "\n    " + INCLUDE + "\n" + changed[insert_at:]
    if (changed.count(INCLUDE) != 1 or changed.count(NEW_MARKER) != 1 or
            "/play/" in NGINX_SNIPPET or "/a/" in NGINX_SNIPPET):
        raise RuntimeError("Invalid patch construction")
    return changed


def atomic_write(path, data, mode):
    fd, temp = tempfile.mkstemp(prefix=".xtream-form-", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("Run with sudo on Linux HomeDocker")
    if not VHOST.is_file() or not CERT.is_file():
        raise RuntimeError("Missing existing vhost/certificate")
    for route, expected in (("/gateway/", "200"),
                            ("/api/auth/gate-check", "401"),
                            ("/api/auth/session", "200")):
        actual = local_code(route)
        if actual != expected:
            raise RuntimeError(f"STOP: updated Admin backend not ready: {route}={actual}")
    if proc("nginx", "-t").returncode != 0:
        raise RuntimeError("nginx baseline validation failed")
    if fingerprint(CERT) != tls_fingerprint():
        raise RuntimeError("Existing DDNS TLS fingerprint mismatch")
    before = VHOST.read_text()
    patched = build_config(before)
    if code("/admin/") != "401":
        raise RuntimeError("Existing Basic gateway baseline unexpected")
    BACKUPS.mkdir(parents=True, exist_ok=True)
    BACKUPS.chmod(0o700)
    backup = BACKUPS / (
        "xtream-vod-bridge-18450-pre-form-"
        + time.strftime("%Y%m%d-%H%M%S") + ".conf.bak"
    )
    shutil.copy2(VHOST, backup)
    backup.chmod(0o600)
    old_mode = stat.S_IMODE(VHOST.stat().st_mode)
    SNIPPET.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(SNIPPET, "x", encoding="utf8") as out:
            out.write(NGINX_SNIPPET)
        SNIPPET.chmod(0o644)
        atomic_write(VHOST, patched, old_mode)
        if proc("nginx", "-t").returncode != 0:
            raise RuntimeError("nginx config invalid after patch")
        if proc("systemctl", "reload", "nginx").returncode != 0:
            raise RuntimeError("nginx reload failed")
        expect = {
            "ANONYMOUS_ADMIN": ("/admin/", "302"),
            "ANONYMOUS_API": ("/admin/api/overview", "302"),
            "ANONYMOUS_JS": ("/admin/assets/app.js", "302"),
            "FORM_LOGIN": ("/admin-signin/", "200"),
        }
        ready = False
        for _ in range(15):
            time.sleep(0.8)
            seen = {key: code(path) for key, (path, _) in expect.items()}
            if all(seen[key] == want for key, (_, want) in expect.items()):
                ready = True
                break
        for key, value in seen.items():
            print(f"{key}={value}")
        if not ready:
            raise RuntimeError("Session-gate HTTPS validation failed")
        if tls_fingerprint() != fingerprint(CERT):
            raise RuntimeError("Public DDNS certificate changed")
        print("SAFARI_FORM_GATEWAY=PASS")
        print("BACKUP_PATH=" + str(backup))
        print("Open https://" + DOMAIN + ":" + str(PORT) + "/admin/")
        print("Use existing Admin password. No Basic gateway prompt.")
    except Exception as exc:
        shutil.copy2(backup, VHOST)
        SNIPPET.unlink(missing_ok=True)
        if proc("nginx", "-t").returncode == 0:
            proc("systemctl", "reload", "nginx")
        print("ROLLBACK_ATTEMPTED=True")
        raise RuntimeError("STOP: form gateway activation failed: " + type(exc).__name__) from None


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(str(exc))
        sys.exit(1)
