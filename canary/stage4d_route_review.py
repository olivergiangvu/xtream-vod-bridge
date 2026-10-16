#!/usr/bin/env python3
"""HomeDocker Stage 4D: generate and validate an in-memory nginx Canary proposal.

No edits to /etc/nginx, Compose, containers, router, firewall or active listeners.
Scratch nginx -t runs with its own temporary -c config; all files auto-delete.
Never print or upload original nginx config, cookies, secrets or candidate body.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.request import build_opener, ProxyHandler, Request

VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
VHOST_SHA = "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35"
INCLUDE_PATH = "/etc/nginx/snippets/xtream-canary-18450.conf"
TEMPLATE_REF = "55bde74372a6194816e14ae033faebf8d5abc61c"
TEMPLATE_BLOB = "1280d7ebd738f3de7d7300606ab0096f2be3bb6d"
TEMPLATE_URL = (
    "https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
    + TEMPLATE_REF + "/canary/xtream-canary-18450.nginx.template"
)
NETWORK = "xtream-vod-canary_private_canary"
LAN = "192.168.50.0/24"
IMAGES = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
    "xtream-vod-canary-admin": "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f",
    "xtream-vod-canary-playback": "homedocker/xtream-vod-canary:5c2f02233a0f",
}


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=25)
    if result.returncode != 0:
        raise ValueError("Read-only check failed: " + args[0])
    return result.stdout


def git_blob_sha(data):
    header = b"blob " + str(len(data)).encode() + b"\x00"
    return hashlib.sha1(header + data).hexdigest()


def render(source, template, admin_ip, play_ip):
    if "/canary" in source or "xtream-canary-18450.conf" in source:
        raise ValueError("Canary routes already exist; refuse duplicate")
    servers = list(re.finditer(r"(?m)^[ \t]*server[ \t]*\{[ \t]*(?:\r?\n|$)", source))
    if len(servers) != 1:
        raise ValueError("Source vhost does not contain exactly one server block")
    required = (
        r"(?m)^\s*listen\s+18450\s+ssl\s*;",
        r"(?m)^\s*server_name\s+olivergiangvu\.asuscomm\.com\s*;",
        r"auth_request\s+/__xtream_admin_gate_check",
        r"location\s+/\s*\{",
    )
    if not all(re.search(signature, source) for signature in required):
        raise ValueError("Production TLS/gateway signatures no longer match")
    for address in (admin_ip, play_ip):
        addr = ipaddress.ip_address(address)
        if addr.version != 4 or not addr.is_private:
            raise ValueError("Canary upstream must be RFC1918 IPv4")
    if admin_ip == play_ip:
        raise ValueError("Canary upstream address collision")
    replacements = {
        "__CANARY_ADMIN_IP__": (admin_ip, 3),
        "__CANARY_PLAY_IP__": (play_ip, 2),
        "__CANARY_LAN_CIDR__": (LAN, 4),
    }
    for placeholder, (replacement, exact_count) in replacements.items():
        if template.count(placeholder) != exact_count:
            raise ValueError("Nginx template placeholder count mismatch")
        template = template.replace(placeholder, replacement)
    if "__CANARY_" in template:
        raise ValueError("Nginx template contains unresolved placeholder")
    if template.count("internal;") != 1 or template.count("deny all;") != 4:
        raise ValueError("Unexpected Canary access-control template")
    if not all("location ^~ " + route in template for route in (
        "/canary/admin/", "/canary/admin-signin/", "/canary/a/", "/canary/play/"
    )):
        raise ValueError("Missing Canary security-sensitive path")
    directive = "    include " + INCLUDE_PATH + ";\n"
    index = servers[0].end()
    candidate = source[:index] + directive + source[index:]
    if candidate.replace(directive, "", 1) != source:
        raise ValueError("Byte exact rollback proof failed")
    return candidate, template, directive


def check_canary_port_isolation(obj, name):
    """Fail on active published ports, flag dormant loopback-only metadata.

    Docker metadata can retain HostConfig.PortBindings even when the live
    NetworkSettings.Ports reports null and docker port has no output.
    The recorded bind is dormant, but may activate after a recreation.
    Non-loopback configured binds always fail closed.
    """
    configured = obj["HostConfig"].get("PortBindings") or {}
    actual = obj["NetworkSettings"].get("Ports") or {}

    if not isinstance(configured, dict) or not isinstance(actual, dict):
        raise ValueError("Canary Docker port metadata malformed: " + name)

    for port, bindings in actual.items():
        if bindings is not None:
            # Validated live Docker layout uses JSON null for unpublished.
            raise ValueError("Canary has effective host port publication: " + name)

    if run("docker", "port", name).strip():
        raise ValueError("Canary docker port reports host publication: " + name)

    dormant_count = 0
    for port, bindings in configured.items():
        if not re.fullmatch(r"\d{1,5}/(?:tcp|udp)", port):
            raise ValueError("Canary configured port key malformed: " + name)
        if bindings is None:
            continue
        if not isinstance(bindings, list):
            raise ValueError("Canary configured port metadata malformed: " + name)
        for entry in bindings:
            if not isinstance(entry, dict):
                raise ValueError("Canary configured bind entry malformed: " + name)
            host_ip = entry.get("HostIp")
            host_port = entry.get("HostPort")
            try:
                if not host_ip or not ipaddress.ip_address(host_ip).is_loopback:
                    raise ValueError()
                if not isinstance(host_port, str) or not host_port.isascii():
                    raise ValueError()
                if not host_port.isdecimal() or not 1 <= int(host_port) <= 65535:
                    raise ValueError()
            except ValueError:
                raise ValueError("Canary configured non-loopback or unsafe host bind: " + name) from None
            dormant_count += 1

    return dormant_count


def docker_upstreams():
    objects = {}
    for name, expected in IMAGES.items():
        items = json.loads(run("docker", "inspect", name))
        if len(items) != 1 or items[0]["Config"]["Image"] != expected:
            raise ValueError("Container identity/image drift: " + name)
        if items[0]["State"].get("Health", {}).get("Status") != "healthy":
            raise ValueError("Container health gate not ready: " + name)
        objects[name] = items[0]
    network = json.loads(run("docker", "network", "inspect", NETWORK))
    if len(network) != 1 or not network[0].get("Internal"):
        raise ValueError("Canary network no longer internal")
    upstreams = []
    dormant_counts = []
    for name in ("xtream-vod-canary-admin", "xtream-vod-canary-playback"):
        obj = objects[name]
        networks = obj["NetworkSettings"]["Networks"]
        if len(networks) != 1 or NETWORK not in networks:
            raise ValueError("Canary is not isolated on expected private network")
        dormant_counts.append(check_canary_port_isolation(obj, name))
        ip = networks[NETWORK].get("IPAddress")
        try:
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.version != 4 or not parsed_ip.is_private:
                raise ValueError()
        except ValueError:
            raise ValueError("Canary Docker address missing/unsafe: " + name) from None
        upstreams.append(ip)
    return upstreams, dormant_counts


def main():
    if not VHOST.is_file() or VHOST.is_symlink() or Path(INCLUDE_PATH).exists():
        raise ValueError("nginx source is unexpected or Canary snippet already exists")
    original = VHOST.read_bytes()
    if hashlib.sha256(original).hexdigest() != VHOST_SHA:
        raise ValueError("Production nginx SHA256 drifted; stop for manual review")
    run("nginx", "-t")
    (admin_ip, play_ip), dormant_counts = docker_upstreams()

    # HTTPS read-only download; no credentials, authorization headers or cookies.
    opener = build_opener(ProxyHandler({}))
    with opener.open(Request(TEMPLATE_URL), timeout=15) as response:
        raw_template = response.read(20000)
    if git_blob_sha(raw_template) != TEMPLATE_BLOB:
        raise ValueError("Pinned nginx template integrity mismatch")
    original_text = original.decode("utf-8")
    proposal, template, directive = render(
        original_text, raw_template.decode("utf-8"), admin_ip, play_ip
    )
    if proposal.replace(directive, "", 1).encode("utf-8") != original:
        raise ValueError("Rollback would not restore original bytes")

    with tempfile.TemporaryDirectory(prefix="xtream-stage4d-", dir="/tmp") as td:
        root = Path(td)
        os.chmod(root, 0o700)
        routes = root / "routes.conf"
        candidate = root / "candidate.conf"
        config = root / "nginx.conf"
        routes.write_text(template, encoding="utf-8")
        candidate.write_text(proposal.replace(INCLUDE_PATH, str(routes), 1),
                             encoding="utf-8")
        config.write_text(
            "worker_processes 1;\n"
            + "pid " + str(root / "pid") + ";\n"
            + "error_log " + str(root / "nginx-error.log") + " warn;\n"
            + "events { worker_connections 64; }\n"
            + "http { include " + str(candidate) + "; }\n",
            encoding="utf-8",
        )
        for path in (routes, candidate, config):
            path.chmod(0o600)
        check = subprocess.run(
            ["nginx", "-t", "-c", str(config), "-p", str(root) + "/"],
            capture_output=True, text=True, timeout=18,
        )
        syntax = "PASS" if check.returncode == 0 else "NEEDS_CONTEXT_REVIEW"

    print("STAGE4D_ROUTE_PREVIEW=GENERATED_IN_MEMORY")
    print("STAGE4D_PRODUCTION_CHANGES=NONE")
    print("LIVE_NGINX_TEST=PASS")
    print("NGINX_VHOST_ORIGINAL_SHA256=" + VHOST_SHA)
    print("PROPOSED_SNIPPET_PATH=" + INCLUDE_PATH + " (NOT_CREATED)")
    print("PROPOSED_SNIPPET_SHA256=" + hashlib.sha256(template.encode()).hexdigest())
    print("PROPOSED_VHOST_SHA256=" + hashlib.sha256(proposal.encode()).hexdigest())
    print("STAGING_NGINX_SYNTAX=" + syntax)
    print("ROLLBACK_BYTE_EXACT=PASS")
    print("CANARY_EFFECTIVE_HOST_PUBLICATIONS=NONE")
    print("CANARY_DORMANT_LOOPBACK_BINDINGS=" + str(sum(dormant_counts)))
    print("WARNING_DORMANT_PORT_BINDINGS_MAY_ACTIVATE_ON_RECREATE=" + str(bool(sum(dormant_counts))).upper())
    print("CANARY_ADMIN_UPSTREAM=" + admin_ip + ":8768")
    print("CANARY_PLAYBACK_UPSTREAM=" + play_ip + ":8767")
    print("CANARY_LAN_ALLOWLIST=" + LAN)
    print("CANARY_GATE=INDEPENDENT_INTERNAL_AUTH_REQUEST")
    print("CANARY_PATHS=/canary/admin/,/canary/admin-signin/,/canary/a/,/canary/play/")
    print("WARNING_WAN_SNAT_NOT_YET_TESTED=TRUE")
    print("WARNING_UPSTREAM_IPS_MAY_CHANGE_AFTER_CANARY_RECREATE=TRUE")
    print("ROUTES_NOT_INSTALLED=TRUE")
    print("READY_FOR_NGINX_RELOAD=FALSE")
    print("NEXT=REVIEW_CANARY_UPGRADE_AND_LIVE_ROLLBACK_PROCEDURE")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            subprocess.TimeoutExpired) as exc:
        print("STOP: Stage 4D read-only review failed: " + str(exc))
        raise SystemExit(1) from None
