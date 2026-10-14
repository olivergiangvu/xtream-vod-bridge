#!/usr/bin/env python3
"""Read-only HomeDocker :18450 /canary/ routing audit.

No writes. Never prints nginx config, private keys, tokens or .env contents.
Discovers the single source config file owning the production public vhost.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler

from canary.stage4b_preflight import (
    CANARY_NETWORK,
    command,
    container_ip,
    local_lan,
    server_blocks,
)

DOMAIN = "olivergiangvu.asuscomm.com"
EXPECTED_ADMIN_IMAGE = "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
EXPECTED_PLAY_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
EXPECTED_PROD_ADMIN = "homedocker/xtream-vod-admin:0.4.3-manifest"
EXPECTED_PROD_PLAY = "homedocker/xtream-vod-bridge:0.4.0"
CONFIG_HEADER = re.compile(r"(?m)^# configuration file ([^:\n]+):\s*$")
PREFIX_CLAUSE = re.compile(r"(?m)^\s*(?:location|rewrite|return)\s+[^;\n]*?/canary(?:/|\b)")


def find_server_config(dump):
    """Identify public vhost's real file, not nginx -T expanded line number."""
    match_list = list(CONFIG_HEADER.finditer(dump))
    if not match_list:
        raise ValueError("nginx -T has no configuration-file markers")
    found = []
    for i, marker in enumerate(match_list):
        next_pos = match_list[i + 1].start() if i + 1 < len(match_list) else len(dump)
        chunk = dump[marker.end():next_pos]
        for block in server_blocks(chunk):
            listeners = re.findall(r"(?m)^\s*listen\s+([^;]+);", block)
            hosts = re.findall(r"(?m)^\s*server_name\s+([^;]+);", block)
            if not any(re.search(r"(?:^|[\s:])18450(?:\s|$)", x) for x in listeners):
                continue
            if not any(DOMAIN in h.split() for h in hosts):
                continue
            if not any("ssl" in x.split() for x in listeners):
                raise ValueError("Public :18450 vhost is not TLS enabled")
            found.append((Path(marker.group(1)), block))
    if len(found) != 1:
        raise ValueError("Expected exactly one public HTTPS :18450 nginx server")
    filename, block = found[0]
    resolved = filename.resolve(strict=True)
    if not resolved.is_relative_to(Path("/etc/nginx").resolve()):
        raise ValueError("Production vhost outside /etc/nginx; manual review required")
    if not resolved.is_file():
        raise ValueError("Public nginx vhost file not found")
    required = [
        r"location\s+\^~\s+/admin/",
        r"location\s+\^~\s+/admin-signin/",
        r"auth_request\s+/__xtream_admin_gate_check",
        r"location\s+/\s*\{",
    ]
    if not all(re.search(pattern, block) for pattern in required):
        raise ValueError("Current production gateway layout differs; review manually")
    if PREFIX_CLAUSE.search(block) or "/canary/" in block:
        raise ValueError("Existing /canary/ routes detected; refuse to overwrite")
    return filename, resolved, block


def lookup_image(name):
    obj = json.loads(command("docker", "inspect", name))
    if len(obj) != 1:
        raise ValueError("Missing expected production container: " + name)
    if obj[0]["State"]["Health"]["Status"] != "healthy":
        raise ValueError("Production container unhealthy: " + name)
    return obj[0]["Config"]["Image"], obj[0]["Id"]


def check_http(ip, port, path, expected):
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(f"http://{ip}:{port}{path}", timeout=5) as response:
            status = response.status
    except HTTPError as exc:
        status = exc.code
    if status != expected:
        raise ValueError(f"Canary internal API returned unexpected HTTP {status}")
    return status


def main():
    status = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if status.returncode:
        raise ValueError("Current production nginx config does not pass nginx -t")
    raw = command("nginx", "-T")
    filename, resolved, _block = find_server_config(raw)

    admin_ip, admin_image = container_ip("xtream-vod-canary-admin")
    play_ip, play_image = container_ip("xtream-vod-canary-playback")
    if admin_image != EXPECTED_ADMIN_IMAGE or play_image != EXPECTED_PLAY_IMAGE:
        raise ValueError("Unexpected Canary image; refuse to generate nginx routing")
    if lookup_image("xtream-vod-admin")[0] != EXPECTED_PROD_ADMIN:
        raise ValueError("Unexpected production Admin image")
    if lookup_image("xtream-vod-bridge")[0] != EXPECTED_PROD_PLAY:
        raise ValueError("Unexpected production Playback image")
    network = json.loads(command("docker", "network", "inspect", CANARY_NETWORK))
    if len(network) != 1 or not network[0]["Internal"]:
        raise ValueError("Canary network is not internal")

    dev, lan_ip, lan_cidr = local_lan()
    net = ipaddress.ip_network(lan_cidr)
    if net.version != 4 or net.num_addresses > 4096:
        raise ValueError("LAN subnet is too broad for Canary access policy")
    if ipaddress.ip_address(lan_ip) not in net:
        raise ValueError("HomeDocker LAN IP does not match subnet")

    check_http(admin_ip, 8768, "/", 200)
    check_http(admin_ip, 8768, "/api/my/sources", 401)
    check_http(play_ip, 8767, "/health", 200)

    # Socket is already in use by production on :18450; don't try to bind it.
    print("SAME_PORT_PREFLIGHT=PASS")
    print("NGINX_PRODUCTION_VHOST_FILE=" + str(filename))
    print("NGINX_REAL_FILE=" + str(resolved))
    print("NGINX_FILE_SHA256=" + hashlib.sha256(resolved.read_bytes()).hexdigest())
    print("NGINX_TEST=PASS")
    print("HTTPS_PORT=18450 (EXISTING_ONLY)")
    print("CANARY_PORT_18451=NOT_USED")
    print("DOMAIN=" + DOMAIN)
    print("LAN_INTERFACE=" + dev)
    print("LAN_HOST_IP=" + lan_ip)
    print("LAN_CIDR_FOR_REVIEW=" + lan_cidr)
    print("CANARY_ADMIN_DOCKER_IP=" + admin_ip)
    print("CANARY_PLAYBACK_DOCKER_IP=" + play_ip)
    print("CANARY_INTERNAL_NETWORK=true")
    print("CANARY_HEALTH_AND_UNAUTH_API=PASS")
    print("PRODUCTION_IMAGES_AND_HEALTH=PASS")
    print("NO_CONFIG_OR_CONTAINER_CHANGES=TRUE")
    print("NEXT=GENERATE_ROUTE_AND_VALIDATE_ROLLBACK")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, KeyError, TypeError) as exc:
        print("STOP: Same-port read-only preflight failed: " + str(exc))
        raise SystemExit(1) from None
