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

CANARY_NETWORK = "xtream-vod-canary_private_canary"


def command(*args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError("Inspection command failed: " + str(args[0]))
    return result.stdout


def no_comments(line):
    # Quoted hash characters must not terminate the directive.
    quote = None
    escaped = False
    result = []
    for char in line:
        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            result.append(char)
            escaped = True
        elif char in "'\"":
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            result.append(char)
        elif char == "#" and quote is None:
            break
        else:
            result.append(char)
    return "".join(result)


def server_blocks(text):
    lines = text.splitlines()
    starts = [i for i, v in enumerate(lines)
              if re.match(r"^\s*server\s*\{", no_comments(v))]
    blocks = []
    for start in starts:
        nesting = 0
        for stop in range(start, len(lines)):
            clean = no_comments(lines[stop])
            nesting += clean.count("{") - clean.count("}")
            if nesting == 0 and stop > start:
                blocks.append("\n".join(lines[start:stop + 1]))
                break
        else:
            raise ValueError("Unbalanced nginx server block")
    return blocks


def container_ip(name):
    objects = json.loads(command("docker", "inspect", name))
    if len(objects) != 1:
        raise ValueError("Expected exactly one Canary container")
    obj = objects[0]
    if obj["State"].get("Health", {}).get("Status") != "healthy":
        raise ValueError("Canary container not healthy: " + name)
    networks = obj["NetworkSettings"]["Networks"]
    if CANARY_NETWORK not in networks:
        raise ValueError("Canary network changed: " + name)
    ip = networks[CANARY_NETWORK].get("IPAddress")
    if not ip or not ipaddress.ip_address(ip).is_private:
        raise ValueError("Canary Docker IP missing")
    return ip, obj["Config"]["Image"]


def local_lan():
    route = json.loads(command("ip", "-j", "-4", "route", "get", "1.1.1.1"))
    if len(route) != 1:
        raise ValueError("Ambiguous HomeDocker default route")
    dev = route[0].get("dev")
    ip = route[0].get("prefsrc", route[0].get("src"))
    if not dev or not ip:
        raise ValueError("Default route has no LAN IP/interface")
    addresses = json.loads(command("ip", "-j", "-4", "addr", "show", "dev", dev))
    cidrs = [
        ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
        for row in addresses
        for a in row.get("addr_info", [])
        if a.get("family") == "inet" and a.get("local") == ip
    ]
    if len(cidrs) != 1:
        raise ValueError("Ambiguous HomeDocker LAN subnet")
    if not any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
    )):
        raise ValueError("HomeDocker network is not RFC1918 LAN")
    return dev, ip, str(cidrs[0].network)


DOMAIN = "olivergiangvu.asuscomm.com"
EXPECTED_ADMIN_IMAGES = {
    "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f": "STAGE4A",
    "homedocker/xtream-vod-canary-admin:0.5g-prefix-206cf27063b8": "STAGE4C",
}
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
    required = {
        "admin_location": r"location\s+\^~\s+/admin/",
        "auth_request_gate": r"auth_request\s+/__xtream_admin_gate_check",
        "playback_root_location": r"location\s+/\s*\{",
    }
    missing = [name for name, pattern in required.items()
               if not re.search(pattern, block)]
    if missing:
        # Output ONLY fixed, non-sensitive check IDs, never the nginx body.
        # This prevents an unnecessary Production vhost rewrite if an
        # existing gate uses valid but different nginx location syntax.
        raise ValueError("Production routing signature mismatch: "
                         + ",".join(missing))
    if PREFIX_CLAUSE.search(block) or "/canary/" in block:
        raise ValueError("Existing /canary/ routes detected; refuse to overwrite")
    return filename, resolved, block


def verify_public_signin_https(lan_ip):
    """Read-only HTTPS GET using curl's validated TLS and exact :18450 SNI.

    A server-level nginx include can define /admin-signin/ in a separate
    source file. nginx -T will not render it inline in its parent vhost.
    Verify the route actually served on the production public Host instead.

    --resolve sends the request to HomeDocker's approved LAN IP, while
    cert verification and the HTTP Host retain the public domain name.
    No credentials are sent and no cookie, nonce, HTML or curl error is logged.
    """
    ip = ipaddress.ip_address(lan_ip)
    if ip.version != 4 or not ip.is_private:
        raise ValueError("Public sign-in probe requires private IPv4 LAN")
    url = f"https://{DOMAIN}:18450/admin-signin/"
    result = subprocess.run(
        [
            "curl", "--noproxy", "*", "--silent", "--show-error",
            "--http1.1", "--max-time", "10",
            "--resolve", f"{DOMAIN}:18450:{ip}",
            "--include", "--header", "Accept: text/html",
            url,
        ],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode:
        raise ValueError("Public Safari sign-in HTTPS verification failed")
    head, sep, body = result.stdout.partition("\r\n\r\n")
    if not sep:
        head, sep, body = result.stdout.partition("\n\n")
    if not sep:
        raise ValueError("Public Safari sign-in response missing HTTP headers")
    header_lines = head.splitlines()
    good_status = bool(header_lines and re.fullmatch(
        r"HTTP/1\.[01] 200(?: .*)?", header_lines[0]
    ))
    html_type = any(re.match(r"(?i)^content-type:\s*text/html", line)
                    for line in header_lines)
    nonce_cookie = any(
        re.match(r"(?i)^set-cookie:\s*xtream_admin_login_nonce=", line)
        for line in header_lines
    )
    if not (
        good_status and html_type and nonce_cookie
        and 'action="/admin-signin/"' in body
        and 'name="nonce"' in body
    ):
        raise ValueError("Public Safari sign-in response does not match secure Gateway")
    return True


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
    if admin_image not in EXPECTED_ADMIN_IMAGES or play_image != EXPECTED_PLAY_IMAGE:
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

    # Use the HomeDocker LAN bind address, not loopback. Existing nginx
    # /admin-signin/ ACLs may intentionally allow LAN while denying 127.0.0.1.
    # TLS SNI and Host still target the exact production public hostname.
    verify_public_signin_https(lan_ip)

    check_http(admin_ip, 8768, "/", 200)
    check_http(admin_ip, 8768, "/api/my/sources", 401)
    check_http(play_ip, 8767, "/health", 200)

    # Socket is already in use by production on :18450; don't try to bind it.
    print("PUBLIC_SIGNIN_HTTPS_PROBE=PASS")
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
    print("CANARY_ADMIN_RELEASE=" + EXPECTED_ADMIN_IMAGES[admin_image])
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
