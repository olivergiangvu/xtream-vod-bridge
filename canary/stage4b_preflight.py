#!/usr/bin/env python3
"""HomeDocker Canary Stage 4B HTTPS ingress READ-ONLY audit.

No config/DB/container changes, no secrets or raw nginx config printed.
Run as root from reviewed SHA, after Stage 4A Canary cookie isolation.
"""
import ipaddress
import json
import re
import socket
import subprocess
from pathlib import Path

CANARY_ADMIN_IMAGE = "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
CANARY_PLAYBACK_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
PRODUCTION_ADMIN_IMAGE = "homedocker/xtream-vod-admin:0.4.3-manifest"
PRODUCTION_PLAYBACK_IMAGE = "homedocker/xtream-vod-bridge:0.4.0"
EXPECTED_HOST = "olivergiangvu.asuscomm.com"
CANARY_PORT = 18451
CANARY_NETWORK = "xtream-vod-canary_private_canary"
CONF_PATH = Path("/etc/nginx/conf.d/xtream-vod-canary-18451.conf")


def command(*argv):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=20)
    if result.returncode:
        raise RuntimeError("Read-only inspection failed: " + argv[0])
    return result.stdout


def _strip_comments(line):
    result = []
    quoted = None
    escaped = False
    for char in line:
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == "\\":
            result.append(char)
            escaped = True
            continue
        if char in "'\"":
            if quoted == char:
                quoted = None
            elif not quoted:
                quoted = char
            result.append(char)
            continue
        if char == "#" and not quoted:
            break
        result.append(char)
    return "".join(result)


def server_blocks(raw):
    """Return source snippets for nginx server blocks with nested locations."""
    lines = raw.splitlines()
    starts = [i for i, line in enumerate(lines)
              if re.match(r"^\s*server\s*\{", _strip_comments(line))]
    blocks = []
    for start in starts:
        depth = 0
        for j in range(start, len(lines)):
            clean = _strip_comments(lines[j])
            depth += clean.count("{") - clean.count("}")
            if depth == 0 and j > start:
                blocks.append("\n".join(lines[start:j + 1]))
                break
        else:
            raise ValueError("Unbalanced nginx server block")
    return blocks


def production_tls(raw):
    domains = []
    for block in server_blocks(raw):
        direct = block.splitlines()
        listen = [line.strip() for line in direct if re.match(r"^\s*listen\b", line)]
        names = [line.strip() for line in direct
                 if re.match(r"^\s*server_name\b", line)]
        if not any(re.search(r"\b18450\b", line) for line in listen):
            continue
        if not any(EXPECTED_HOST in line.split(";", 1)[0].split() for line in names):
            continue
        certs = re.findall(r"(?m)^\s*ssl_certificate\s+([^;]+);", block)
        keys = re.findall(r"(?m)^\s*ssl_certificate_key\s+([^;]+);", block)
        if len(certs) != 1 or len(keys) != 1:
            raise ValueError("Ambiguous v0.4 production TLS certificates")
        cert = certs[0].strip().strip("'\"")
        key = keys[0].strip().strip("'\"")
        if not all(p.startswith("/") and "$" not in p for p in (cert, key)):
            raise ValueError("Production certificate paths must be absolute")
        if not (Path(cert).is_file() and Path(key).is_file()):
            raise ValueError("Production certificate/key file missing")
        domains.append((cert, key))
    if len(domains) != 1:
        raise ValueError("Expected exactly one production :18450 public domain")
    return domains[0]


def local_lan():
    route = json.loads(command("ip", "-j", "-4", "route", "get", "1.1.1.1"))
    if not isinstance(route, list) or len(route) != 1:
        raise ValueError("Cannot uniquely identify the HomeDocker LAN route")
    dev, ip = route[0].get("dev"), route[0].get("prefsrc", route[0].get("src"))
    if not dev or not ip:
        raise ValueError("Missing default route interface or source IP")
    addr = ipaddress.ip_address(ip)
    private_ranges = [ipaddress.ip_network(s) for s in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if not any(addr in n for n in private_ranges):
        raise ValueError("Default source IP is not RFC1918; refuse Canary LAN bind")
    interfaces = json.loads(command("ip", "-j", "-4", "addr", "show", "dev", dev))
    found = [
        ipaddress.ip_interface(f"{data['local']}/{data['prefixlen']}")
        for row in interfaces
        for data in row.get("addr_info", [])
        if data.get("local") == ip and data.get("family") == "inet"
    ]
    if len(found) != 1:
        raise ValueError("Unable to determine one LAN CIDR for default interface")
    return dev, str(addr), str(found[0].network)


def container_ip(name):
    data = json.loads(command("docker", "inspect", name))
    if len(data) != 1:
        raise ValueError("Canary container missing")
    found = data[0]
    state = found.get("State", {})
    if state.get("Health", {}).get("Status") != "healthy":
        raise ValueError("Canary container not healthy: " + name)
    nets = found["NetworkSettings"]["Networks"]
    if CANARY_NETWORK not in nets:
        raise ValueError("Canary container does not use expected private network")
    address = nets[CANARY_NETWORK].get("IPAddress")
    if not address or not ipaddress.ip_address(address).is_private:
        raise ValueError("Canary bridge IP unavailable / non-private")
    return address, found["Config"]["Image"]


def test_bind(local_ip):
    for ip in (local_ip, "127.0.0.1"):
        with socket.socket() as sock:
            try:
                sock.bind((ip, CANARY_PORT))
            except OSError as exc:
                raise ValueError(f"Port {CANARY_PORT} unavailable on {ip}") from exc


def main():
    if CONF_PATH.exists():
        raise SystemExit("STOP: Canary nginx conf already exists; do not overwrite")
    admin_ip, admin_image = container_ip("xtream-vod-canary-admin")
    playback_ip, playback_image = container_ip("xtream-vod-canary-playback")
    prod_admin = json.loads(command("docker", "inspect", "xtream-vod-admin"))[0]
    prod_play = json.loads(command("docker", "inspect", "xtream-vod-bridge"))[0]
    if (admin_image != CANARY_ADMIN_IMAGE or
            playback_image != CANARY_PLAYBACK_IMAGE or
            prod_admin["Config"]["Image"] != PRODUCTION_ADMIN_IMAGE or
            prod_play["Config"]["Image"] != PRODUCTION_PLAYBACK_IMAGE):
        raise SystemExit("STOP: Image drift detected; review before ingress")
    network = json.loads(command("docker", "network", "inspect", CANARY_NETWORK))
    if len(network) != 1 or not network[0].get("Internal"):
        raise SystemExit("STOP: Canary Docker network is no longer internal")
    dev, lan_ip, cidr = local_lan()
    test_bind(lan_ip)
    raw = command("nginx", "-T")
    cert, key = production_tls(raw)
    if not re.search(r"(?m)^\s*include\s+/etc/nginx/conf\.d/\*\.conf;", raw):
        raise SystemExit("STOP: /etc/nginx/conf.d/*.conf is not included")
    if any(re.search(r"\b18451\b", line) for line in raw.splitlines()
           if re.match(r"^\s*listen\b", line)):
        raise SystemExit("STOP: nginx already listens on port 18451")
    print("STAGE4B_READONLY_PREFLIGHT=PASS")
    print("CANARY_ADMIN_IMAGE=EXPECTED")
    print("CANARY_PLAYBACK_IMAGE=EXPECTED")
    print("PRODUCTION_IMAGES=EXPECTED")
    print("CANARY_NETWORK_INTERNAL=true")
    print(f"CANARY_ADMIN_DOCKER_IP={admin_ip}")
    print(f"CANARY_PLAYBACK_DOCKER_IP={playback_ip}")
    print(f"LAN_INTERFACE={dev}")
    print(f"LAN_LISTEN_IP={lan_ip}")
    print(f"LAN_ALLOW_CIDR={cidr}")
    print(f"TLS_CERTIFICATE=REUSE_PRODUCTION (filename={Path(cert).name})")
    print("TLS_PRIVATE_KEY=REUSE_PRODUCTION (path not printed)")
    print(f"NGINX_CANARY_TARGET={CONF_PATH}")
    print("CANARY_18451_PORTS=FREE")
    print("NO_NGINX_OR_DOCKER_CHANGES=TRUE")
    print("NEXT_GATE=REVIEW_LAN_CIDR_AND_NGINX_INSTALLER")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as exc:
        print("STOP: " + str(exc))
        raise SystemExit(1) from None
