#!/usr/bin/env python3
"""Read-only HomeDocker LAN admin HTTPS preflight.

No change to network/Docker/nginx or sensitive files. Print only boolean
results and numeric port; do not log certificate paths, credential values,
domain names, existing nginx configuration or network inventories.
"""
import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
from pathlib import Path


def probe_local_listener(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=1):
            return True
    except (OSError, TimeoutError):
        return False


def cert_matches_hostname(cert_file: Path, hostname: str) -> bool:
    """openssl x509 -checkhost does not read the private key."""
    if not cert_file.is_file() or not shutil.which("openssl"):
        return False
    try:
        x = subprocess.run(
            ["openssl", "x509", "-in", str(cert_file), "-noout", "-checkhost", hostname],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return x.returncode == 0 and "does match certificate" in x.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def resolve_to_lan(hostname: str, lan_ip: str) -> bool:
    try:
        answers = socket.getaddrinfo(hostname, None, family=socket.AF_INET)
        return any(a[4][0] == lan_ip for a in answers)
    except (OSError, ValueError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only LAN HTTPS admin checks")
    parser.add_argument("--lan-ip", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--https-port", type=int, default=18769)
    parser.add_argument("--admin-port", type=int, default=18768)
    parser.add_argument("--allow-cidr", default="192.168.50.0/24")
    args = parser.parse_args()
    try:
        ip = ipaddress.ip_address(args.lan_ip)
        network = ipaddress.ip_network(args.allow_cidr, strict=False)
        valid_address = isinstance(ip, ipaddress.IPv4Address) and ip.is_private and ip in network
    except ValueError:
        valid_address = False
    if not valid_address:
        parser.error("LAN IP must be private IPv4 and within allow-cidr")
    if not 1024 <= args.https_port <= 65535 or not 1024 <= args.admin_port <= 65535:
        parser.error("Admin ports must be between 1024 and 65535")

    checks = {
        "read_only": True,
        "loopback_admin_reachable": probe_local_listener("127.0.0.1", args.admin_port),
        "candidate_lan_https_port_in_use": probe_local_listener(args.lan_ip, args.https_port),
        "certificate_hostname_matches": cert_matches_hostname(Path(args.cert), args.hostname),
        "private_key_exists": Path(args.key).is_file(),
        "dns_resolves_to_lan_ip": resolve_to_lan(args.hostname, args.lan_ip),
        "nginx_installed": shutil.which("nginx") is not None,
        "https_port": args.https_port,
        "lan_ip_within_allowed_cidr": valid_address,
    }
    checks["ready_for_review"] = (
        checks["loopback_admin_reachable"]
        and not checks["candidate_lan_https_port_in_use"]
        and checks["certificate_hostname_matches"]
        and checks["private_key_exists"]
        and checks["dns_resolves_to_lan_ip"]
        and checks["nginx_installed"]
    )
    print(json.dumps(checks, indent=2, sort_keys=True))
    return 0 if checks["ready_for_review"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
