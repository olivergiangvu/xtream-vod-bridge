#!/usr/bin/env python3
"""Read-only HomeDocker capacity/conflict preflight. Never print secrets.

Run on the Linux Docker host (SSH); it does not deploy, inspect environment
variables, call IPTV APIs, or modify nginx, Docker, or system files.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


def run(args: list[str], timeout: int = 12) -> tuple[int | None, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=timeout, check=False)
        return proc.returncode, proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return None, ""


def listens_on(ss_output: str, port: int) -> bool:
    """Match local ports, not peer ports, without printing socket/process info."""
    for line in ss_output.splitlines():
        words = line.split()
        # ss -ltnH: State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port
        if len(words) < 5:
            continue
        local = words[3]
        if re.search(r":(\d+)$", local) and local.rsplit(":", 1)[-1] == str(port):
            return True
    return False


def docker_claims_port(ps_output: str, port: int) -> bool:
    # Docker ps --format '{{.Names}}|{{.Ports}}'; avoid checking the host's
    # potentially unrelated ephemeral/container-only ports.
    for line in ps_output.splitlines():
        ports = line.partition("|")[2]
        if re.search(rf"(?:^|[\s,])(?:[^\s,]*:)?{port}->\d+/(?:tcp|udp)", ports):
            return True
    return False


def public_base_url_ok(value: str) -> bool:
    """Public base may use domain:port root OR an nginx path prefix."""
    try:
        p = urlsplit(value)
        port = p.port
        return (p.scheme == "https" and bool(p.hostname) and
                not p.username and not p.password and not p.query and
                not p.fragment and (port is None or 1 <= port <= 65535) and
                "//" not in p.path)
    except ValueError:
        return False


def existing_nginx_paths(port: int = 18767) -> tuple[bool, bool]:
    """Best effort location-conflict signal; never print nginx contents."""
    found_path = False
    found_proxy_port = False
    checked: set[Path] = set()
    for root in (Path("/etc/nginx/conf.d"), Path("/etc/nginx/sites-enabled")):
        if not root.is_dir():
            continue
        for path in root.iterdir():
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in checked:
                continue
            checked.add(resolved)
            try:
                content = path.read_text(errors="replace")
            except (OSError, UnicodeError):
                continue
            found_path |= bool(re.search(r"location\s+[^\n;{}]*?/xtream-vod/", content))
            found_proxy_port |= bool(re.search(rf"proxy_pass\s+http://127\.0\.0\.1:{port}(?:/|[;\s])", content))
    return found_path, found_proxy_port


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only HomeDocker checks: no credentials shown")
    parser.add_argument("--port", type=int, default=18767)
    parser.add_argument("--public-base-url", default=None, help="optional HTTPS base URL, without token")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("port must be between 1024 and 65535")

    observations: dict[str, object] = {
        "read_only": True, "port": args.port,
        "docker_cli": bool(shutil.which("docker")),
        "nginx_binary": bool(shutil.which("nginx")),
    }
    code, version = run(["docker", "version", "--format", "{{.Server.Version}}"])
    observations["docker_server_available"] = code == 0
    if code == 0:
        observations["docker_server_version"] = version

    code, containers = run(["docker", "ps", "--format", "{{.Names}}|{{.Ports}}"])
    observations["docker_inventory_available"] = code == 0
    if code == 0:
        names = [line.split("|", 1)[0] for line in containers.splitlines() if line]
        observations["running_containers"] = len(names)
        observations["bridge_container_exists"] = "xtream-vod-bridge" in names
        observations["docker_port_conflict"] = docker_claims_port(containers, args.port)

    ss_code, ss_out = run(["ss", "-ltnH"])
    observations["ss_available"] = ss_code == 0
    if ss_code == 0:
        observations["tcp_port_in_use"] = listens_on(ss_out, args.port)

    nginx_code, _ = run(["nginx", "-t", "-q"])
    observations["nginx_test_pass"] = nginx_code == 0
    path_exists, proxy_exists = existing_nginx_paths(args.port)
    observations["existing_xtream_nginx_location"] = path_exists
    observations["existing_xtream_nginx_proxy"] = proxy_exists
    if args.public_base_url:
        observations["public_base_url_format_ok"] = public_base_url_ok(args.public_base_url)

    conflict = bool(observations.get("docker_port_conflict") or
                    observations.get("tcp_port_in_use") or path_exists or proxy_exists)
    observations["preflight"] = "REVIEW_CONFLICT" if conflict else (
        "READY_FOR_CONTROLLED_STAGING" if
        observations["docker_server_available"] and observations["docker_inventory_available"] and
        observations["ss_available"] and observations["nginx_test_pass"] and
        observations.get("public_base_url_format_ok", True) else "REVIEW_PREREQUISITES")
    print(json.dumps(observations, indent=2, sort_keys=True))
    return 0 if observations["preflight"] == "READY_FOR_CONTROLLED_STAGING" else 2


if __name__ == "__main__":
    raise SystemExit(main())
