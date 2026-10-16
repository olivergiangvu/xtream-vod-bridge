#!/usr/bin/env python3
"""Stage 5A.2: verified Canary Admin image build; never recreates containers.

Default --plan validates the *post Stage4F* live baseline and pinned sources.
Optional --build (explicit approval token) builds only a local image, without
Compose changes, service restarts, nginx reloads, host ports or image pulls.
Does not output secrets, full configs, docker build logs or container envs.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler, Request

ROOT = Path("/opt/xtream-vod-canary")
BASE = ROOT / "src/canary/compose.yaml"
OVERRIDE = ROOT / "ui-override.yaml"
VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
PINNED_SHA = {
    BASE: "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354",
    OVERRIDE: "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
    VHOST: "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35",
}
SRC_REF = "206cf27063b8939fbd5880a61ff31aa7c2352985"
OLD_ADMIN = "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f"
PLAY = "homedocker/xtream-vod-canary:5c2f02233a0f"
NEW_ADMIN = "homedocker/xtream-vod-canary-admin:0.5g-prefix-206cf27063b8"
NETWORK = "xtream-vod-canary_private_canary"
IMAGES = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
    "xtream-vod-canary-admin": OLD_ADMIN,
    "xtream-vod-canary-playback": PLAY,
}
SOURCES = {
    "route_paths.py": "d313f86ce81ae3906ce93b21235329d085048fa3",
    "admin_auth.py": "b52948bf4e333a5baab468ad82badf926db900c5",
    "admin_ui.py": "9a67edac8838cb0a6d279498fbc8f672a73df9aa",
    "admin/assets/app.js": "123ea2c3e076e64ca826320710ba7e202f98ffbb",
    "admin/assets/workspace.js": "114bb4ef43afc463d5fe57b723ef2e0cec802611",
}
STAGE4A_OVERRIDE = (
    "services:\n  xtream-vod-admin:\n"
    + "    image: " + OLD_ADMIN + "\n"
    + "    environment:\n"
    + "      XTREAM_SESSION_COOKIE: xtream_canary_admin_session\n"
    + "      XTREAM_LOGIN_NONCE_COOKIE: xtream_canary_login_nonce\n"
    + "      XTREAM_GATEWAY_REFERRER_POLICY: same-origin\n"
    + "      ADMIN_PUBLIC_ORIGIN: https://olivergiangvu.asuscomm.com:18451\n"
    + "      PUBLIC_BASE_URL: https://olivergiangvu.asuscomm.com:18451\n"
)


def stop(message):
    raise ValueError(message)


def shell(*args, timeout=40, env=None):
    task = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env=env)
    if task.returncode:
        stop("Read-only Docker command failed: " + args[0])
    return task.stdout


def git_blob(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\x00" + raw
    ).hexdigest()


def psi():
    for line in Path("/proc/pressure/cpu").read_text().splitlines():
        if line.startswith("some "):
            match = re.search(r"\bavg10=([0-9.]+)", line)
            return float(match.group(1)) if match else None
    return None


def check_psi():
    start = psi()
    time.sleep(10)
    end = psi()
    if start is None or end is None or start >= 30 or end >= 30:
        stop("CPU_PSI_GATE_NOT_READY (need both avg10 samples <30)")
    return start, end


def cpu_ticks():
    """Cumulative CPU time across all logical CPUs; iowait counts as idle."""
    row = Path("/proc/stat").read_text().splitlines()[0].split()
    if not row or row[0] != "cpu" or len(row) < 9:
        stop("System CPU accounting unavailable")
    values = [int(value) for value in row[1:9]]
    return sum(values), values[3] + values[4]


def memory_available_bytes():
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            fields["available_kib"] = int(line.split()[1])
            break
    if "available_kib" not in fields:
        stop("Memory headroom information unavailable")
    return fields["available_kib"] * 1024


def low_impact_build_gate():
    """Separate narrow exception for FROM + COPY only, never a recreate gate.

    This measures actual 10-second host utilization and memory/disk headroom,
    rather than waiting indefinitely for the 30% CPU PSI heuristic. BuildKit
    work remains in Docker daemon, not CPU-limited by nice of the CLI.
    """
    if os.cpu_count() != 2:
        stop("Expected 2 logical CPUs; re-review hardware before build")
    docker_root = shell("docker", "info", "--format", "{{.DockerRootDir}}").strip()
    root = Path(docker_root)
    if not root.is_absolute() or not root.is_dir():
        stop("Docker data root unavailable")
    total0, idle0 = cpu_ticks()
    psi0 = psi()
    time.sleep(10)
    total1, idle1 = cpu_ticks()
    psi1 = psi()
    delta = total1 - total0
    if delta <= 0:
        stop("Host CPU accounting did not advance")
    utilization = 100 * (1 - (idle1 - idle0) / delta)
    mem = memory_available_bytes()
    disk = shutil.disk_usage(root).free
    print("BUILD_ONLY_HOST_CPU_UTILIZATION_10S=" + f"{utilization:.2f}%")
    print("BUILD_ONLY_CPU_PSI_START=" +
          (f"{psi0:.2f}" if psi0 is not None else "UNKNOWN"))
    print("BUILD_ONLY_CPU_PSI_END=" +
          (f"{psi1:.2f}" if psi1 is not None else "UNKNOWN"))
    print("BUILD_ONLY_MEM_AVAILABLE_MIB=" + str(mem // 1048576))
    print("BUILD_ONLY_DOCKER_DISK_FREE_MIB=" + str(disk // 1048576))
    if utilization >= 75:
        stop("BUILD_ONLY_HOST_CPU_HEADROOM_NOT_READY (>=75% busy)")
    if psi0 is None or psi1 is None or max(psi0, psi1) >= 70:
        stop("BUILD_ONLY_EXTREME_CPU_PRESSURE_OR_UNKNOWN")
    if mem < 1024 * 1048576:
        stop("BUILD_ONLY_RAM_HEADROOM_NOT_READY (<1024MiB)")
    if disk < 2048 * 1048576:
        stop("BUILD_ONLY_DOCKER_DISK_NOT_READY (<2048MiB)")
    print("BUILD_ONLY_RESOURCE_GATE=PASS")
    return utilization


def verify_baseline():
    for path, expected in PINNED_SHA.items():
        if not path.is_file() or path.is_symlink():
            stop("Missing/symlinked approved baseline file: " + path.name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            stop("Approved baseline file drift: " + path.name)
    if OVERRIDE.read_text(encoding="utf-8") != STAGE4A_OVERRIDE:
        stop("Canary override drifted")

    env = os.environ.copy()
    env.update(CANARY_DIR=str(ROOT), CANARY_IMAGE=PLAY)
    config = json.loads(shell(
        "docker", "compose", "-p", "xtream-vod-canary",
        "-f", str(BASE), "-f", str(OVERRIDE), "config", "--format", "json",
        env=env))
    services = config.get("services", {})
    if set(services) != {"xtream-vod-admin", "xtream-vod-bridge"}:
        stop("Unexpected Compose services")
    nets = config.get("networks", {})
    if set(nets) != {"private_canary"} or nets["private_canary"].get("internal") is not True:
        stop("Canary Docker network not private-only")
    if nets["private_canary"].get("name") != NETWORK:
        stop("Canary Docker network unexpectedly renamed")
    for service, expected in (
        ("xtream-vod-admin", OLD_ADMIN), ("xtream-vod-bridge", PLAY)
    ):
        obj = services[service]
        if obj.get("image") != expected or obj.get("ports") or obj.get("publish_all_ports"):
            stop("Canary Compose image or host-port publication drift")
        members = obj.get("networks") or {}
        if set(members) != {"private_canary"} or obj.get("network_mode"):
            stop("Canary Compose network isolation drift")
    for old_image in (OLD_ADMIN, PLAY):
        shell("docker", "image", "inspect", old_image, timeout=20)

    containers = {}
    for name, expected in IMAGES.items():
        objects = json.loads(shell("docker", "inspect", name))
        if len(objects) != 1:
            stop("Container inventory drift: " + name)
        obj = objects[0]
        if obj.get("Config", {}).get("Image") != expected:
            stop("Container image changed: " + name)
        if obj.get("State", {}).get("Health", {}).get("Status") != "healthy":
            stop("Container not healthy: " + name)
        if name.startswith("xtream-vod-canary-"):
            if set(obj.get("NetworkSettings", {}).get("Networks") or {}) != {NETWORK}:
                stop("Live Canary has non-private Docker network")
            if any(x is not None for x in
                   (obj.get("NetworkSettings", {}).get("Ports") or {}).values()):
                stop("Live Canary has actual host port publication")
            if shell("docker", "port", name).strip():
                stop("Docker reports published Canary host port")
        containers[name] = obj["Id"]
    network = json.loads(shell("docker", "network", "inspect", NETWORK))
    if len(network) != 1 or network[0].get("Internal") is not True:
        stop("Live Canary network drift")
    return containers


def verify_sources(directory):
    opener = build_opener(ProxyHandler({}))
    for name, expected_blob in SOURCES.items():
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        url = (
            "https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
            + SRC_REF + "/" + name
        )
        with opener.open(Request(url), timeout=30) as response:
            raw = response.read(1_500_000)
        if git_blob(raw) != expected_blob:
            stop("Pinned Canary build source integrity drift: " + name)
        path.write_bytes(raw)
        path.chmod(0o600)

    for name in ("route_paths.py", "admin_auth.py", "admin_ui.py"):
        ast.parse((directory / name).read_text(encoding="utf-8"), filename=name)

    node = shutil.which("node")
    if node:
        for name in ("admin/assets/app.js", "admin/assets/workspace.js"):
            result = subprocess.run(
                [node, "--check", str(directory / name)],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode:
                stop("Pinned Canary JavaScript failed syntax validation")
    return True


def dockerfile():
    return (
        "FROM " + OLD_ADMIN + "\n"
        "COPY route_paths.py admin_auth.py admin_ui.py /srv/\n"
        "COPY admin/assets/app.js admin/assets/workspace.js /srv/admin/assets/\n"
    )


def build_image(directory):
    if shell("docker", "image", "ls", "-q", NEW_ADMIN).strip():
        stop("Candidate Admin tag already exists; refuse to overwrite")
    (directory / "Dockerfile").write_text(dockerfile(), encoding="utf-8")
    # Building runs in Docker's daemon/build subsystem; nice only prioritizes
    # the invoking CLI. Do not claim this controls BuildKit CPU scheduling.
    result = subprocess.run(
        ["docker", "build", "--network", "none", "--pull=false",
         "--progress", "quiet", "-t", NEW_ADMIN, str(directory)],
        capture_output=True, text=True, timeout=240,
    )
    if result.returncode:
        stop("Offline local Docker Admin image build failed (logs suppressed)")
    manifest = json.loads(shell("docker", "image", "inspect", NEW_ADMIN))
    if len(manifest) != 1 or manifest[0].get("RepoTags") is None:
        stop("Built Canary Admin image is not locally inspectable")


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--build", action="store_true")
    modes.add_argument("--plan-light", action="store_true")
    modes.add_argument("--build-light", action="store_true")
    parser.add_argument("--approval", default="")
    args = parser.parse_args()
    building = args.build or args.build_light
    if building and args.approval != NEW_ADMIN:
        stop("Explicit approval of exact Canary candidate image required")
    if os.geteuid() != 0:
        stop("Run with sudo (read-only plan or approved isolated build)")
    if building and shell("docker", "image", "ls", "-q", NEW_ADMIN).strip():
        stop("Candidate image tag already exists; do not overwrite")
    before = verify_baseline()

    with tempfile.TemporaryDirectory(prefix="xtream-stage5a2-") as folder:
        path = Path(folder)
        os.chmod(path, 0o700)
        verify_sources(path)
        print("STAGE5A2_PINNED_SOURCE_INTEGRITY=PASS")
        print("STAGE5A2_LOCAL_ROLLBACK_IMAGES=PASS")
        print("STAGE5A2_COMPOSE_ISOLATION_AND_HEALTH=PASS")
        print("STAGE5A2_CANDIDATE_TAG=" + NEW_ADMIN)
        if building or args.plan_light:
            if args.build:
                first, last = check_psi()
                print("CPU_BUILD_GATE_FIRST=" + f"{first:.2f}")
                print("CPU_BUILD_GATE_LAST=" + f"{last:.2f}")
            else:
                low_impact_build_gate()
            # Catch runtime and SHA drift while downloading sources.
            if verify_baseline() != before:
                stop("Container identity changed before build")
            if building:
                build_image(path)
                if verify_baseline() != before:
                    stop("Container identity changed during build")
                print("STAGE5A2_ADMIN_IMAGE_ONLY_BUILD=PASS")
            else:
                print("STAGE5A2_MODE=PLAN_LIGHT_ONLY")
        else:
            print("STAGE5A2_MODE=PLAN_ONLY")
    print("CANARY_COMPOSE_OR_CONTAINERS_CHANGED=NO")
    print("PRODUCTION_CONTAINERS_CHANGED=NO")
    print("NGINX_OR_FIREWALL_CHANGED=NO")
    print("NEXT=" + (
        "REVIEW_CANARY_RECREATE_ROLLBACK_PROCEDURE"
        if building else "AWAIT_SEPARATE_APPROVAL_FOR_IMAGE_ONLY_BUILD"
    ))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print("STOP: Stage 5A.2: " + str(exc))
        raise SystemExit(1) from None
