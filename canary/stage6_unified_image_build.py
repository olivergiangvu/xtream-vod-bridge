#!/usr/bin/env python3
"""Stage M3: SHA-pinned OFFLINE unified image-only build. Default --plan.

No Compose edits, nginx changes, container recreation, services, provider
calls or secret output. Needs both legacy Canary containers stopped first.
Docker build has FROM + COPY only, --network none and --pull=false.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler, Request

REF = "cab39cd806cd7773e599f813ae38c9a17456ed3a"
BASE_IMAGE = "homedocker/xtream-vod-canary-admin:0.5g-prefix-206cf27063b8"
CANDIDATE_IMAGE = "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd"
CANARY_ROOT = Path("/opt/xtream-vod-canary")
VHOST = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
BASE_COMPOSE = CANARY_ROOT / "src/canary/compose.yaml"
OVERRIDE = CANARY_ROOT / "ui-override.yaml"
PINNED_LOCAL = {
    VHOST: "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35",
    BASE_COMPOSE: "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354",
    OVERRIDE: "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
}
SOURCES = {
    "unified_app.py": "01b2208e06f857706810344ba5a692e007d92102",
    "admin_ui.py": "83c11efc43dbd6d8f9a58546c931fd7162300b82",
    "Dockerfile": "5246556d2898d95daf13002942a6db0f728f92b9",
}
SOURCE_PATHS = {
    "unified_app.py": "unified_app.py",
    "admin_ui.py": "admin_ui.py",
    "Dockerfile": "canary/Dockerfile.unified-offline",
}
PRODUCTION = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
}
OLD_CANARY = {
    "xtream-vod-canary-admin":
        "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f",
    "xtream-vod-canary-playback":
        "homedocker/xtream-vod-canary:5c2f02233a0f",
}


def stop(msg):
    raise ValueError(msg)


def run(*args, timeout=35):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        stop("Read-only Docker check failed: " + args[0])
    return p.stdout


def git_blob(data):
    return hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\x00" + data
    ).hexdigest()


def inspect(name):
    result = json.loads(run("docker", "inspect", name))
    if len(result) != 1:
        stop("Docker inspect count invalid: " + name)
    return result[0]


def verify_host():
    for path, expected in PINNED_LOCAL.items():
        if path.is_symlink() or not path.is_file():
            stop("Expected protected file missing: " + path.name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            stop("Expected protected file drift: " + path.name)
    if not (CANARY_ROOT / "secrets/canary.env").is_file():
        stop("Canary secret env file unavailable")
    if not (CANARY_ROOT / "data").is_dir():
        stop("Canary isolated data directory missing")
    image = json.loads(run("docker", "image", "inspect", BASE_IMAGE))
    if len(image) != 1:
        stop("Pinned unified build base image missing")
    identities = {}
    for name, expected in PRODUCTION.items():
        c = inspect(name)
        if (c["Config"]["Image"] != expected
                or c.get("State", {}).get("Health", {}).get("Status") != "healthy"
                or not c.get("State", {}).get("Running")):
            stop("Production image or health invalid: " + name)
        identities[name] = c["Id"]
    for name, expected in OLD_CANARY.items():
        c = inspect(name)
        if c["Config"]["Image"] != expected:
            stop("Legacy Canary image drift: " + name)
        if c["State"]["Running"]:
            stop("Legacy Canary still running; stop old Canary before unified build")
    return identities


def verify_sources(folder):
    opener = build_opener(ProxyHandler({}))
    for target, blob in SOURCES.items():
        source = SOURCE_PATHS[target]
        url = (
            "https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
            + REF + "/" + source
        )
        with opener.open(Request(url), timeout=30) as response:
            content = response.read(150000)
        if git_blob(content) != blob:
            stop("Immutable source integrity mismatch: " + target)
        item = folder / target
        item.write_bytes(content)
        item.chmod(0o600)
    for source in ("unified_app.py", "admin_ui.py"):
        ast.parse((folder / source).read_text(encoding="utf-8"))
    df = (folder / "Dockerfile").read_text()
    if re.search(r"(?mi)^\s*(?:RUN|ADD|HEALTHCHECK)\s", df):
        stop("Dockerfile contains unexpected build/run directives")
    if "FROM " + BASE_IMAGE not in df or "COPY unified_app.py admin_ui.py /srv/" not in df:
        stop("Dockerfile no longer derives from approved local base image")
    print("UNIFIED_SOURCE_AND_DOCKERFILE_PIN=PASS")


def host_ticks():
    row = Path("/proc/stat").read_text().splitlines()[0].split()
    if len(row) < 9 or row[0] != "cpu":
        stop("Host CPU accounting unavailable")
    values = [int(x) for x in row[1:9]]
    return sum(values), values[3] + values[4]


def psi10():
    for row in Path("/proc/pressure/cpu").read_text().splitlines():
        if row.startswith("some "):
            value = re.search(r"avg10=([0-9.]+)", row)
            return float(value.group(1)) if value else None
    return None


def build_gate():
    if os.cpu_count() != 2:
        stop("Expected two logical CPUs for approved light build gate")
    root = Path(run("docker", "info", "--format", "{{.DockerRootDir}}").strip())
    if not root.is_absolute() or not root.is_dir():
        stop("Invalid Docker root directory")
    t0, i0 = host_ticks()
    p0 = psi10()
    time.sleep(10)
    t1, i1 = host_ticks()
    p1 = psi10()
    if t1 <= t0 or p0 is None or p1 is None:
        stop("CPU accounting/pressure sampling unavailable")
    used = 100.0 * (1.0 - (i1 - i0) / (t1 - t0))
    available = next((
        int(line.split()[1]) for line in
        Path("/proc/meminfo").read_text().splitlines()
        if line.startswith("MemAvailable:")
    ), 0)
    disk = shutil.disk_usage(root).free
    print("UNIFIED_BUILD_CPU_UTIL_10S=" + f"{used:.2f}%")
    print("UNIFIED_BUILD_PSI_START=" + f"{p0:.2f}")
    print("UNIFIED_BUILD_PSI_END=" + f"{p1:.2f}")
    print("UNIFIED_BUILD_MEM_AVAILABLE_MIB=" + str(available // 1024))
    print("UNIFIED_BUILD_DOCKER_DISK_FREE_MIB=" + str(disk // 1048576))
    if used >= 75 or max(p0, p1) >= 70 or available < 1048576 or disk < 2147483648:
        stop("UNIFIED_BUILD_RESOURCE_GATE_NOT_READY")
    print("UNIFIED_BUILD_RESOURCE_GATE=PASS")


def image_present():
    check = subprocess.run(
        ["docker", "image", "inspect", CANDIDATE_IMAGE],
        capture_output=True, timeout=20
    )
    return check.returncode == 0


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--build", action="store_true")
    parser.add_argument("--approval", default="")
    args = parser.parse_args()
    if os.geteuid() != 0:
        stop("Run under sudo")
    if args.build and args.approval != CANDIDATE_IMAGE:
        stop("Exact image tag approval required for build-only mode")
    if args.build and image_present():
        stop("Candidate image already present; refuse overwrite")
    original_ids = verify_host()
    with tempfile.TemporaryDirectory(prefix="xtream-unified-build-") as directory:
        folder = Path(directory)
        os.chmod(folder, 0o700)
        verify_sources(folder)
        print("UNIFIED_OLD_CANARY=STOPPED")
        print("UNIFIED_PRODUCTION=HEALTHY_UNCHANGED")
        print("UNIFIED_CANDIDATE_IMAGE=" + CANDIDATE_IMAGE)
        if args.build:
            build_gate()
            if verify_host() != original_ids:
                stop("Production changed during resource check")
            p = subprocess.run(
                ["docker", "build", "--network", "none", "--pull=false",
                 "--progress", "quiet", "-t", CANDIDATE_IMAGE, str(folder)],
                capture_output=True, text=True, timeout=180
            )
            if p.returncode:
                stop("Offline unified FROM+COPY build failed (logs suppressed)")
            if not image_present():
                stop("Unified candidate image absent after build")
            if verify_host() != original_ids:
                stop("Production identities changed during image build")
            print("UNIFIED_IMAGE_BUILD_ONLY=PASS")
            print("CONTAINERS_COMPOSE_NGINX_CHANGED=NO")
            print("NEXT=VERIFY_ONE_CONTAINER_CANARY_RELEASE_GATE")
        else:
            print("UNIFIED_MODE=PLAN_ONLY")
            print("CONTAINERS_COMPOSE_NGINX_CHANGED=NO")
            print("NEXT=AWAIT_SEPARATE_IMAGE_ONLY_BUILD_APPROVAL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as e:
        print("STOP: M3 image plan: " + str(e))
        raise SystemExit(1) from None
