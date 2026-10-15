#!/usr/bin/env python3
"""Stage M3.3B — bounded startup failure reproduction, read-only by default.

A separate, explicitly approved --run clones the RETAINED Canary snapshot to a
new disposable directory, starts ONE isolated diagnostic container, captures
ONLY allowlisted status / Python traceback shape, then removes the diagnostic
container and disposable data. The prior snapshot and production are never
written to. No nginx/firewall/Compose mutation, provider egress or host ports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

ROOT = Path("/opt/xtream-vod-canary")
SOURCE = ROOT / "unified-data"
LEGACY = ROOT / "data"
IMAGE = "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd"
NAME = "xtream-vod-unified-diagnostic"
ENVFILE = ROOT / "secrets/canary.env"
APPROVAL = "run-one-offline-unified-startup-diagnostic"
PROD = {
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
}
LEGACY_CANARY = (
    "xtream-vod-canary-playback",
    "xtream-vod-canary-admin",
)
MAX_BYTES = 512 * 1024 * 1024
MAX_FILES = 10000


def guard(value, code):
    if not value:
        raise RuntimeError(code)


def execute(argv, *, timeout=35, check=True):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, text=True)
    if check:
        guard(p.returncode == 0, "COMMAND_FAILURE_" + Path(argv[0]).name)
    return p


def docker_inspect(name):
    p = execute(["docker", "container", "inspect", name], check=False)
    if p.returncode:
        return None
    data = json.loads(p.stdout)
    guard(len(data) == 1, "CONTAINER_INSPECT_AMBIGUOUS")
    return data[0]


def protected_baseline():
    ids = {}
    for name, expected in PROD.items():
        item = docker_inspect(name)
        guard(item is not None and item["Config"]["Image"] == expected
              and item["State"]["Running"]
              and (item["State"].get("Health") or {}).get("Status") == "healthy",
              "PRODUCTION_UNEXPECTED_" + name)
        ids[name] = item["Id"]
    for name in LEGACY_CANARY:
        item = docker_inspect(name)
        guard(item is not None and not item["State"]["Running"],
              "OLD_CANARY_UNEXPECTED_" + name)
    guard(docker_inspect("xtream-vod-unified-canary") is None,
          "UNIFIED_CANARY_UNEXPECTEDLY_EXISTS")
    guard(docker_inspect(NAME) is None, "DIAGNOSTIC_CONTAINER_ALREADY_EXISTS")
    print("PRODUCTION_HEALTH_AND_IDENTITIES=VERIFIED", flush=True)
    print("OLD_CANARIES_STOPPED=PASS", flush=True)
    return ids


def verify_unchanged(ids):
    for name, cid in ids.items():
        item = docker_inspect(name)
        guard(item is not None and item["Id"] == cid and
              item["State"]["Running"] and
              (item["State"].get("Health") or {}).get("Status") == "healthy",
              "PRODUCTION_CHANGED_" + name)


def image_check():
    p = execute(["docker", "image", "inspect", IMAGE])
    data = json.loads(p.stdout)
    guard(len(data) == 1, "IMAGE_NOT_UNIQUE")
    cfg = data[0]["Config"]
    guard("unified_app:application" in (cfg.get("Cmd") or []),
          "IMAGE_NOT_UNIFIED_ENTRYPOINT")
    guard(cfg.get("User") == "10001:10001", "IMAGE_USER_DRIFTED")
    print("LOCAL_UNIFIED_IMAGE=VERIFIED", flush=True)


def snapshot_check():
    guard(SOURCE.is_dir() and not SOURCE.is_symlink(),
          "RETAINED_DATA_SNAPSHOT_MISSING")
    guard(LEGACY.is_dir() and not LEGACY.is_symlink(),
          "OLD_CANARY_DATA_MISSING")
    guard(ENVFILE.is_file() and not ENVFILE.is_symlink(),
          "CANARY_ENV_FILE_MISSING")
    size = count = 0
    for base, dirs, files in os.walk(SOURCE, followlinks=False):
        for name in dirs + files:
            st = (Path(base) / name).lstat()
            guard(stat.S_ISDIR(st.st_mode) or
                  (stat.S_ISREG(st.st_mode) and st.st_nlink == 1),
                  "UNSAFE_SNAPSHOT_LINK_OR_FILE")
            if stat.S_ISREG(st.st_mode):
                size += st.st_size
                count += 1
                guard(size <= MAX_BYTES and count <= MAX_FILES,
                      "SNAPSHOT_SIZE_EXCEEDS_LIMIT")
    guard((SOURCE / "index.sqlite").is_file(), "SQLITE_SNAPSHOT_MISSING")
    print("RETAINED_SNAPSHOT_READONLY_SOURCE=PASS", flush=True)
    print("SNAPSHOT_SIZE_MIB=" + str(round(size / 1048576, 2)), flush=True)


def cpu_gate():
    # One-off 0.5-core service, avoid adding load during extreme contention.
    row = Path("/proc/stat").read_text().splitlines()[0].split()
    start = [int(x) for x in row[1:9]]
    def psi():
        line = next((s for s in
                     Path("/proc/pressure/cpu").read_text().splitlines()
                     if s.startswith("some ")), "")
        match = re.search(r"avg10=([0-9.]+)", line)
        return float(match.group(1)) if match else None
    before = psi()
    time.sleep(10)
    row = Path("/proc/stat").read_text().splitlines()[0].split()
    end = [int(x) for x in row[1:9]]
    after = psi()
    total = sum(end) - sum(start)
    idle = (end[3] + end[4]) - (start[3] + start[4])
    mem = next((int(s.split()[1]) for s in
                Path("/proc/meminfo").read_text().splitlines()
                if s.startswith("MemAvailable:")), 0)
    guard(os.cpu_count() == 2 and total > 0 and
          before is not None and after is not None, "RESOURCE_METRICS_MISSING")
    cpu = 100 * (1 - idle / total)
    print("DIAGNOSTIC_CPU_10S=" + f"{cpu:.2f}%", flush=True)
    print("DIAGNOSTIC_PSI_START=" + f"{before:.2f}", flush=True)
    print("DIAGNOSTIC_PSI_END=" + f"{after:.2f}", flush=True)
    print("DIAGNOSTIC_AVAILABLE_RAM_MIB=" + str(mem // 1024), flush=True)
    guard(cpu < 75 and max(before, after) < 70 and mem >= 1048576,
          "DIAGNOSTIC_RESOURCE_GATE_NOT_READY")
    print("DIAGNOSTIC_RESOURCE_GATE=PASS", flush=True)


def file_sha(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(262144), b""):
            h.update(chunk)
    return h.digest()


def disposable_clone(folder):
    """A fresh clone is used; never mount the retained snapshot writable."""
    target = folder / "data"
    srcstat = SOURCE.stat()
    target.mkdir(mode=0o700)
    for base, dirs, files in os.walk(SOURCE, followlinks=False):
        sub = Path(base).relative_to(SOURCE)
        dest = target / sub
        info = Path(base).lstat()
        guard(stat.S_ISDIR(info.st_mode), "UNEXPECTED_SNAPSHOT_DIR")
        os.chown(dest, info.st_uid, info.st_gid)
        os.chmod(dest, stat.S_IMODE(info.st_mode))
        for name in dirs:
            child = Path(base) / name
            guard(stat.S_ISDIR(child.lstat().st_mode),
                  "SNAPSHOT_DIRECTORY_CHANGED")
            (dest / name).mkdir(mode=0o700)
        for name in files:
            child = Path(base) / name
            st = child.lstat()
            guard(stat.S_ISREG(st.st_mode) and st.st_nlink == 1,
                  "SNAPSHOT_FILE_CHANGED")
            copy = dest / name
            shutil.copyfile(child, copy, follow_symlinks=False)
            os.chown(copy, st.st_uid, st.st_gid)
            os.chmod(copy, stat.S_IMODE(st.st_mode))
            guard(file_sha(child) == file_sha(copy), "SNAPSHOT_COPY_MISMATCH")
    print("DISPOSABLE_SNAPSHOT_CLONED=PASS", flush=True)
    return target


def safe_diag(logtext: str):
    """Never echo arbitrary stderr/log lines or URLs/secret values."""
    frame = re.compile(r'^\s*File\s+"([^"]+)",\s+line\s+(\d+),\s+in\s+(.+)$')
    exception = re.compile(r"^([A-Za-z_][A-Za-z_0-9.]*(?:Error|Exception))(?::|$)")
    frames = []
    categories = []
    for raw in logtext.splitlines():
        match = frame.match(raw)
        if match:
            name = Path(match.group(1)).name
            # File basenames must match expected Python module shape.
            if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*\.py", name):
                frames.append(f"{name}:L{match.group(2)}")
        match = exception.match(raw)
        if match:
            categories.append(match.group(1))
    print("TRACEBACK_FRAMES_LAST_8=" + (",".join(frames[-8:]) or "NONE"), flush=True)
    print("EXCEPTION_TYPES=" + (",".join(categories[-5:]) or "NONE"), flush=True)
    # Report only hardcoded categories; never echo arbitrary exception messages.
    patterns = {
        "MISSING_PYTHON_MODULE": r"No module named",
        "SQLITE_DATABASE_READONLY": r"attempt to write a readonly database",
        "SQLITE_DATABASE_OPEN_FAILED": r"unable to open database file",
        "SQLITE_SCHEMA_MISSING": r"no such table:",
        "PERMISSION_DENIED": r"Permission denied",
        "MISSING_OR_PLACEHOLDER_CONFIG": r"Missing/placeholder configuration",
        "PORT_BIND_FAILED": r"address already in use",
        "ROOT_FS_READONLY": r"Read-only file system",
        "APP_IMPORT_FAILED": r"Error loading ASGI app",
        "STARTUP_FAILED": r"Application startup failed",
    }
    codes = [code for code, pattern in patterns.items()
             if re.search(pattern, logtext, re.IGNORECASE)]
    print("ERROR_CLASSIFICATION=" + (",".join(codes) or "UNCLASSIFIED"), flush=True)
    print("TRACEBACK_MESSAGES_OR_ENV_VALUES_PRINTED=NO", flush=True)


def run_one(ids, folder):
    data = disposable_clone(folder)
    args = [
        "docker", "run", "--detach", "--name", NAME,
        "--network", "none", "--publish-all=false",
        "--restart", "no", "--cpus", "0.5", "--memory", "256m",
        "--pids-limit", "64", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
        "--user", "10001:10001",
        "--env-file", str(ENVFILE),
        "-e", "XTREAM_UNIFIED_MODE=1",
        "-e", "LEGACY_SYNC_ENABLED=0",
        "-e", "XTREAM_URL_PREFIX=/canary",
        "-e", "XTREAM_SESSION_COOKIE=xtream_canary_admin_session",
        "-e", "XTREAM_LOGIN_NONCE_COOKIE=xtream_canary_login_nonce",
        "-e", "XTREAM_GATEWAY_REFERRER_POLICY=same-origin",
        "-e", "ADMIN_PUBLIC_ORIGIN=https://olivergiangvu.asuscomm.com:18450",
        "-e", "PUBLIC_BASE_URL=https://olivergiangvu.asuscomm.com:18450/canary",
        "--mount", f"type=bind,src={data},dst=/data",
        "--pull", "never",
        IMAGE
    ]
    result = execute(args, check=False, timeout=80)
    guard(result.returncode == 0, "DIAGNOSTIC_DOCKER_RUN_FAILED")
    print("DIAGNOSTIC_CONTAINER_CREATED=PASS", flush=True)
    time.sleep(12)
    obj = docker_inspect(NAME)
    guard(obj is not None, "DIAGNOSTIC_CONTAINER_DISAPPEARED")
    host = obj.get("HostConfig") or {}
    guard(host.get("NetworkMode") == "none" and
          host.get("NanoCpus") == 500000000 and
          host.get("Memory") == 268435456 and
          host.get("ReadonlyRootfs") is True and
          not (host.get("PortBindings") or {}),
          "DIAGNOSTIC_CONTAINMENT_INVALID")
    state = obj.get("State") or {}
    print("DIAGNOSTIC_RUNNING=" + str(bool(state.get("Running"))), flush=True)
    print("DIAGNOSTIC_EXIT_CODE=" + str(state.get("ExitCode")), flush=True)
    print("DIAGNOSTIC_OOM_KILLED=" + str(bool(state.get("OOMKilled"))), flush=True)
    print("DIAGNOSTIC_NETWORK=NONE", flush=True)
    print("DIAGNOSTIC_PUBLISHED_HOST_PORTS=ZERO", flush=True)
    logs = execute(["docker", "logs", "--tail", "120", NAME],
                   check=False, timeout=20)
    safe_diag((logs.stdout + "\n" + logs.stderr)[-131072:])
    verify_unchanged(ids)
    print("PRODUCTION_UNCHANGED_AFTER_DIAGNOSTIC=PASS", flush=True)


def cleanup(ids):
    obj = docker_inspect(NAME)
    if obj is not None:
        guard(obj["Config"]["Image"] == IMAGE and
              obj.get("HostConfig", {}).get("NetworkMode") == "none",
              "REFUSE_TO_CLEAN_UNIDENTIFIED_CONTAINER")
        if obj["State"].get("Running"):
            execute(["docker", "stop", "--time", "10", NAME], timeout=30)
        execute(["docker", "rm", NAME], timeout=30)
    guard(docker_inspect(NAME) is None, "DIAGNOSTIC_CONTAINER_NOT_REMOVED")
    verify_unchanged(ids)
    print("DIAGNOSTIC_CONTAINER_CLEANUP=VERIFIED", flush=True)
    print("PRODUCTION_IDENTITIES_AFTER_CLEANUP=UNCHANGED", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--approval", default="")
    args = parser.parse_args()
    guard(os.geteuid() == 0, "SUDO_REQUIRED")
    guard(not args.run or args.approval == APPROVAL,
          "EXPLICIT_DIAGNOSTIC_CONTAINER_START_APPROVAL_REQUIRED")
    ids = protected_baseline()
    image_check()
    snapshot_check()
    print("DIAGNOSTIC_SCOPE=ONE_TEMPORARY_NO_NETWORK_CONTAINER")
    if not args.run:
        print("DIAGNOSTIC_MODE=PLAN_ONLY")
        print("CONTAINERS_AND_FILES_MODIFIED=NONE")
        print("START_APPROVAL=NO")
        return
    cpu_gate()
    ids2 = protected_baseline()
    guard(ids == ids2, "BASELINE_CHANGED_WHILE_SAMPLING")
    try:
        # tempfile is created only after all preflight gates have passed.
        with tempfile.TemporaryDirectory(prefix=".unified-diagnostic-",
                                         dir=ROOT) as temp:
            try:
                run_one(ids, Path(temp))
            finally:
                cleanup(ids)
    finally:
        # Only remove the temporary diagnostic directory, not retained /unified-data.
        print("RETAINED_UNIFIED_DATA_UNCHANGED_BY_MOUNT=YES")
    print("DIAGNOSTIC_RUN_COMPLETE=PASS")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # No arbitrary exception messages (potential secrets) are printed.
        print("STOP_M3_3B=" + type(exc).__name__)
        raise SystemExit(1) from None
