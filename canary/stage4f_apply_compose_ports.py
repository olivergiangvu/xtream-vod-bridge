#!/usr/bin/env python3
"""Stage 4F: root-only, fail-closed Canary Compose port-stanza repair.

Default is PLAN, no live writes. APPLY is an independently authorized action.
NEVER recreates any container, changes nginx, touches production or exposes env.
"""
from __future__ import annotations
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

BASE = Path("/opt/xtream-vod-canary/src/canary/compose.yaml")
OVERRIDE = Path("/opt/xtream-vod-canary/ui-override.yaml")
NGINX = Path("/etc/nginx/conf.d/xtream-vod-bridge-18450.conf")
BACKUP_ROOT = Path("/etc/homedocker-backup/xtream-canary-compose-stage4f")
EXPECTED = {
    BASE: "79d4cb76db03ae881769339e4e2b851e1c68c1e1bb6133a62661dbdbca49a42e",
    OVERRIDE: "eab5db9b32c81dd7d22ddfbd00c86b2fec9d927e8281120eafe2628025927bda",
    NGINX: "8746edfcc5b899ee8c4381c0890d203b0dd3aada33390eab0d389cc54faedd35",
}
CANDIDATE_SHA = "bbbc26eaf33fd8005aff5f1e0e58ae4912bed6cd56fe96cb407b1ce4ea9de354"
PLAY_IMAGE = "homedocker/xtream-vod-canary:5c2f02233a0f"
EXPECTED_PORTS = {"18769": ("xtream-vod-bridge", 8767),
                  "18770": ("xtream-vod-admin", 8768)}
EXPECTED_IMAGES = {
    "xtream-vod-bridge": PLAY_IMAGE,
    "xtream-vod-admin":
        "homedocker/xtream-vod-canary-admin:0.5e-cookie-e153b327b49f",
}


def stop(msg):
    raise ValueError(msg)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def preview_patch(original):
    """Strict exact known two-line removals; output must match pinned SHA."""
    source = original.decode("utf-8")
    result = source
    for published in EXPECTED_PORTS:
        pattern = (
            r'(?m)^    ports:\n      - (?P<q>["\x27]?)127\.0\.0\.1:'
            + published + ":" + str(EXPECTED_PORTS[published][1])
            + r'(?P=q)\n'
        )
        result, count = re.subn(pattern, "", result)
        if count != 1:
            stop("Canary port stanza does not match approved line layout")
    candidate = result.encode("utf-8")
    if digest(candidate) != CANDIDATE_SHA:
        stop("Canary repair does not match pinned candidate SHA256")
    if digest(original) != EXPECTED[BASE]:
        stop("Original Canary Compose SHA no longer matches")
    return candidate


def compose(file_path):
    env = os.environ.copy()
    env.update(CANARY_DIR="/opt/xtream-vod-canary", CANARY_IMAGE=PLAY_IMAGE)
    cmd = ["docker", "compose", "-p", "xtream-vod-canary",
           "--project-directory", str(BASE.parent),
           "-f", str(file_path), "-f", str(OVERRIDE),
           "config", "--format", "json"]
    out = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=45)
    if out.returncode:
        stop("Compose candidate validation failed (output suppressed)")
    return json.loads(out.stdout)


def compare_compose(before, after):
    if set(before.get("services", {})) != set(EXPECTED_IMAGES):
        stop("Unexpected original Compose service inventory")
    if set(after.get("services", {})) != set(EXPECTED_IMAGES):
        stop("Candidate service inventory changed")
    baseline = copy.deepcopy(before)
    for service, image in EXPECTED_IMAGES.items():
        old = before["services"][service]
        new = after["services"][service]
        if old.get("image") != image:
            stop("Original image differs from pinned Canary image")
        ports = old.get("ports") or []
        if len(ports) != 1 or not isinstance(ports[0], dict):
            stop("Original Compose port count differs")
        p = ports[0]
        published = next((key for key, value in EXPECTED_PORTS.items()
                          if value[0] == service), None)
        if (str(p.get("published")) != published
            or p.get("host_ip") != "127.0.0.1"
            or str(p.get("target")) != str(EXPECTED_PORTS[published][1])):
            stop("Original Compose port binding differs")
        if new.get("ports"):
            stop("Candidate Compose still publishes ports")
        baseline["services"][service].pop("ports", None)
    if baseline != after:
        stop("Candidate changed non-port effective Compose settings")
    network = after.get("networks", {}).get("private_canary", {})
    if network.get("internal") is not True:
        stop("Candidate Canary Docker network is not internal")


def verified_file(path, expected):
    if not path.is_file() or path.is_symlink():
        stop("Expected live file missing/symlink: " + path.name)
    data = path.read_bytes()
    if digest(data) != expected:
        stop("Live file SHA drift: " + path.name)
    return data


def atomic_bytes(path, data, metadata):
    fd, tmp = tempfile.mkstemp(prefix=".xtream-stage4f-", dir=str(path.parent))
    try:
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        os.fchown(fd, metadata.st_uid, metadata.st_gid)
        with os.fdopen(fd, "wb") as out:
            fd = -1
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-candidate-sha", default="")
    args = parser.parse_args()

    if args.apply and args.approved_candidate_sha != CANDIDATE_SHA:
        stop("Explicit exact candidate approval token required")
    if os.geteuid() != 0:
        stop("Use sudo for read-only review or authorized apply")

    original = verified_file(BASE, EXPECTED[BASE])
    verified_file(OVERRIDE, EXPECTED[OVERRIDE])
    verified_file(NGINX, EXPECTED[NGINX])
    candidate = preview_patch(original)

    before = compose(BASE)
    with tempfile.TemporaryDirectory(prefix="xtream-stage4f-preview-") as td:
        trial = Path(td) / "compose.yaml"
        trial.write_bytes(candidate)
        compare_compose(before, compose(trial))

    print("STAGE4F_SAFE_CANDIDATE=PASS")
    print("ORIGINAL_SHA256=" + EXPECTED[BASE])
    print("CANDIDATE_SHA256=" + CANDIDATE_SHA)
    print("EFFECTIVE_COMPOSE_ONLY_TWO_PORTS_REMOVED=PASS")
    print("PRODUCTION_NGINX_UNCHANGED=PASS")
    if not args.apply:
        print("STAGE4F_MODE=PLAN_ONLY")
        print("LIVE_FILES_CHANGED=NONE")
        print("CANARY_CONTAINERS_RECREATED=NO")
        return

    if BACKUP_ROOT.is_symlink():
        stop("Unsafe backup directory symlink")
    BACKUP_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUP_ROOT.is_symlink():
        stop("Unsafe backup directory symlink")
    root_stat = BACKUP_ROOT.stat()
    if root_stat.st_uid != 0 or stat.S_IMODE(root_stat.st_mode) & 0o077:
        stop("Backup directory not root-owned and private")
    lockpath = BACKUP_ROOT / ".lock"
    fdlock = os.open(lockpath, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fdlock, fcntl.LOCK_EX)
        original = verified_file(BASE, EXPECTED[BASE])
        verified_file(OVERRIDE, EXPECTED[OVERRIDE])
        verified_file(NGINX, EXPECTED[NGINX])
        candidate = preview_patch(original)
        metadata = BASE.stat()
        fname = "compose-" + str(time.time_ns()) + "-before-ports.yaml"
        backup = BACKUP_ROOT / fname
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(original)
            out.flush()
            os.fsync(out.fileno())
        if digest(backup.read_bytes()) != EXPECTED[BASE]:
            stop("Backup integrity failure")
        applied = False
        try:
            atomic_bytes(BASE, candidate, metadata)
            applied = True
            if digest(BASE.read_bytes()) != CANDIDATE_SHA:
                stop("Written Canary Compose SHA mismatch")
            with tempfile.TemporaryDirectory(prefix="xtream-stage4f-check-") as td:
                # Re-check effective Compose without writing to production.
                after = compose(BASE)
                compare_compose(before, after)
        except Exception:
            if applied:
                atomic_bytes(BASE, original, metadata)
                print("STAGE4F_AUTOMATIC_ROLLBACK_ATTEMPTED=TRUE")
            raise
        print("STAGE4F_FILE_APPLY=PASS")
        print("BACKUP_PATH=" + str(backup))
        print("BACKUP_SHA256=" + EXPECTED[BASE])
        print("COMPOSE_BASE_SHA256=" + digest(BASE.read_bytes()))
        print("PRODUCTION_CONTAINERS_RECREATED=NO")
        print("CANARY_CONTAINERS_RECREATED=NO")
        print("NGINX_OR_FIREWALL_CHANGED=NO")
        print("NEXT=REVIEW_CANARY_IMAGE_UPGRADE_AND_ROLLBACK")
    finally:
        os.close(fdlock)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired) as err:
        print("STOP: Stage 4F: " + str(err))
        raise SystemExit(1) from None
