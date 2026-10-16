#!/usr/bin/env python3
"""Stage 5A.3: Canary-only atomic override and verified recreate/rollback.

Default --plan is read-only. --apply requires an exact candidate approval and
pre-recreate CPU gate. Never touches nginx, router, firewall or production
containers. No image build/pull, no credentials/configs/logs printed.
Rollback must verify old Admin AND Playback healthy; otherwise report CRITICAL.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler, Request

PLAN_COMMIT = "ce7b76cb56a3b4699484f682641b6f2b9d5b02cb"
PLAN_BLOB = "822a9c22162c4d54721e98f0346763128a4509c2"
PLAN_URL = (
    "https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
    + PLAN_COMMIT + "/canary/stage5a3_recreate_plan.py"
)
CANDIDATE_SHA = "24ef130ce3c929d29489e78ee3e9ebafff46a14b63066d507994508694b09337"
BACKUP_DIR = Path("/etc/homedocker-backup/xtream-canary-compose-stage5a3")
RECREATE_APPROVAL = "canary-admin-and-playback"
TIMEOUT_HEALTH = 150
EXPECTED_PROD = {
    "xtream-vod-admin": "homedocker/xtream-vod-admin:0.4.3-manifest",
    "xtream-vod-bridge": "homedocker/xtream-vod-bridge:0.4.0",
}


def stop(message):
    raise ValueError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def git_blob(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\x00" + raw
    ).hexdigest()


def command(argv, *, stdin=None, timeout=50):
    p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        stop("Local operation failed: " + argv[0] + " (output suppressed)")
    return p.stdout


def load_pinned_plan(directory):
    with build_opener(ProxyHandler({})).open(Request(PLAN_URL), timeout=25) as r:
        raw = r.read(200000)
    if git_blob(raw) != PLAN_BLOB:
        stop("Pinned Stage5A3 plan source integrity mismatch")
    path = directory / "stage5a3_plan.py"
    path.write_bytes(raw)
    spec = importlib.util.spec_from_file_location("_stage5a3_pinned_plan", path)
    if not spec or not spec.loader:
        stop("Pinned read-only plan cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if sha256(module.CANDIDATE.encode("utf-8")) != CANDIDATE_SHA:
        stop("Pinned candidate override SHA mismatch")
    return module


def validate_plan(plan, scratch):
    plan.check_files()
    original = plan.OVERRIDE.read_bytes()
    if sha256(original) != plan.OVERRIDE_SHA:
        stop("Override SHA changed before recreate")
    before = plan.config(plan.OVERRIDE)
    candidate_file = scratch / "ui-override.yaml"
    candidate_file.write_bytes(plan.CANDIDATE.encode("utf-8"))
    candidate_file.chmod(0o600)
    candidate = plan.config(candidate_file)
    plan.check_composed(before, candidate)
    ids = plan.check_live()
    return original, ids


def host_cpu_sample():
    line = Path("/proc/stat").read_text().splitlines()[0].split()
    if len(line) < 9 or line[0] != "cpu":
        stop("Host CPU accounting missing")
    values = list(map(int, line[1:9]))
    return sum(values), values[3] + values[4]


def readiness(plan):
    if os.cpu_count() != 2:
        stop("Host CPU topology changed")
    a_psi = plan.psi10()
    t0, i0 = host_cpu_sample()
    time.sleep(10)
    b_psi = plan.psi10()
    t1, i1 = host_cpu_sample()
    diff = t1 - t0
    if diff <= 0:
        stop("Host CPU accounting invalid")
    utilization = 100.0 * (1.0 - (i1 - i0) / diff)
    available = None
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            available = int(line.split()[1]) / 1024
            break
    disk_path = Path(
        command(["docker", "info", "--format", "{{.DockerRootDir}}"]).strip()
    )
    if not disk_path.is_absolute() or not disk_path.is_dir():
        stop("Docker data directory invalid")
    disk = shutil.disk_usage(disk_path).free / 1048576
    print("RECREATE_CPU_PSI_AVG10_FIRST=" +
          (f"{a_psi:.2f}" if a_psi is not None else "UNKNOWN"))
    print("RECREATE_CPU_PSI_AVG10_LAST=" +
          (f"{b_psi:.2f}" if b_psi is not None else "UNKNOWN"))
    print("RECREATE_HOST_CPU_UTILIZATION=" + f"{utilization:.2f}%")
    print("RECREATE_MEM_AVAILABLE_MIB=" +
          (str(int(available)) if available is not None else "UNKNOWN"))
    print("RECREATE_DOCKER_DISK_FREE_MIB=" + str(int(disk)))
    if a_psi is None or b_psi is None or a_psi >= 30 or b_psi >= 30:
        stop("RECREATE_CPU_PSI_NOT_READY (both avg10 samples must be <30)")
    if utilization >= 75:
        stop("RECREATE_HOST_CPU_UTILIZATION_NOT_READY")
    if available is None or available < 1024 or disk < 2048:
        stop("RECREATE_MEMORY_OR_DOCKER_DISK_NOT_READY")
    print("RECREATE_RESOURCE_GATE=PASS")


def safe_directory():
    if BACKUP_DIR.is_symlink():
        stop("Backup directory symlink not permitted")
    BACKUP_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    if BACKUP_DIR.is_symlink():
        stop("Backup directory symlink not permitted")
    metadata = BACKUP_DIR.stat()
    if metadata.st_uid != 0 or (stat.S_IMODE(metadata.st_mode) & 0o077):
        stop("Backup directory must be root-owned 0700")


def fsync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_backup(original):
    path = BACKUP_DIR / ("ui-override-before-5a3-" + str(time.time_ns()) + ".yaml")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(original)
        handle.flush()
        os.fsync(handle.fileno())
    fsync_directory(BACKUP_DIR)
    if sha256(path.read_bytes()) != sha256(original):
        stop("Backup verification failed")
    return path


def atomic_override(path, raw, meta):
    fd, tmp = tempfile.mkstemp(prefix=".xtream-stage5a3-", dir=str(path.parent))
    try:
        os.fchown(fd, meta.st_uid, meta.st_gid)
        os.fchmod(fd, stat.S_IMODE(meta.st_mode))
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        fsync_directory(path.parent)
    finally:
        if fd >= 0:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)


def compose_up(plan, service):
    cmd = [
        "docker", "compose", "-p", "xtream-vod-canary",
        "-f", str(plan.BASE), "-f", str(plan.OVERRIDE),
        "up", "-d", "--no-deps", "--no-build", "--force-recreate", service,
    ]
    env = os.environ.copy()
    env.update(CANARY_DIR=str(plan.ROOT), CANARY_IMAGE=plan.PLAY_IMAGE)
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)
    if proc.returncode:
        stop("Canary Compose recreate failed: " + service + " (logs suppressed)")


def inspect(name):
    data = json.loads(command(["docker", "inspect", name], timeout=20))
    if len(data) != 1:
        stop("Docker inspect returned unexpected count: " + name)
    return data[0]


def wait_healthy(name):
    deadline = time.monotonic() + TIMEOUT_HEALTH
    while time.monotonic() < deadline:
        try:
            obj = inspect(name)
            state = obj.get("State", {})
            if state.get("Running") and (state.get("Health") or {}).get("Status") == "healthy":
                return obj
        except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
            pass
        time.sleep(3)
    stop("Canary health verification timed out: " + name)


def verify_prod(original_ids):
    for name, image in EXPECTED_PROD.items():
        obj = inspect(name)
        if obj.get("Id") != original_ids[name]:
            stop("Production container identity changed: " + name)
        if obj.get("Config", {}).get("Image") != image:
            stop("Production image identity changed: " + name)
        if (obj.get("State", {}).get("Health") or {}).get("Status") != "healthy":
            stop("Production health changed: " + name)


def verify_canary(plan, name, expected_image, *, old_id=None):
    obj = wait_healthy(name)
    if obj.get("Config", {}).get("Image") != expected_image:
        stop("Canary image identity invalid: " + name)
    if old_id is not None and obj.get("Id") == old_id:
        stop("Canary was not recreated: " + name)
    labels = obj.get("Config", {}).get("Labels") or {}
    if labels.get("com.docker.compose.project") != "xtream-vod-canary":
        stop("Canary Compose project ownership invalid: " + name)
    attachments = obj.get("NetworkSettings", {}).get("Networks") or {}
    if set(attachments) != {plan.NETWORK}:
        stop("Canary attached to unauthorized network: " + name)
    net = json.loads(command(["docker", "network", "inspect", plan.NETWORK]))
    if len(net) != 1 or net[0].get("Internal") is not True:
        stop("Canary Docker network no longer internal")
    ports = obj.get("NetworkSettings", {}).get("Ports") or {}
    if any(entry is not None for entry in ports.values()):
        stop("Canary has active host ports: " + name)
    if command(["docker", "port", name]).strip():
        stop("Canary docker port shows host publication: " + name)
    configured = obj.get("HostConfig", {}).get("PortBindings") or {}
    if any(binding for binding in configured.values()):
        stop("Canary recreated with dormant/active host bindings: " + name)
    return obj


ADMIN_SMOKE = """
import app, admin_auth, admin_ui, route_paths, urllib.request
origin = "https://olivergiangvu.asuscomm.com:18450"
assert app.PUBLIC == origin + "/canary"
assert admin_auth.PUBLIC_ORIGIN == origin
assert route_paths.LOGIN_PATH == "/canary/admin-signin/"
assert route_paths.ADMIN_PATH == "/canary/admin/"
assert admin_auth.COOKIE == "xtream_canary_admin_session"
assert admin_auth.COOKIE_PATH == "/canary/admin/"
assert admin_ui.GATE_LOGIN_COOKIE == "xtream_canary_login_nonce"
with urllib.request.urlopen("http://127.0.0.1:8768/gateway/", timeout=10) as r:
    assert r.status == 200
    assert 'action="/canary/admin-signin/"' in r.read().decode()
    assert "Path=/canary/admin-signin/" in r.headers.get("Set-Cookie", "")
with urllib.request.urlopen("http://127.0.0.1:8768/", timeout=10) as r:
    html = r.read().decode()
    assert 'id="personalWorkspace"' in html
    assert 'id="adminWorkspace"' in html
"""

PLAY_SMOKE = """
import app
assert app.PUBLIC == "https://olivergiangvu.asuscomm.com:18450/canary"
"""


def smoke(name, script):
    command(["docker", "exec", "-i", name, "python", "-"],
            stdin=script, timeout=30)


def verify_unchanged(plan, original_ids):
    verify_prod(original_ids)
    if sha256(plan.BASE.read_bytes()) != plan.BASE_SHA:
        stop("Canary base Compose SHA drifted")
    if sha256(plan.VHOST.read_bytes()) != plan.VHOST_SHA:
        stop("Nginx production vhost SHA drifted")


def rollback(plan, original, original_ids, *, recreate_attempted):
    print("ROLLBACK_STAGE5A3_STARTED=TRUE", flush=True)
    errors = []
    override_restored = False
    try:
        metadata = plan.OVERRIDE.stat()
        atomic_override(plan.OVERRIDE, original, metadata)
        if sha256(plan.OVERRIDE.read_bytes()) != plan.OVERRIDE_SHA:
            stop("Canary override restoration SHA mismatch")
        override_restored = True
        print("ROLLBACK_OVERRIDE_BYTES=VERIFIED", flush=True)
    except Exception:
        errors.append("OVERRIDE_RESTORE_FAILED")
    if recreate_attempted and not override_restored:
        errors.append("RECREATE_ROLLBACK_BLOCKED_UNVERIFIED_OVERRIDE")
    if recreate_attempted and override_restored:
        for service in ("xtream-vod-bridge", "xtream-vod-admin"):
            try:
                compose_up(plan, service)
                cname = ("xtream-vod-canary-playback"
                         if service == "xtream-vod-bridge" else "xtream-vod-canary-admin")
                expected = plan.PLAY_IMAGE if service == "xtream-vod-bridge" else plan.OLD_ADMIN
                verify_canary(plan, cname, expected)
            except Exception:
                errors.append("CONTAINER_RESTORE_FAILED_" + service)
    try:
        if not override_restored:
            stop("Override file not restored; do not claim recovery")
        if recreate_attempted:
            verify_canary(plan, "xtream-vod-canary-playback", plan.PLAY_IMAGE)
            verify_canary(plan, "xtream-vod-canary-admin", plan.OLD_ADMIN)
        else:
            current_ids = plan.check_live()
            for name in ("xtream-vod-canary-playback", "xtream-vod-canary-admin"):
                if current_ids[name] != original_ids[name]:
                    stop("Original Canary identity changed during file-only rollback")
        verify_unchanged(plan, original_ids)
    except Exception:
        errors.append("POST_ROLLBACK_HEALTH_OR_PRODUCTION_AUDIT_FAILED")
    if errors:
        print("CRITICAL_ROLLBACK_VERIFIED=NO", flush=True)
        print("ROLLBACK_PROBLEM_CODES=" + ",".join(errors), flush=True)
        return False
    print("ROLLBACK_OLD_IMAGES_AND_HEALTH=PASS", flush=True)
    print("ROLLBACK_PRIVATE_NETWORK_AND_ZERO_PORTS=PASS", flush=True)
    print("ROLLBACK_PRODUCTION_UNCHANGED=PASS", flush=True)
    print("ROLLBACK_VERIFIED=YES", flush=True)
    return True


def caught_signal(signum, _frame):
    raise InterruptedError("Stage5A3 interrupted by signal " + str(signum))


def apply(plan, scratch):
    safe_directory()
    lock_path = BACKUP_DIR / ".lock"
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        original, original_ids = validate_plan(plan, scratch)
        readiness(plan)
        # Nothing may drift during the resource gate.
        current, fresh_ids = validate_plan(plan, scratch)
        if current != original or fresh_ids != original_ids:
            stop("Canary baseline changed while checking CPU readiness")
        backup = write_backup(original)
        print("STAGE5A3_BACKUP_PATH=" + str(backup), flush=True)
        print("STAGE5A3_BACKUP_SHA256=" + sha256(backup.read_bytes()), flush=True)

        old_signals = {
            s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)
        }
        for s in old_signals:
            signal.signal(s, caught_signal)

        modified = False
        recreate_attempted = False
        try:
            modified = True
            metadata = plan.OVERRIDE.stat()
            atomic_override(plan.OVERRIDE, plan.CANDIDATE.encode("utf-8"), metadata)
            if sha256(plan.OVERRIDE.read_bytes()) != CANDIDATE_SHA:
                stop("Candidate override was not written byte-for-byte")
            print("STAGE5A3_OVERRIDE_ATOMIC_APPLY=PASS", flush=True)

            recreate_attempted = True
            compose_up(plan, "xtream-vod-bridge")
            verify_canary(plan, "xtream-vod-canary-playback", plan.PLAY_IMAGE,
                          old_id=original_ids["xtream-vod-canary-playback"])
            print("STAGE5A3_PLAYBACK_RECREATE_HEALTH=PASS", flush=True)
            verify_prod(original_ids)

            compose_up(plan, "xtream-vod-admin")
            verify_canary(plan, "xtream-vod-canary-admin", plan.NEW_ADMIN,
                          old_id=original_ids["xtream-vod-canary-admin"])
            print("STAGE5A3_ADMIN_RECREATE_HEALTH=PASS", flush=True)
            smoke("xtream-vod-canary-admin", ADMIN_SMOKE)
            smoke("xtream-vod-canary-playback", PLAY_SMOKE)
            print("STAGE5A3_PREFIX_COOKIE_AND_PLAYBACK_SMOKE=PASS", flush=True)
            verify_unchanged(plan, original_ids)
            print("STAGE5A3_PRODUCTION_UNCHANGED=PASS", flush=True)
            print("STAGE5A3_ZERO_PORTS_AND_PRIVATE_NETWORK=PASS", flush=True)
            print("STAGE5A3_APPLY=PASS", flush=True)
            print("NGINX_AND_FIREWALL_CHANGED=NO", flush=True)
            print("NEXT=REDISCOVER_CANARY_DOCKER_IPS_FOR_STAGE5B", flush=True)
        except BaseException:
            if modified:
                ok = rollback(plan, original, original_ids,
                              recreate_attempted=recreate_attempted)
                if not ok:
                    print("CRITICAL_STOP_KEEP_BACKUP_AND_DO_NOT_RETRY", flush=True)
            raise
        finally:
            for s, previous in old_signals.items():
                signal.signal(s, previous)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--plan", action="store_true")
    modes.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-candidate-sha", default="")
    parser.add_argument("--approved-recreate", default="")
    args = parser.parse_args()
    if os.geteuid() != 0:
        stop("Run under sudo for root-only Compose and backup audits")
    if args.apply and (
        args.approved_candidate_sha != CANDIDATE_SHA
        or args.approved_recreate != RECREATE_APPROVAL
    ):
        stop("Exact Canary recreate approval tokens required")
    with tempfile.TemporaryDirectory(prefix="xtream-stage5a3-safe-") as folder:
        scratch = Path(folder)
        os.chmod(scratch, 0o700)
        plan = load_pinned_plan(scratch)
        original, ids = validate_plan(plan, scratch)
        print("STAGE5A3_APPLY_SCRIPT_PRECHECK=PASS")
        print("STAGE5A3_PINNED_PLAN_CODE=PASS")
        print("STAGE5A3_PREVIEW_EFFECTIVE_ONLY_APPROVED_CHANGES=PASS")
        print("STAGE5A3_OVERRIDE_CURRENT_SHA256=" + sha256(original))
        print("STAGE5A3_OVERRIDE_CANDIDATE_SHA256=" + CANDIDATE_SHA)
        print("STAGE5A3_ROLLBACK_IMAGES_AND_HEALTH=READY")
        print("STAGE5A3_PRODUCTION_IDS_SAVED_IN_MEMORY=PASS")
        if args.apply:
            apply(plan, scratch)
        else:
            print("STAGE5A3_MODE=PLAN_ONLY")
            print("LIVE_FILES_AND_CONTAINERS_CHANGED=NONE")
            print("NGINX_OR_FIREWALL_CHANGED=NO")
            print("APPLY_APPROVAL=NOT_GRANTED")
            print("NEXT=REVIEW_RECREATE_RISKS_AND_OBTAIN_SEPARATE_APPROVAL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired,
            InterruptedError, KeyboardInterrupt) as exc:
        print("STOP: Stage5A3 apply: " + str(exc))
        raise SystemExit(1) from None
