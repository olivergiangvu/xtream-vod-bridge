#!/usr/bin/env python3
"""M3.2: ONE isolated Unified Canary; read-only by default, explicit --apply.

No nginx/firewall/Production/legacy-Canary mutation, no new published ports.
Apply clones stopped Canary data, starts only the new unified Canary, verifies
health, auth, private network and resource limits. Failure restores the prior
runtime state; the isolated test-data clone is retained for investigation.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from urllib.request import Request, ProxyHandler, build_opener

PIN_COMMIT = "f1dac319d428043183b4d4e56e6ea6a24e53b50c"
PIN_BLOB = "91ec448409dd686157ea298283cf6cf5dac1cea7"
PLAN_URL = ("https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
            + PIN_COMMIT + "/canary/stage6_unified_launch_plan.py")
CANARY_IMAGE = "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd"
APPROVAL = "start-only-one-private-unified-canary"
COMPOSE_TARGET = Path("/opt/xtream-vod-canary/unified-compose.yaml")
LOCK_DIR = Path("/etc/homedocker-backup/xtream-unified-canary-m3")
HEALTH_TIMEOUT = 120


def ensure(condition, code):
    if not condition:
        raise ValueError(code)


def run(argv, *, env=None, timeout=40, stdin=None):
    result = subprocess.run(argv, input=stdin, capture_output=True,
                            text=True, timeout=timeout, env=env)
    ensure(result.returncode == 0, "COMMAND_FAILED_" + argv[0])
    return result.stdout


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def pinned_plan(folder):
    with build_opener(ProxyHandler({})).open(
        Request(PLAN_URL), timeout=30
    ) as response:
        raw = response.read(100000)
    ensure(blob(raw) == PIN_BLOB, "PINNED_PLAN_SOURCE_INTEGRITY_FAILED")
    path = folder / "stage6_unified_launch_plan.py"
    path.write_bytes(raw)
    spec = importlib.util.spec_from_file_location("_m3_launch_plan", path)
    ensure(spec is not None and spec.loader is not None,
           "PINNED_PLAN_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    print("PINNED_STAGE_M3_1_PLAN=PASS")
    return module


def baseline(plan, folder):
    plan.check_protected()
    production_ids = plan.check_containers()
    plan.verify_image()
    size = plan.source_snapshot_inventory()
    path = plan.download_compose(folder)
    cfg = plan.effective(path)
    plan.check_effective(cfg)
    raw = path.read_bytes()
    ensure(plan.git_blob(raw) == plan.COMPOSE_BLOB,
           "APPROVED_COMPOSE_INTEGRITY_FAILED")
    return production_ids, raw, size


def prod_unchanged(plan, ids):
    for name, expected in plan.PROD.items():
        obj = plan.inspect(name)
        state = obj.get("State") or {}
        ensure(obj.get("Id") == ids[name] and
               obj.get("Config", {}).get("Image") == expected and
               state.get("Running") and
               (state.get("Health") or {}).get("Status") == "healthy",
               "PRODUCTION_CHANGED_" + name)


def resources():
    def ticks():
        values = Path("/proc/stat").read_text().splitlines()[0].split()
        ensure(values[0] == "cpu" and len(values) >= 9,
               "CPU_ACCOUNTING_UNAVAILABLE")
        parts = [int(x) for x in values[1:9]]
        return sum(parts), parts[3] + parts[4]
    def psi():
        line = next((x for x in Path("/proc/pressure/cpu").read_text().splitlines()
                     if x.startswith("some ")), "")
        match = re.search(r"avg10=([0-9.]+)", line)
        return float(match.group(1)) if match else None
    ensure(os.cpu_count() == 2, "CPU_TOPOLOGY_DRIFTED")
    before, p0 = ticks(), psi()
    time.sleep(10)
    after, p1 = ticks(), psi()
    ensure(after[0] > before[0] and p0 is not None and p1 is not None,
           "CPU_READINESS_SAMPLE_UNAVAILABLE")
    utilization = 100 * (1 - (after[1] - before[1]) / (after[0] - before[0]))
    mem = next((int(s.split()[1]) for s in
                Path("/proc/meminfo").read_text().splitlines()
                if s.startswith("MemAvailable:")), 0)
    print("M3_2_HOST_CPU_UTILIZATION=" + f"{utilization:.2f}%")
    print("M3_2_HOST_PSI_FIRST=" + f"{p0:.2f}")
    print("M3_2_HOST_PSI_LAST=" + f"{p1:.2f}")
    print("M3_2_RAM_AVAILABLE_MIB=" + str(mem // 1024))
    ensure(utilization < 75 and max(p0, p1) < 70 and mem >= 1048576,
           "M3_2_RESOURCE_GATE_NOT_READY")
    print("M3_2_RESOURCE_GATE=PASS")


def fsync_dir(parent):
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_lock():
    ensure(not LOCK_DIR.is_symlink(), "LOCK_DIR_SYMLINK")
    LOCK_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    st = LOCK_DIR.stat()
    ensure(st.st_uid == 0 and not (stat.S_IMODE(st.st_mode) & 0o077),
           "LOCK_DIR_PERMISSIONS_INVALID")
    return os.open(LOCK_DIR / "stage6.lock",
                   os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)


def clone_data(plan):
    ensure(not plan.TARGET_DATA.exists() and not plan.TARGET_DATA.is_symlink(),
           "NEW_DATA_DIR_ALREADY_EXISTS")
    tmp = Path(tempfile.mkdtemp(prefix=".unified-clone-", dir=plan.ROOT))
    try:
        for base, folders, files in os.walk(plan.SOURCE_DATA, followlinks=False):
            rel = Path(base).relative_to(plan.SOURCE_DATA)
            target = tmp / rel
            source_meta = Path(base).lstat()
            ensure(stat.S_ISDIR(source_meta.st_mode), "DATA_SOURCE_UNSAFE")
            os.chown(target, source_meta.st_uid, source_meta.st_gid)
            os.chmod(target, stat.S_IMODE(source_meta.st_mode))
            for name in folders:
                source = Path(base) / name
                ensure(stat.S_ISDIR(source.lstat().st_mode), "DATA_SYMLINK_UNSAFE")
                (target / name).mkdir(mode=0o700)
            for name in files:
                source = Path(base) / name
                info = source.lstat()
                ensure(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                       "DATA_HARDLINK_OR_SPECIAL_UNSAFE")
                destination = target / name
                shutil.copyfile(source, destination, follow_symlinks=False)
                os.chown(destination, info.st_uid, info.st_gid)
                os.chmod(destination, stat.S_IMODE(info.st_mode))
                ensure(hashlib.sha256(source.read_bytes()).digest() ==
                       hashlib.sha256(destination.read_bytes()).digest(),
                       "DATA_CLONE_SHA_MISMATCH")
                with destination.open("rb") as handle:
                    os.fsync(handle.fileno())
        fsync_dir(tmp)
        os.replace(tmp, plan.TARGET_DATA)
        fsync_dir(plan.ROOT)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)
    print("M3_2_ISOLATED_DATA_CLONE=PASS", flush=True)


def stage_compose(plan, raw):
    ensure(not COMPOSE_TARGET.exists() and not COMPOSE_TARGET.is_symlink(),
           "NEW_COMPOSE_ALREADY_EXISTS")
    fd = os.open(COMPOSE_TARGET,
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    fsync_dir(COMPOSE_TARGET.parent)
    ensure(plan.git_blob(COMPOSE_TARGET.read_bytes()) == plan.COMPOSE_BLOB,
           "NEW_COMPOSE_SHA_INVALID")
    print("M3_2_NEW_COMPOSE_STAGED=PASS", flush=True)


def maybe_container(plan):
    r = subprocess.run(
        ["docker", "container", "inspect", plan.NAME],
        capture_output=True, text=True, timeout=20
    )
    if r.returncode:
        return None
    objects = json.loads(r.stdout)
    ensure(len(objects) == 1, "CANARY_CONTAINER_INSPECT_INVALID")
    return objects[0]


def maybe_network(plan):
    r = subprocess.run(
        ["docker", "network", "inspect", plan.NETWORK],
        capture_output=True, text=True, timeout=20
    )
    if r.returncode:
        return None
    objects = json.loads(r.stdout)
    ensure(len(objects) == 1, "CANARY_NETWORK_INSPECT_INVALID")
    return objects[0]


def verify_runtime(plan, *, require_healthy=False):
    obj = maybe_container(plan)
    ensure(obj is not None, "UNIFIED_CANARY_MISSING")
    cfg = obj.get("Config") or {}
    labels = cfg.get("Labels") or {}
    ensure(cfg.get("Image") == plan.IMAGE and
           labels.get("com.docker.compose.project") == plan.PROJECT and
           labels.get("com.docker.compose.service") == "xtream-unified",
           "UNIFIED_CANARY_CONTAINER_IDENTITY_INVALID")
    host = obj.get("HostConfig") or {}
    ensure(host.get("NanoCpus") == 500000000 and
           host.get("Memory") == 268435456 and
           host.get("PidsLimit") == 64,
           "UNIFIED_CANARY_RESOURCE_LIMITS_INVALID")
    ensure(host.get("ReadonlyRootfs") is True and
           (host.get("RestartPolicy") or {}).get("Name") == "no" and
           not (host.get("PortBindings") or {}),
           "UNIFIED_CANARY_HOST_CONFIG_INVALID")
    ensure(not run(["docker", "port", plan.NAME]).strip(),
           "UNIFIED_CANARY_PUBLISHED_PORTS")
    networks = (obj.get("NetworkSettings") or {}).get("Networks") or {}
    ensure(set(networks) == {plan.NETWORK}, "UNIFIED_CANARY_EXTRA_NETWORK")
    ports = (obj.get("NetworkSettings") or {}).get("Ports") or {}
    ensure(all(bindings is None for bindings in ports.values()),
           "UNIFIED_CANARY_ACTIVE_PORT_MAPPING")
    net = maybe_network(plan)
    ensure(net is not None and net.get("Internal") is True,
           "UNIFIED_CANARY_NETWORK_NOT_INTERNAL")
    mounts = obj.get("Mounts") or []
    ensure(len(mounts) == 1 and
           mounts[0].get("Source") == str(plan.TARGET_DATA) and
           mounts[0].get("Destination") == "/data",
           "UNIFIED_CANARY_DATA_MOUNT_INVALID")
    state = obj.get("State") or {}
    ensure(state.get("Running"), "UNIFIED_CANARY_NOT_RUNNING")
    if require_healthy:
        ensure((state.get("Health") or {}).get("Status") == "healthy",
               "UNIFIED_CANARY_NOT_HEALTHY")
    return obj


def await_health(plan):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        obj = verify_runtime(plan)
        if (obj["State"].get("Health") or {}).get("Status") == "healthy":
            verify_runtime(plan, require_healthy=True)
            return
        time.sleep(3)
    raise ValueError("UNIFIED_CANARY_HEALTH_TIMEOUT")


SMOKE = r'''
import json, urllib.request, urllib.error
import app, route_paths, admin_auth

base = "http://127.0.0.1:8767"
def check(path, statuses=(200,)):
    try:
        with urllib.request.urlopen(base + path, timeout=8) as response:
            code, headers, body = response.status, response.headers, response.read(65000)
    except urllib.error.HTTPError as error:
        code, headers, body = error.code, error.headers, error.read(65000)
    assert code in statuses, (path, code)
    return headers, body

assert app.LEGACY_SYNC_ENABLED is False
assert app.PUBLIC == "https://olivergiangvu.asuscomm.com:18450/canary"
assert route_paths.ADMIN_PATH == "/canary/admin/"
assert admin_auth.COOKIE == "xtream_canary_admin_session"
_, body = check("/live")
assert json.loads(body)["status"] == "ok"
check("/ready")
check("/health")
_, body = check("/")
assert b'id="personalWorkspace"' in body
assert b'id="adminWorkspace"' in body
headers, body = check("/gateway/")
assert b'action="/canary/admin-signin/"' in body
assert "Path=/canary/admin-signin/" in headers.get("Set-Cookie", "")
assert headers.get("Referrer-Policy") == "same-origin"
check("/assets/app.js")
check("/api/auth/gate-check", (401,))
check("/api/system/users", (401,))
check("/a/invalid/manifest.json", (400, 401, 403, 404))
'''


def verify_smoke(plan):
    run(["docker", "exec", "-i", plan.NAME, "python", "-"],
        stdin=SMOKE, timeout=70)
    print("M3_2_UNIFIED_ADMIN_PLAYBACK_AUTH_SMOKE=PASS", flush=True)


def rollback(plan, original_ids, *, compose_created):
    print("M3_2_ROLLBACK_STARTED=YES", flush=True)
    errors = []
    try:
        candidate = maybe_container(plan)
        if candidate is not None:
            labels = candidate.get("Config", {}).get("Labels") or {}
            ensure(candidate["Config"]["Image"] == plan.IMAGE and
                   labels.get("com.docker.compose.project") == plan.PROJECT and
                   labels.get("com.docker.compose.service") == "xtream-unified",
                   "ROLLBACK_REFUSES_UNOWNED_CONTAINER")
            if candidate.get("State", {}).get("Running"):
                run(["docker", "stop", "-t", "10", plan.NAME], timeout=35)
            run(["docker", "rm", plan.NAME], timeout=30)
        ensure(maybe_container(plan) is None, "ROLLBACK_CONTAINER_REMAINS")
        print("M3_2_ROLLBACK_UNIFIED_CONTAINER=ABSENT", flush=True)
    except Exception:
        errors.append("ROLLBACK_CONTAINER_FAILED")
    try:
        network = maybe_network(plan)
        if network is not None:
            ensure(network.get("Internal") is True and
                   not (network.get("Containers") or {}),
                   "ROLLBACK_REFUSES_SHARED_NETWORK")
            run(["docker", "network", "rm", plan.NETWORK])
        ensure(maybe_network(plan) is None, "ROLLBACK_NETWORK_REMAINS")
        print("M3_2_ROLLBACK_PRIVATE_NETWORK=ABSENT", flush=True)
    except Exception:
        errors.append("ROLLBACK_NETWORK_FAILED")
    try:
        if compose_created and COMPOSE_TARGET.exists():
            ensure(not COMPOSE_TARGET.is_symlink() and
                   plan.git_blob(COMPOSE_TARGET.read_bytes()) == plan.COMPOSE_BLOB,
                   "ROLLBACK_REFUSES_MODIFIED_COMPOSE")
            COMPOSE_TARGET.unlink()
            fsync_dir(COMPOSE_TARGET.parent)
        print("M3_2_ROLLBACK_NEW_COMPOSE=VERIFIED", flush=True)
    except Exception:
        errors.append("ROLLBACK_COMPOSE_FAILED")
    try:
        prod_unchanged(plan, original_ids)
        for name in plan.OLD:
            ensure(not plan.inspect(name)["State"]["Running"],
                   "OLD_CANARY_RESTARTED_UNEXPECTEDLY")
        plan.check_protected()
        print("M3_2_ROLLBACK_PRODUCTION_AND_LEGACY=UNCHANGED", flush=True)
    except Exception:
        errors.append("ROLLBACK_PRODUCTION_VERIFICATION_FAILED")
    # The isolated test snapshot may contain data written during initialisation.
    # Preserve it; never delete it under an automatic rollback handler.
    print("M3_2_ISOLATED_TEST_DATA_RETAINED=YES", flush=True)
    if errors:
        print("CRITICAL_M3_2_ROLLBACK_VERIFIED=NO", flush=True)
        print("ROLLBACK_FAILURE_CODES=" + ",".join(errors), flush=True)
        return False
    print("M3_2_ROLLBACK_VERIFIED=YES", flush=True)
    return True


def signal_interrupt(signum, _frame):
    raise InterruptedError("M3_2_INTERRUPT_" + str(signum))


def apply(plan, folder):
    fd = private_lock()
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        ids, raw, size = baseline(plan, folder)
        resources()
        new_ids, new_raw, new_size = baseline(plan, folder)
        ensure(ids == new_ids and raw == new_raw and size == new_size,
               "BASELINE_CHANGED_DURING_RESOURCE_GATE")

        signal_handlers = {sig: signal.getsignal(sig) for sig
                           in (signal.SIGINT, signal.SIGTERM)}
        for sig in signal_handlers:
            signal.signal(sig, signal_interrupt)

        changed = False
        compose_created = False
        try:
            changed = True
            clone_data(plan)
            # Set flag before file creation to handle a partial write safely.
            compose_created = True
            stage_compose(plan, raw)
            ensure(plan.effective(COMPOSE_TARGET) == plan.effective(
                folder / "unified-compose.yaml"), "STAGED_COMPOSE_DRIFTED")
            environment = os.environ.copy()
            environment.update(
                CANARY_DIR=str(plan.ROOT), CANARY_UNIFIED_IMAGE=plan.IMAGE
            )
            run([
                "docker", "compose", "-p", plan.PROJECT,
                "--project-directory", str(plan.ROOT),
                "-f", str(COMPOSE_TARGET), "up", "-d",
                "--no-deps", "--no-build", "--pull", "never", "xtream-unified"
            ], env=environment, timeout=120)
            await_health(plan)
            print("M3_2_UNIFIED_HEALTH=PASS", flush=True)
            verify_smoke(plan)
            verify_runtime(plan, require_healthy=True)
            prod_unchanged(plan, ids)
            for name in plan.OLD:
                ensure(not plan.inspect(name)["State"]["Running"],
                       "LEGACY_CANARY_RESTARTED")
            plan.check_protected()
            print("M3_2_PRODUCTION_IDENTITIES_AND_HEALTH=UNCHANGED", flush=True)
            print("M3_2_PRIVATE_NETWORK_ZERO_PORTS_RESOURCE_CAPS=PASS", flush=True)
            print("M3_2_ONE_CANARY_APPLY=PASS", flush=True)
            print("NGINX_FIREWALL_OLD_COMPOSE_CHANGED=NONE", flush=True)
            print("NEXT=M4_METRICS_AND_SECURITY_RELEASE_GATE", flush=True)
        except BaseException:
            if changed and not rollback(plan, ids, compose_created=compose_created):
                print("CRITICAL_DO_NOT_RETRY_UNTIL_MANUAL_REVIEW", flush=True)
            raise
        finally:
            for sig, old in signal_handlers.items():
                signal.signal(sig, old)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--approved-image", default="")
    parser.add_argument("--approved-action", default="")
    args = parser.parse_args()
    ensure(os.geteuid() == 0, "REQUIRES_SUDO")
    if args.apply:
        ensure(args.approved_image == CANARY_IMAGE and
               args.approved_action == APPROVAL,
               "EXPLICIT_UNIFIED_CANARY_START_APPROVAL_REQUIRED")
    with tempfile.TemporaryDirectory(prefix="xtream-m3-2-plan-") as directory:
        folder = Path(directory)
        folder.chmod(0o700)
        plan = pinned_plan(folder)
        ids, raw, _size = baseline(plan, folder)
        print("M3_2_IMMUTABLE_COMPOSE_AND_IMAGE=PASS")
        print("M3_2_TARGET_ONE_PRIVATE_CANARY_ONLY=PASS")
        if args.apply:
            apply(plan, folder)
        else:
            prod_unchanged(plan, ids)
            print("M3_2_MODE=PLAN_ONLY")
            print("HOST_CONFIG_AND_CONTAINERS_CHANGED=NONE")
            print("START_APPROVAL=NO")
            print("NEXT=REQUEST_SEPARATE_APPLY_APPROVAL")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError, subprocess.TimeoutExpired,
            InterruptedError, KeyboardInterrupt) as exc:
        print("STOP: M3.2 unified start: " + str(exc))
        raise SystemExit(1) from None
