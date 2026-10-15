#!/usr/bin/env python3
"""M3.4: image-only, offline permission fix for non-root Unified runtime.

Reuses the original immutable M3 sources. Changes NO application Python bytes.
Adds only an explicit COPY --chmod=0644 and readable Python source modes.
Plan is default; build requires an exact new-image approval. Does NOT create
containers, modify Compose/nginx, or overwrite the original Canary image.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.request import ProxyHandler, Request, build_opener

PIN_REF = "0e0de3b39a35fcb87c8f8ae39fc8a5f6d9ca4e60"
PIN_BLOB = "a22b4afd24c83440ea90bd9a2f212a2e260a4f12"
PIN_PATH = "canary/stage6_unified_image_build.py"
NEW_IMAGE = "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd-permfix1"
OLD_IMAGE = "homedocker/xtream-vod-unified-canary:0.6.0-cab39cd806cd"
OLD_COPY = "COPY unified_app.py admin_ui.py /srv/"
NEW_COPY = "COPY --chmod=0644 unified_app.py admin_ui.py /srv/"


def require(value, code):
    if not value:
        raise RuntimeError(code)


def git_blob(raw):
    return hashlib.sha1(
        b"blob " + str(len(raw)).encode() + b"\x00" + raw
    ).hexdigest()


def original_builder(folder):
    url = ("https://raw.githubusercontent.com/olivergiangvu/xtream-vod-bridge/"
           + PIN_REF + "/" + PIN_PATH)
    opener = build_opener(ProxyHandler({}))
    with opener.open(Request(url), timeout=30) as response:
        raw = response.read(160000)
    require(git_blob(raw) == PIN_BLOB, "PINNED_OLD_BUILDER_INTEGRITY_FAILURE")
    script = folder / "stage6_unified_image_build.py"
    script.write_bytes(raw)
    spec = importlib.util.spec_from_file_location("_pinned_original_m3", script)
    require(spec is not None and spec.loader is not None, "PINNED_BUILDER_IMPORT_FAILED")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    print("M3_4_ORIGINAL_BUILDER_PIN=VERIFIED", flush=True)
    return module


def new_image_absent():
    result = subprocess.run(
        ["docker", "image", "inspect", NEW_IMAGE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
    )
    require(result.returncode != 0, "REFUSE_TO_OVERWRITE_EXISTING_NEW_IMAGE")


def fix_dockerfile(folder, original):
    dockerfile = folder / "Dockerfile"
    source = dockerfile.read_text(encoding="utf-8")
    require(source.count(OLD_COPY) == 1, "ORIGINAL_COPY_NOT_UNIQUE")
    require(NEW_COPY not in source, "UNEXPECTED_ALREADY_MODIFIED_DOCKERFILE")
    revised = source.replace(OLD_COPY, NEW_COPY, 1)
    require(revised.replace(NEW_COPY, OLD_COPY, 1) == source,
            "DOCKERFILE_UNEXPECTED_MUTATION")
    dockerfile.write_text(revised, encoding="utf-8")
    for name in ("unified_app.py", "admin_ui.py"):
        path = folder / name
        require(original.git_blob(path.read_bytes()) == original.SOURCES[name],
                "APP_SOURCE_BYTES_CHANGED_" + name)
        path.chmod(0o644)
        require((path.stat().st_mode & 0o777) == 0o644,
                "APP_SOURCE_READ_MODE_INCORRECT")
    df = dockerfile.read_text(encoding="utf-8")
    require("FROM " + original.BASE_IMAGE in df, "BASE_IMAGE_DRIFT")
    require(df.count(NEW_COPY) == 1, "CHMOD_COPY_MISSING")
    require("RUN " not in df and "\nADD " not in df,
            "UNAPPROVED_DOCKERFILE_COMMAND")
    print("M3_4_SOURCE_BYTES=UNCHANGED", flush=True)
    print("M3_4_PYTHON_SOURCE_CONTEXT_MODE=0644", flush=True)
    print("M3_4_DOCKER_COPY_MODE=0644", flush=True)
    print("M3_4_ONLY_DOCKERFILE_CHANGE=COPY_CHMOD", flush=True)


def image_metadata(original):
    p = subprocess.run(
        ["docker", "image", "inspect", OLD_IMAGE],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, timeout=20
    )
    require(p.returncode == 0, "OLD_IMAGE_MISSING")
    image = json.loads(p.stdout)
    require(len(image) == 1, "OLD_IMAGE_INVALID")
    config = image[0].get("Config") or {}
    require(config.get("User") == "10001:10001", "OLD_IMAGE_USER_DRIFT")
    require("unified_app:application" in (config.get("Cmd") or []),
            "OLD_IMAGE_CMD_DRIFT")
    require(original.BASE_IMAGE != NEW_IMAGE and OLD_IMAGE != NEW_IMAGE,
            "IMAGE_TAG_COLLISION")
    print("M3_4_OLD_IMAGE_RETAINED=YES", flush=True)


def build_image(original, folder, ids):
    original.build_gate()
    require(original.verify_host() == ids, "PRODUCTION_DRIFT_DURING_RESOURCE_GATE")
    new_image_absent()
    p = subprocess.run(
        ["docker", "build", "--network", "none", "--pull=false",
         "--progress", "quiet", "-t", NEW_IMAGE, str(folder)],
        capture_output=True, text=True, timeout=180
    )
    require(p.returncode == 0, "OFFLINE_PERMISSION_FIXED_IMAGE_BUILD_FAILED")
    result = subprocess.run(
        ["docker", "image", "inspect", NEW_IMAGE],
        capture_output=True, text=True, timeout=25
    )
    require(result.returncode == 0, "NEW_IMAGE_UNAVAILABLE")
    cfg = json.loads(result.stdout)[0].get("Config") or {}
    require(cfg.get("User") == "10001:10001", "NEW_IMAGE_USER_DRIFT")
    require("unified_app:application" in (cfg.get("Cmd") or []),
            "NEW_IMAGE_COMMAND_DRIFT")
    require(original.verify_host() == ids, "PRODUCTION_DRIFT_AFTER_BUILD")
    print("M3_4_OFFLINE_IMAGE_BUILD=PASS", flush=True)
    print("M3_4_NEW_IMAGE=" + NEW_IMAGE, flush=True)
    print("M3_4_ORIGINAL_IMAGE_UNMODIFIED=YES", flush=True)
    print("M3_4_LIVE_CONTAINERS_COMPOSE_NGINX_CHANGED=NONE", flush=True)
    print("NEXT=SEPARATE_ONE_CONTAINER_STARTUP_DIAGNOSTIC_APPROVAL")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--approval", default="")
    args = parser.parse_args()
    require(os.geteuid() == 0, "SUDO_REQUIRED")
    require(not args.build or args.approval == NEW_IMAGE,
            "EXPLICIT_NEW_IMAGE_BUILD_APPROVAL_REQUIRED")
    new_image_absent()
    with tempfile.TemporaryDirectory(prefix="xtream-unified-permfix-") as temp:
        folder = Path(temp)
        folder.chmod(0o700)
        orig = original_builder(folder)
        ids = orig.verify_host()
        image_metadata(orig)
        orig.verify_sources(folder)
        fix_dockerfile(folder, orig)
        print("M3_4_NEW_TAG=" + NEW_IMAGE, flush=True)
        if args.build:
            build_image(orig, folder, ids)
        else:
            require(orig.verify_host() == ids,
                    "PRODUCTION_DRIFT_DURING_PLAN")
            print("M3_4_MODE=PLAN_ONLY", flush=True)
            print("M3_4_HOST_AND_IMAGES_CHANGED=NONE", flush=True)
            print("M3_4_NEW_IMAGE_BUILD_APPROVAL=NO", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Any source/OS exception message might contain private paths or URL.
        print("STOP_M3_4=" + type(exc).__name__, flush=True)
        raise SystemExit(1) from None
