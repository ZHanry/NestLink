#!/usr/bin/env python3
"""Record the GitHub-built synthetic direction executable; never build or run it."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

SOURCES = (
    "Cargo.lock",
    "rust-toolchain.toml",
    "docs/refactor/native-codecs.lock.json",
    "crates/media-codec/Cargo.toml",
    "crates/media-codec/build.rs",
    "crates/media-codec/src/lib.rs",
    "crates/media-codec/src/h264.rs",
    "crates/media-codec/src/video.rs",
    "crates/media-codec/src/windows_mf.cpp",
    "crates/media-codec/src/windows_mf.rs",
    "crates/media-codec/src/windows_gpu_presenter.cpp",
    "crates/media-codec/src/windows_gpu_presenter.rs",
    "crates/media-codec/src/owner_observation.h",
    "crates/media-codec/src/owner_observation.rs",
    "crates/media-codec/src/controller_probe.rs",
    "crates/media-codec/examples/windows-controller-direction-probe.rs",
    "scripts/refactor-windows-normal-user.py",
    "scripts/refactor-controller-direction-artifact.py",
    ".github/workflows/rust-core.yml",
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Windows":
        raise SystemExit("This manifest writer requires the Windows GitHub runner")
    if os.environ.get("GITHUB_REPOSITORY") != "ZHanry/NestLink":
        raise SystemExit("Unexpected repository")
    source = os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise SystemExit("Full source revision required")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != source:
        raise SystemExit("Direction diagnostic source differs from the workflow")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]*", os.environ[name]):
            raise SystemExit("Invalid run identity")
    if subprocess.check_output(["git", "status", "--porcelain"]).strip():
        raise SystemExit("Diagnostic checkout is dirty")
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", *SOURCES], check=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR") or "target")
    if os.environ.get("CARGO_BUILD_TARGET"):
        target /= os.environ["CARGO_BUILD_TARGET"]
    executable = target / "release/examples/windows-controller-direction-probe.exe"
    output = Path(os.environ["RUNNER_TEMP"]) / "nestlink-controller-direction-target-probe"
    output.mkdir()
    copied = output / executable.name
    shutil.copyfile(executable, copied)
    manifest = {
        "schema": 1,
        "source_revision": source,
        "repository": os.environ["GITHUB_REPOSITORY"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "workflow": os.environ["GITHUB_WORKFLOW"],
        "purpose": "owned-synthetic-controller-direction-target-probe-only",
        "filename": copied.name,
        "bytes": copied.stat().st_size,
        "sha256": sha(copied),
        "build_profile": "release",
        "build_command": "cargo build --locked --release -p nestlink-media-codec --example windows-controller-direction-probe",
        "build_identity": "verified-medium-non-admin-token",
        "executed_on_github": False,
        "target_validation": "pending-authorized-target-execution",
        "product_negotiation_enabled": False,
        "physical_capture": False,
        "scanout_verified": False,
        "performance_qualified": False,
        "source_files": [{"path": name, "sha256": sha(Path(name))} for name in SOURCES],
    }
    (output / "controller-probe-build.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
