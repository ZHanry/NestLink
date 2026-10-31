#!/usr/bin/env python3
"""Qualify the existing unsigned Linux headless DEB on a hosted native runner.

This uses the same DEB builder as the complete candidate cohort. It does not
create a cohort or sign/promote a package. OS networking remains an explicit
ordinary-user owner plus separate root plan operation after installation.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_network_candidate", ROOT / "scripts/refactor-candidate-producer.py")
PRODUCER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PRODUCER)
PACKAGE = "nestlink-rc-network"
INSTALLED = Path("/opt/nestlink-rc/network/nestlink-daemon")
COMMANDS = ("network-tun", "network-tun-system", "network-subnet", "network-subnet-system",
            "network-lan", "space-dns", "space-dns-system", "wireguard",
            "private-service-proxy", "private-web-gateway", "maintenance", "diagnostics")


def sha(path):
    return PRODUCER.digest(path)


def qualify(args):
    if platform.system() != "Linux" or os.geteuid() == 0 or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("native hosted Linux with an ordinary test UID is required")
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    target = "x86_64-unknown-linux-gnu" if architecture == "amd64" else "aarch64-unknown-linux-gnu"
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if source != os.environ["GITHUB_SHA"] or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT).strip():
        raise ValueError("qualification requires the exact clean workflow SHA")
    args.output.mkdir(parents=True, exist_ok=False)
    version = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    receipt = {
        "schema_version": 1, "source_revision": source, "version": version,
        "build_provenance": {"workflow": os.environ["GITHUB_WORKFLOW_REF"],
                             "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
                             "target": target, "cargo_lock_sha256": sha(ROOT / "Cargo.lock"),
                             "binary_sha256": sha(args.binary)},
        "execution_provenance": {"runner_environment": os.environ["RUNNER_ENVIRONMENT"],
                                 "machine": platform.machine(), "ordinary_uid": os.geteuid(),
                                 "kernel": platform.release()},
        "status": "failed", "commands": [], "production_update_eligible": False,
        "limitations": ["Unsigned development package; no installed signed update or formal lifecycle claim",
                        "CLI admission/refusal and actual DEB install/reinstall/uninstall only; physical TUN, subnet, DNS and WireGuard have separate experiments",
                        "No graphical Linux desktop, phone or physical ARM64 target acceptance"],
    }

    def command(name, argv, success=True):
        result = subprocess.run([str(value) for value in argv], cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120, check=False)
        path = args.output / (name + ".log")
        path.write_bytes(result.stdout)
        receipt["commands"].append({"name": name, "return_code": result.returncode,
                                    "log": path.name, "log_sha256": sha(path)})
        if (result.returncode == 0) != success:
            raise ValueError("unexpected qualification command result: " + name)
        return result.stdout

    installed = False
    try:
        if INSTALLED.exists() or subprocess.run(["dpkg-query", "--status", PACKAGE], stdout=subprocess.DEVNULL,
                                               stderr=subprocess.DEVNULL, check=False).returncode == 0:
            raise ValueError("runner already contains this isolated candidate package")
        PRODUCER.TOOLS.elf(args.binary, 183 if architecture == "arm64" else 62)
        with tempfile.TemporaryDirectory(prefix="nestlink-network-payload-") as temporary:
            directory = Path(temporary)
            PRODUCER.copy_fixed(args.binary, directory / "nestlink-daemon")
            package = args.output / ("NestLink-candidate-linux-" + architecture + "-network.deb")
            PRODUCER.deb_candidate(directory, package, "network", architecture,
                                   {"source_revision": source, "version": version, "sequence": 1})
        receipt["package"] = {"path": package.name, "bytes": package.stat().st_size, "sha256": sha(package)}
        command("ordinary-install-refused", ["dpkg", "--install", package], success=False)
        if INSTALLED.exists():
            raise ValueError("ordinary installation unexpectedly wrote product files")
        # Mark cleanup ownership before dpkg starts: an interrupted unpack must
        # also be removed. The pre-existing-package check above protects peers.
        installed = True
        command("install", ["sudo", "-n", "dpkg", "--install", package])
        if sha(INSTALLED) != receipt["build_provenance"]["binary_sha256"]:
            raise ValueError("installed daemon is not the exact hosted build")
        command("version", [INSTALLED, "--version"])
        for name in COMMANDS:
            command("help-" + name, [INSTALLED, name, "--help"])
        with tempfile.TemporaryDirectory(prefix="nestlink-network-user-state-") as temporary:
            state = Path(temporary)
            sentinel = state / "retained-data"
            sentinel.write_bytes(os.urandom(64))
            expected = sha(sentinel)
            dns = [INSTALLED, "space-dns", "--state-dir", state, "--space", "00000000-0000-4000-8000-000000000001"]
            command("missing-login-refused", dns, success=False)
            command("root-runtime-refused", ["sudo", "-n", *dns], success=False)
            command("reinstall", ["sudo", "-n", "dpkg", "--install", package])
            if sha(INSTALLED) != receipt["build_provenance"]["binary_sha256"] or sha(sentinel) != expected:
                raise ValueError("reinstall changed the accepted binary or user data")
            command("uninstall", ["sudo", "-n", "dpkg", "--remove", PACKAGE])
            installed = False
            if INSTALLED.exists() or sha(sentinel) != expected:
                raise ValueError("uninstall left executable bytes or changed retained user data")
        receipt["status"] = "passed"
    finally:
        if installed:
            try:
                command("failed-install-cleanup", ["sudo", "-n", "dpkg", "--remove", PACKAGE])
            except (OSError, ValueError, subprocess.SubprocessError):
                receipt["cleanup_failed"] = True
        receipt["files"] = [{"path": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
                            for path in sorted(args.output.iterdir()) if path.is_file()]
        (args.output / "linux-network-package.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"source_revision": source, "architecture": architecture, "status": receipt["status"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    qualify(parser.parse_args())


if __name__ == "__main__":
    main()
