#!/usr/bin/env python3
"""Actions-only L0/L1 checks, exact-source receipts and reviewable rustfmt patches.

This does not run L2 network experiments or qualify a target device or release.
Environment guards prevent accidental local execution; they are not a remote
attestation protocol. GitHub's run/job/artifact records remain authoritative.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import Mapping


REPOSITORY = "ZHanry/NestLink"
WORKFLOW_PATH = ".github/workflows/network-rewrite.yml"
PACKAGES = (
    "nestlink-protocol", "nestlink-identity", "nestlink-policy", "nestlink-connectivity",
    "nestlink-storage", "nestlink-transport-stream", "nestlink-transport-quic",
    "nestlink-transport-wss", "nestlink-remote", "nestlink-server",
)
REQUIRED_COMMANDS = {
    "rust-toolchain", "format-check", "contract-clippy", "contract-tests", "ci-evidence-tests",
}
COMMAND_TIMEOUT_SECONDS = 1200


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_actions_environment(environment: Mapping[str, str]) -> dict:
    if environment.get("GITHUB_ACTIONS") != "true":
        raise ValueError("R02: these project checks may run only in GitHub Actions")
    if environment.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("R02: a GitHub-hosted runner is required; self-hosted is refused")
    if environment.get("GITHUB_REPOSITORY") != REPOSITORY:
        raise ValueError("unexpected network contract repository")
    for key in ("GITHUB_SHA", "GITHUB_WORKFLOW_SHA"):
        if re.fullmatch(r"[0-9a-f]{40}", environment.get(key, "")) is None:
            raise ValueError("missing exact source/workflow SHA: " + key)
    workflow_ref = environment.get("GITHUB_WORKFLOW_REF", "")
    if not workflow_ref.startswith(REPOSITORY + "/" + WORKFLOW_PATH + "@refs/"):
        raise ValueError("unexpected network contract workflow reference")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if re.fullmatch(r"[1-9][0-9]*", environment.get(key, "")) is None:
            raise ValueError("missing numeric Actions identity: " + key)
    for key in ("GITHUB_JOB", "GITHUB_WORKFLOW", "RUNNER_NAME", "RUNNER_ARCH"):
        value = environment.get(key, "")
        if not value or len(value) > 256 or any(ord(char) < 32 for char in value):
            raise ValueError("missing or invalid Actions identity: " + key)
    if environment.get("RUNNER_OS") not in ("Linux", "Windows"):
        raise ValueError("network contract job supports only Linux or Windows")
    return {
        "repository": environment["GITHUB_REPOSITORY"],
        "source_revision": environment["GITHUB_SHA"],
        "workflow": environment["GITHUB_WORKFLOW"],
        "workflow_path": WORKFLOW_PATH,
        "workflow_ref": workflow_ref,
        "workflow_sha": environment["GITHUB_WORKFLOW_SHA"],
        "job": environment["GITHUB_JOB"],
        "run_id": environment["GITHUB_RUN_ID"],
        "run_attempt": environment["GITHUB_RUN_ATTEMPT"],
        "run_url": "https://github.com/" + REPOSITORY + "/actions/runs/" + environment["GITHUB_RUN_ID"],
        "runner": {
            "environment": environment["RUNNER_ENVIRONMENT"],
            "name": environment["RUNNER_NAME"],
            "os": environment["RUNNER_OS"],
            "architecture": environment["RUNNER_ARCH"],
        },
    }


def validate_output_path(output: Path, source: Path, runner_temp: Path) -> Path:
    if not output.is_absolute() or not runner_temp.is_absolute():
        raise ValueError("evidence and runner temporary paths must be absolute")
    resolved = output.resolve()
    source = source.resolve()
    runner_temp = runner_temp.resolve()
    if resolved == source or resolved.is_relative_to(source):
        raise ValueError("validation evidence must remain outside the source tree")
    if resolved == runner_temp or not resolved.is_relative_to(runner_temp):
        raise ValueError("validation evidence must be an owned child of RUNNER_TEMP")
    if resolved.exists():
        raise ValueError("refusing to overwrite an existing evidence directory")
    return resolved


def git_bytes(source: Path, *arguments: str) -> bytes:
    return subprocess.check_output(
        ["git", "--no-pager", *arguments], cwd=source, stderr=subprocess.PIPE, timeout=60,
    )


def source_snapshot(source: Path, expected_sha: str) -> dict:
    actual = git_bytes(source, "rev-parse", "HEAD").decode("ascii").strip()
    status = git_bytes(source, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    lock = source / "Cargo.lock"
    return {
        "expected_revision": expected_sha,
        "source_revision": actual,
        "exact_source": actual == expected_sha,
        "clean": not status,
        "status_raw_sha256": hashlib.sha256(status).hexdigest(),
        "status_raw_bytes": len(status),
        "status": status.decode("utf-8", errors="replace").split("\0")[:-1],
        "dependency_lock_sha256": sha256_file(lock),
    }


def require_unchanged_source(before: dict, after: dict) -> None:
    if not before["exact_source"] or not before["clean"]:
        raise ValueError("source checkout must be clean and match GITHUB_SHA before checks")
    if not after["exact_source"] or not after["clean"]:
        raise ValueError("checks changed the source checkout; original changes are retained")
    if after["dependency_lock_sha256"] != before["dependency_lock_sha256"]:
        raise ValueError("checks changed Cargo.lock; locked dependency evidence differs")


def stop_process_tree(process: subprocess.Popen, log) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=log, stderr=subprocess.STDOUT, check=False, timeout=30,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=30)


def run_command(name: str, arguments: list[str], source: Path, output: Path,
                records: list[dict], timeout: int = COMMAND_TIMEOUT_SECONDS) -> dict:
    log_path = output / (name + ".log")
    record = {
        "name": name, "argv": arguments, "started_at": utc_now(),
        "timeout_seconds": timeout, "log": log_path.name,
        "return_code": None, "timed_out": False,
    }
    records.append(record)
    started = time.monotonic()
    try:
        with log_path.open("wb") as log:
            log.write((json.dumps({"argv": arguments, "started_at": record["started_at"]}) + "\n").encode())
            log.flush()
            try:
                process = subprocess.Popen(
                    arguments, cwd=source, stdout=log, stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL, start_new_session=os.name != "nt",
                )
                try:
                    record["return_code"] = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    record["timed_out"] = True
                    record["return_code"] = 124
                    stop_process_tree(process, log)
            except OSError as error:
                record["return_code"] = 127
                record["error"] = type(error).__name__ + ": " + str(error)
                log.write((record["error"] + "\n").encode("utf-8", errors="replace"))
    finally:
        record["finished_at"] = utc_now()
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if log_path.is_file():
            record["log_bytes"] = log_path.stat().st_size
            record["log_sha256"] = sha256_file(log_path)
            with log_path.open("rb") as log:
                log.seek(max(0, record["log_bytes"] - 16 * 1024))
                print(log.read().decode("utf-8", errors="replace"), flush=True)
        print(json.dumps(record, sort_keys=True), flush=True)
    return record


def formatting_patch(source: Path, output: Path, records: list[dict]) -> bool:
    # cargo fmt mutates only an isolated, detached Git worktree. The checked
    # source remains untouched, and both changed-file inventory and patch survive.
    worktree = output / "format-source"
    add = run_command("format-worktree-create", ["git", "worktree", "add", "--detach", str(worktree), "HEAD"], source, output, records, 120)
    if add["return_code"] != 0:
        return False
    succeeded = False
    try:
        formatted = run_command("format-patch-generate", ["cargo", "fmt", "--all"], worktree, output, records, 300)
        status = git_bytes(worktree, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        (output / "format-worktree-status.json").write_text(
            json.dumps({"status": status.decode("utf-8", errors="replace").split("\0")[:-1]}, indent=2) + "\n", encoding="utf-8",
        )
        names = git_bytes(worktree, "diff", "--name-only", "-z", "HEAD").decode("utf-8").split("\0")[:-1]
        untracked = git_bytes(worktree, "ls-files", "--others", "--exclude-standard", "-z")
        patch = git_bytes(worktree, "diff", "--no-ext-diff", "--binary", "HEAD")
        (output / "rustfmt.patch").write_bytes(patch)
        succeeded = formatted["return_code"] == 0 and not untracked and all(name.endswith(".rs") for name in names)
        if not succeeded:
            (output / "format-patch-error.txt").write_text(
                "Formatter failed or changed unexpected source paths. Inspect the retained log, status and patch.\n", encoding="utf-8",
            )
    finally:
        cleanup = run_command("format-worktree-remove", ["git", "worktree", "remove", "--force", str(worktree)], source, output, records, 120)
        succeeded = succeeded and cleanup["return_code"] == 0
    return succeeded


def artifact_files(output: Path) -> list[dict]:
    files = []
    for path in sorted(output.rglob("*")):
        if path.is_symlink():
            raise ValueError("evidence cannot contain symbolic links")
        if path.is_file():
            if path == output / "network-rewrite-evidence.json":
                continue  # A receipt cannot recursively hash itself.
            files.append({
                "path": path.relative_to(output).as_posix(),
                "bytes": path.stat().st_size, "sha256": sha256_file(path),
            })
    return files


def evidence_receipt(identity: dict, before: dict | None, after: dict | None,
                     commands: list[dict], files: list[dict], failure: str | None) -> dict:
    required = REQUIRED_COMMANDS.copy()
    if identity["runner"]["os"] == "Windows":
        required.add("ordinary-windows-token")
    success = (
        failure is None and before is not None and after is not None
        and before.get("exact_source") is True and before.get("clean") is True
        and after.get("exact_source") is True and after.get("clean") is True
        and before.get("dependency_lock_sha256") == after.get("dependency_lock_sha256")
        and required <= {command["name"] for command in commands}
        and all(command["return_code"] == 0 for command in commands)
    )
    return {
        "schema_version": 1,
        "kind": "nestlink-network-rewrite-contract-checks",
        "recorded_at": utc_now(), "timezone": "Asia/Shanghai",
        "status": "passed_l0_l1" if success else "failed",
        "evidence_levels": ["L0", "L1"],
        "acceptance_claims": [],
        "failure": failure,
        "source_before": before, "source_after": after,
        "commands": commands,
        "build_provenance": {
            **identity,
            "dependency_lock_sha256": before["dependency_lock_sha256"] if before else None,
            "artifact_kind": "validation-logs-and-formatter-patch",
            "artifact_files": files,
            "receipt_digest_source": "GitHub Actions upload-artifact digest; self-hash excluded",
        },
        "execution_provenance": {
            "kind": "github_actions", **identity,
            "executed_commands": [command["name"] for command in commands],
            "target_device_acceptance": False,
            "l2_network_experiment": False,
        },
        "limitations": [
            "L0/L1 contract and CI receipt checks only; AC04 production-socket fault experiments have not run here.",
            "No target GPU, phone, physical NAT, TUN, public HA, game or cross-day acceptance is claimed.",
            "A formatting patch is review material; failing source is not replaced or counted as passing.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    identity = validate_actions_environment(os.environ)
    source = Path(__file__).resolve().parent.parent
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve()
    if source != workspace:
        raise ValueError("script source must match the Actions checkout workspace")
    actual_os = "Windows" if sys.platform == "win32" else "Linux" if sys.platform.startswith("linux") else None
    if identity["runner"]["os"] != actual_os:
        raise ValueError("runner OS identity differs from the executing host")
    output = validate_output_path(arguments.output, source, Path(os.environ.get("RUNNER_TEMP", "")))
    output.mkdir()
    records: list[dict] = []
    before = after = None
    failure = None
    try:
        before = source_snapshot(source, identity["source_revision"])
        require_unchanged_source(before, before)
        prefix = []
        if actual_os == "Windows":
            prefix = [sys.executable, "-B", "scripts/refactor-windows-normal-user.py"]
            run_command("ordinary-windows-token", prefix + [sys.executable, "-B", "scripts/refactor-windows-normal-user.py", "--check"], source, output, records, 60)
        run_command("rust-toolchain", ["rustc", "--version", "--verbose"], source, output, records, 60)
        fmt = run_command("format-check", ["cargo", "fmt", "--all", "--", "--check"], source, output, records, 300)
        require_unchanged_source(before, source_snapshot(source, identity["source_revision"]))
        if fmt["return_code"] != 0:
            if not formatting_patch(source, output, records):
                failure = "formatter patch generation or owned worktree cleanup failed"
        else:
            (output / "rustfmt.patch").write_bytes(b"")
        package_arguments = [argument for package in PACKAGES for argument in ("-p", package)]
        commands = [
            ("contract-clippy", ["cargo", "clippy", "--all-targets", "--locked", "--keep-going", *package_arguments, "--", "-D", "warnings"]),
            ("contract-tests", prefix + ["cargo", "test", "--locked", "--lib", "--tests", "--no-fail-fast", *package_arguments]),
            ("ci-evidence-tests", prefix + [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/network", "-p", "test_*.py", "-v"]),
        ]
        for name, command in commands:
            run_command(name, command, source, output, records)
            require_unchanged_source(before, source_snapshot(source, identity["source_revision"]))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ": " + str(error)
        print(failure, file=sys.stderr, flush=True)
    finally:
        try:
            after = source_snapshot(source, identity["source_revision"])
            if before is not None:
                require_unchanged_source(before, after)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            failure = (failure + "; " if failure else "") + type(error).__name__ + ": " + str(error)
        files = artifact_files(output)
        receipt = evidence_receipt(identity, before, after, records, files, failure)
        (output / "network-rewrite-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return 0 if receipt["status"] == "passed_l0_l1" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(1)
