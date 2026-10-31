#!/usr/bin/env python3
"""Run actual owned split-DNS experiments only on disposable hosted VMs.

The ordinary daemon tests use the ordinary business token. The separate OS
test deliberately needs administrator/root in order to exercise NRPT/resolved.
It changes a random product-owned suffix and retains its recovery journal if
the OS does not confirm cleanup. It never replaces the machine's resolver.
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


OS_TEST = (
    "space_dns_system::tests::"
    "actual_os_split_dns_resolves_and_recovers_without_changing_unrelated_policy"
)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    environment = os.environ
    if (
        environment.get("GITHUB_ACTIONS") != "true"
        or environment.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or environment.get("GITHUB_REPOSITORY") != "ZHanry/NestLink"
        or not environment.get("GITHUB_WORKFLOW_REF", "").startswith(
            "ZHanry/NestLink/.github/workflows/space-dns.yml@refs/"
        )
        or environment.get("RUNNER_OS") not in ("Linux", "Windows")
        or re.fullmatch(r"[0-9a-f]{40}", environment.get("GITHUB_SHA", "")) is None
    ):
        raise ValueError("R02: this OS-changing experiment requires its GitHub-hosted workflow")
    source = Path.cwd().resolve()
    output = arguments.output.resolve()
    runner_temp = Path(environment["RUNNER_TEMP"]).resolve()
    if (
        not arguments.output.is_absolute()
        or output == runner_temp
        or not output.is_relative_to(runner_temp)
        or output.is_relative_to(source)
        or output.exists()
    ):
        raise ValueError("a fresh owned evidence directory beneath RUNNER_TEMP is required")
    output.mkdir()
    receipt = {
        "schema_version": 1,
        "kind": "owned-system-split-dns-hosted-experiment",
        "repository": environment["GITHUB_REPOSITORY"],
        "source_revision": environment["GITHUB_SHA"],
        "workflow_revision": environment["GITHUB_WORKFLOW_SHA"],
        "run_id": environment["GITHUB_RUN_ID"],
        "run_attempt": environment["GITHUB_RUN_ATTEMPT"],
        "runner_os": environment["RUNNER_OS"],
        "runner_environment": environment["RUNNER_ENVIRONMENT"],
        "dependency_lock_sha256": digest(source / "Cargo.lock"),
        "commands": [],
        "acceptance_claims": [],
        "status": "failed",
    }

    def execute(name: str, argv: list[str], timeout: int, extra_env=None) -> int:
        log = output / (name + ".log")
        command = {
            "name": name, "argv": argv, "timeout_seconds": timeout,
            "log": log.name, "started_at_unix": time.time(),
        }
        receipt["commands"].append(command)
        with log.open("wb") as stream:
            try:
                process = subprocess.Popen(
                    argv, stdout=stream, stderr=subprocess.STDOUT,
                    env=None if extra_env is None else dict(environment, **extra_env),
                    start_new_session=os.name != "nt",
                )
                command["return_code"] = process.wait(timeout=timeout)
                command["timed_out"] = False
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False,
                    )
                elif argv[0] == "sudo":
                    # An ordinary runner cannot kill its elevated child's
                    # group. Bound the same explicit hosted root experiment.
                    subprocess.run(
                        ["sudo", "--non-interactive", "kill", "-KILL", "--", "-" + str(process.pid)],
                        stdout=stream, stderr=subprocess.STDOUT, timeout=30, check=False,
                    )
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=30)
                command["return_code"] = None
                command["timed_out"] = True
        command["finished_at_unix"] = time.time()
        command["log_sha256"] = digest(log)
        print(name + ": " + str(command["return_code"]), flush=True)
        return command["return_code"] if command["return_code"] is not None else 124

    try:
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        if actual != environment["GITHUB_SHA"]:
            raise ValueError("source revision mismatch")
        if subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"]):
            raise ValueError("experiment requires the exact clean source")
        if execute("build-test-owner", [
            "cargo", "test", "--locked", "-p", "nestlink-daemon", "--bin",
            "nestlink-daemon", "--no-run", "--message-format=json",
        ], 900):
            raise RuntimeError("daemon test compilation failed; retained log is authoritative")
        artifacts = []
        for line in (output / "build-test-owner.log").read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "nestlink-daemon"
                and item.get("profile", {}).get("test") is True
                and item.get("executable")
            ):
                artifacts.append(Path(item["executable"]).resolve())
        if len(artifacts) != 1 or not artifacts[0].is_relative_to(source / "target"):
            raise ValueError("expected exactly one source-owned daemon test executable")
        executable = artifacts[0]
        receipt["executable"] = {"path": str(executable), "sha256": digest(executable)}
        test_args = [str(executable), "space_dns", "--show-output", "--test-threads=1", "--color=never"]
        if os.name == "nt":
            # Reuse the existing restricted-token implementation; build and OS
            # mutation are separate from ordinary business-process execution.
            test_args = [sys.executable, "scripts/refactor-windows-normal-user.py", *test_args]
        ordinary = execute("ordinary-daemon-owners", test_args, 300)
        os_args = [str(executable), OS_TEST, "--ignored", "--exact", "--show-output", "--test-threads=1", "--color=never"]
        if os.name != "nt":
            os_args = ["sudo", "--non-interactive", "env", "NESTLINK_SYSTEM_DNS_LAB=1", *os_args]
        elevated = execute("actual-os-resolver-and-recovery", os_args, 300, {"NESTLINK_SYSTEM_DNS_LAB": "1"})
        if ordinary or elevated:
            raise RuntimeError("one or more actual DNS ownership tests failed")
        # A mistyped filter cannot silently report success with zero tests.
        ordinary_log = (output / "ordinary-daemon-owners.log").read_text(errors="replace")
        os_log = (output / "actual-os-resolver-and-recovery.log").read_text(errors="replace")
        if not re.search(r"test result: ok\. [1-9][0-9]* passed;", ordinary_log):
            raise ValueError("ordinary DNS test inventory was empty")
        if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in os_log or OS_TEST not in os_log:
            raise ValueError("the exact real OS resolver test did not execute")
        if digest(executable) != receipt["executable"]["sha256"]:
            raise ValueError("executable changed between ordinary and elevated execution")
        receipt["status"] = "passed_scoped_hosted_os_experiment"
    except Exception as error:
        receipt["failure"] = type(error).__name__ + ": " + str(error)
        print(receipt["failure"], file=sys.stderr)
    finally:
        receipt["source_after"] = {
            "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "status": subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], text=True),
            "dependency_lock_sha256": digest(source / "Cargo.lock"),
        }
        if (
            receipt["source_after"]["revision"] != receipt["source_revision"]
            or receipt["source_after"]["status"]
            or receipt["source_after"]["dependency_lock_sha256"] != receipt["dependency_lock_sha256"]
        ):
            receipt["status"] = "failed"
            receipt["failure"] = "source or lock changed during the hosted experiment"
        (output / "system-dns-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if receipt["status"] == "passed_scoped_hosted_os_experiment" else 1


if __name__ == "__main__":
    raise SystemExit(main())
