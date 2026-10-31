#!/usr/bin/env python3
"""Run L2 SDK/raw/nft ownership cases only on an isolated GitHub-hosted VM.

The ordinary test process owns real private-service authorization and sockets.
Its exact executable also supplies the separate root helper cooperation role.
This experiment does not claim production CLI/login recovery (L3) acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
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
import uuid

ROLE_PREFIX = "NESTLINK_RAW_ROLE_RESULT="
CASES = {
    "tcp": "raw::tcp_uid_fence_and_physical_cleanup",
    "udp": "raw::udp_uid_fence_empty_datagrams_and_helper_crash",
}
HOSTED_KEYS = (
    "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW_REF", "GITHUB_SHA",
)


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(value: dict) -> dict:
    """Retain every kernel handle/configuration; omit only nft tool metadata."""
    tables, chains, rules = [], [], []
    for item in value["nftables"]:
        if len(item) != 1:
            raise ValueError("ambiguous nft observation")
        kind, body = next(iter(item.items()))
        if kind == "table":
            tables.append(body)
        elif kind == "chain":
            chains.append(body)
        elif kind == "rule":
            rules.append(body)
        elif kind != "metainfo":
            raise ValueError("unexpected nft object in the exact test table")
    if len(tables) != 1:
        raise ValueError("exactly one table observation required")
    return {"table": tables[0], "chains": sorted(chains, key=lambda row: row["name"]), "rules": rules}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    environment = os.environ
    if (
        os.name != "posix" or os.geteuid() == 0
        or environment.get("NESTLINK_RAW_KERNEL_GATE") != "1"
        or environment.get("GITHUB_ACTIONS") != "true"
        or environment.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or environment.get("RUNNER_OS") != "Linux"
        or environment.get("GITHUB_REPOSITORY") != "ZHanry/NestLink"
        or not environment.get("GITHUB_WORKFLOW_REF", "").startswith(
            "ZHanry/NestLink/.github/workflows/local-port-gate.yml@refs/"
        )
        or re.fullmatch(r"[0-9a-f]{40}", environment.get("GITHUB_SHA", "")) is None
    ):
        raise ValueError("R02: raw kernel gate experiment requires its ordinary-user hosted workflow")
    source, output = Path.cwd().resolve(), arguments.output.resolve()
    runner_temp = Path(environment["RUNNER_TEMP"]).resolve()
    if (
        not arguments.output.is_absolute() or output == runner_temp
        or not output.is_relative_to(runner_temp) or output.is_relative_to(source)
        or output.exists()
    ):
        raise ValueError("a fresh owned evidence directory beneath RUNNER_TEMP is required")
    output.mkdir(mode=0o700)
    receipt = {
        "schema_version": 1, "kind": "sdk-raw-local-port-gate-hosted-experiment",
        "evidence_level": "L2_hosted_sdk_kernel", "production_cli_validated": False,
        "repository": environment["GITHUB_REPOSITORY"],
        "source_revision": environment["GITHUB_SHA"],
        "workflow_revision": environment["GITHUB_WORKFLOW_SHA"],
        "run_id": environment["GITHUB_RUN_ID"], "run_attempt": environment["GITHUB_RUN_ATTEMPT"],
        "runner_environment": environment["RUNNER_ENVIRONMENT"], "runner_uid": os.geteuid(),
        "dependency_lock_sha256": digest(source / "Cargo.lock"),
        "commands": [], "cases": {}, "status": "failed",
    }
    executable = None
    executable_directory = None
    roots = []
    sentinel = "nl_lab_" + uuid.uuid4().hex[:16]
    sentinel_before = None

    def execute(name, argv, timeout=30, extra_env=None, stdin=None):
        log = output / (name + ".log")
        command = {"name": name, "argv": [str(word) for word in argv], "timeout_seconds": timeout,
                   "log": log.name, "started_at_unix": time.time()}
        receipt["commands"].append(command)
        with log.open("wb") as stream:
            process = subprocess.Popen(
                command["argv"], stdout=stream, stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                env=dict(environment, **(extra_env or {})), start_new_session=True,
            )
            try:
                process.communicate(None if stdin is None else json.dumps(stdin).encode(), timeout=timeout)
                command["return_code"], command["timed_out"] = process.returncode, False
            except subprocess.TimeoutExpired:
                # The test group can contain an elevated child. Kill that exact
                # original group as root; then inspect/recover only our journal.
                subprocess.run(
                    ["sudo", "--non-interactive", "kill", "-KILL", "--", "-" + str(process.pid)],
                    stdout=stream, stderr=subprocess.STDOUT, timeout=10, check=False,
                )
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
                command["return_code"], command["timed_out"] = None, True
        command["finished_at_unix"], command["log_sha256"] = time.time(), digest(log)
        return command["return_code"], log.read_text(errors="replace")

    def required(name, argv, **kwargs):
        code, log = execute(name, argv, **kwargs)
        if code != 0:
            raise RuntimeError(f"{name} failed ({code}); see retained command log")
        return log

    def nft(name, argv, *, transaction=None):
        text = required(name, ["sudo", "--non-interactive", "nft", "--json", "--handle", "--numeric", *argv], stdin=transaction)
        return None if not text.strip() else json.loads(text)

    def role(action, root):
        return ["sudo", "--non-interactive", "env", "NESTLINK_RAW_KERNEL_GATE=1",
                *(key + "=" + environment[key] for key in HOSTED_KEYS),
                "NESTLINK_RAW_KERNEL_ROLE=" + action, "NESTLINK_RAW_KERNEL_ROOT=" + str(root),
                str(executable), "--ignored", "--exact", "raw::root_helper_role",
                "--nocapture", "--test-threads=1", "--color=never"]

    def inspect(name, root):
        text = required(name, role("inspect", root))
        rows = [line.split(ROLE_PREFIX, 1)[1] for line in text.splitlines() if ROLE_PREFIX in line]
        if len(rows) != 1:
            raise ValueError("missing exact helper inspection result")
        return json.loads(rows[0])["state"]

    def assert_one_test(log, case):
        if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", log) or case not in log:
            raise ValueError("exact ignored kernel case did not run once and pass")

    try:
        if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != environment["GITHUB_SHA"]:
            raise ValueError("source revision mismatch")
        if subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"]):
            raise ValueError("experiment requires the exact clean source")
        log = required("build-sdk-raw-owner", [
            "cargo", "test", "--locked", "-p", "nestlink-sdk", "--test", "private_services",
            "--no-run", "--message-format=json",
        ], timeout=1800)
        artifacts = []
        for line in log.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (item.get("reason") == "compiler-artifact"
                and item.get("target", {}).get("name") == "private_services"
                and item.get("profile", {}).get("test") is True and item.get("executable")):
                artifacts.append(Path(item["executable"]).resolve())
        if len(artifacts) != 1 or not artifacts[0].is_relative_to(source / "target"):
            raise ValueError("expected one source-owned private_services test executable")
        built_executable = artifacts[0]
        executable_directory = Path(tempfile.mkdtemp(prefix="nestlink-raw-roles-", dir="/tmp"))
        executable = executable_directory / "private-services"
        shutil.copyfile(built_executable, executable)
        executable.chmod(0o555)
        executable_directory.chmod(0o755)
        receipt["executable"] = {
            "build_path": str(built_executable), "path": str(executable),
            "sha256": digest(built_executable),
        }
        if digest(executable) != receipt["executable"]["sha256"]:
            raise ValueError("shared ordinary/root/probe executable differs from the hosted build")
        required("create-unrelated-sentinel", ["sudo", "--non-interactive", "nft", "--json", "--file", "-"], stdin={"nftables": [
            {"add": {"table": {"family": "inet", "name": sentinel, "comment": "NestLink:raw-lab:" + sentinel}}},
            {"add": {"chain": {"family": "inet", "table": sentinel, "name": "untouched"}}},
        ]})
        sentinel_before = snapshot(nft("sentinel-before", ["list", "table", "inet", sentinel]))
        for name, case in CASES.items():
            case_output = output / name
            case_output.mkdir(mode=0o700)
            root_text = required(name + "-root-directory", ["sudo", "--non-interactive", "mktemp", "-d", "/run/nestlink-raw-lab.XXXXXXXX"])
            root = Path(root_text.strip())
            if not re.fullmatch(r"/run/nestlink-raw-lab\.[A-Za-z0-9]{8}", str(root)):
                raise ValueError("unexpected root experiment directory")
            roots.append((name, root, case_output))
            required(name + "-public-directory", ["sudo", "--non-interactive", "chmod", "0755", str(root)])
            text = required(name + "-sdk-kernel-case", [str(executable), "--ignored", "--exact", case,
                            "--nocapture", "--test-threads=1", "--color=never"], timeout=70,
                            extra_env={"NESTLINK_RAW_KERNEL_ROOT": str(root), "NESTLINK_RAW_KERNEL_OUTPUT": str(case_output)})
            assert_one_test(text, case)
            result = json.loads((case_output / "scenario.json").read_text())
            attestation = json.loads((case_output / "root-receipt.json").read_text())
            root_receipt = root / "receipt.json"
            metadata = root_receipt.stat(follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or json.loads(root_receipt.read_text()) != attestation):
                raise ValueError("public root receipt is not the original immutable root-owned readback")
            plan = result["plan"]
            table = result["table"]
            if (result["source_revision"] != environment["GITHUB_SHA"]
                or result["evidence_level"] != "L2_hosted_sdk_kernel" or result["production_cli_validated"] is not False
                or result["status"] != "passed_before_owner_process_exit"
                or result["protocol"] != name or result["owner"]["uid"] != os.geteuid()
                or result["occupied_port_rejected"] is not True or result["socket_closed"] is not True
                or result["cleanup_failures"] != 0 or result["gate_retained_after_socket_close"] is not True
                or table != "nlp_" + plan["owner_id"].replace("-", "")
                or plan != attestation["plan"] or attestation["helper"]["uid"] != 0
                or attestation["helper"]["pid"] == plan["process"]["pid"]
                or plan["process"] != result["owner"]
                or attestation["helper"]["image_inode"] != plan["process"]["image_inode"]
                or attestation["helper"]["image_device"] != plan["process"]["image_device"]):
                raise ValueError("incomplete SDK/kernel scenario receipt")
            probes = result["probes"]
            if ([probe["uid"] for probe in probes[:3]] != [os.geteuid(), 65534, os.geteuid()]
                or [probe["allowed"] for probe in probes[:3]] != [True, False, True]
                or len(probes) != (4 if name == "udp" else 3)
                or len({probe["pid"] for probe in probes}) != len(probes)):
                raise ValueError("real same/different UID probe evidence missing")
            for probe in probes:
                if probe["allowed"] != (probe["payload"] in result["backend_payloads"]):
                    raise ValueError("UID probe outcome disagrees with actual approved backend bytes")
            if name == "udp" and (probes[3]["payload"] != [] or probes[3]["allowed"] is not True or result["forwarded_datagrams"] < 6):
                raise ValueError("real empty UDP request/reply missing")
            local_tls = result["local_tls"]
            if name == "tcp":
                payload = local_tls["payload"]
                before_tls = sum(probe["allowed"] is True for probe in probes)
                certificate = case_output / "local-tls-certificate.der"
                if (local_tls["kind"] != "local_tls_over_original_private_tcp_service"
                    or local_tls["plan"] != plan or local_tls["helper"] != attestation["helper"]
                    or local_tls["trusted_name"] != "owned-raw.nestlink.internal"
                    or local_tls["wrong_name"] != "wrong-name.invalid"
                    or local_tls["client_trust"] != "explicit_generated_single_root"
                    or local_tls["certificate_der"] != certificate.name
                    or not 0 < len(certificate.read_bytes()) <= 16384
                    or local_tls["trusted_ca_validated"] is not True
                    or local_tls["wrong_name_rejected"] is not True
                    or not local_tls["wrong_name_error"]
                    or local_tls["original_receipt_unchanged"] is not True
                    or local_tls["rejected_handshake_backend_unchanged"] is not True
                    or local_tls["backend_payloads_before_tls"] != before_tls
                    or local_tls["backend_payloads_after_tls"] != before_tls + 1
                    or len(result["backend_payloads"]) != before_tls + 1
                    or not 6 < len(payload) <= 2048
                    or payload[:6] != [0, 255, 128, 13, 10, 0]
                    or local_tls["reply"] != payload
                    or result["backend_payloads"].count(payload) != 1
                    or local_tls["accepted_connections"] != 2
                    or local_tls["completed_connections"] != 2
                    or local_tls["rejected_connections"] != 1
                    or local_tls["failed_connections"] != 0
                    or local_tls["cleanup_failures"] != 0
                    or local_tls["socket_closed"] is not True
                    or local_tls["socket_rebound"] is not True
                    or local_tls["remote_https_validated"] is not False):
                    raise ValueError("local TLS original owner, standard trust, backend bytes or physical cleanup evidence missing")
            elif local_tls is not None:
                raise ValueError("UDP must not claim a TCP TLS termination experiment")
            expected = attestation["installed"]
            snapshots = ["installed", "after-probes", "after-socket-close"]
            if name == "tcp":
                snapshots.append("after-local-tls")
            for label in snapshots:
                if snapshot(json.loads((case_output / (label + ".nft.json")).read_text())) != expected:
                    raise ValueError("kernel table handles/configuration differ from root attestation")
            if name == "udp":
                if not result["helper_killed"] or not result["live_process_recovery_rejected"]:
                    raise ValueError("helper crash/live owner recovery scenario missing")
                if "original gate socket owner is still alive" not in (case_output / "early-recover.log").read_text():
                    raise ValueError("early recovery failed for a reason other than actual live owner")
                if snapshot(json.loads((case_output / "after-helper-kill.nft.json").read_text())) != expected:
                    raise ValueError("helper crash removed or changed kernel fence")
                retained = inspect(name + "-retained-inspect", root)
                if retained["journal"] is None or retained["current"] != expected:
                    raise ValueError("helper crash lost protected journal or exact kernel gate")
                marker = "NestLink:raw-lab-foreign:" + uuid.uuid4().hex
                nft(name + "-foreign-inject", ["--file", "-"], transaction={"nftables": [{"add": {"rule": {
                    "family": "inet", "table": table, "chain": "output", "expr": [{"counter": None}], "comment": marker,
                }}}]})
                foreign = snapshot(nft(name + "-foreign-before", ["list", "table", "inet", table]))
                code, diagnostic = execute(name + "-foreign-recovery-denied", role("recover", root))
                if (code == 0 or "gate object handles/configuration changed" not in diagnostic
                    or snapshot(nft(name + "-foreign-after", ["list", "table", "inet", table])) != foreign):
                    raise ValueError("recovery deleted or modified foreign gate configuration")
                rules = [rule for rule in foreign["rules"] if rule.get("comment") == marker]
                if len(rules) != 1:
                    raise ValueError("exact injected foreign rule handle missing")
                nft(name + "-foreign-operator-remove", ["--file", "-"], transaction={"nftables": [{"delete": {"rule": {
                    "family": "inet", "table": table, "chain": "output", "handle": rules[0]["handle"],
                }}}]})
                if snapshot(nft(name + "-foreign-restored", ["list", "table", "inet", table])) != expected:
                    raise ValueError("operator failed to restore the exact original gate")
                required(name + "-post-exit-recover", role("recover", root))
                result["foreign_rule_preserved"] = True
            else:
                # Normal helper owns cleanup, and may still be observing the
                # just-exited process. Wait for its explicit physical receipt.
                helper_log = case_output / "root-helper.log"
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if '"cleaned_after_owner_exit":true' in helper_log.read_text(errors="replace"):
                        break
                    time.sleep(0.1)
                else:
                    raise ValueError("original root helper never confirmed owner-exit cleanup")
            state = inspect(name + "-final-inspect", root)
            if state != {"journal": None, "current": None}:
                raise ValueError("kernel gate or protected journal remained after confirmed cleanup")
            tables = nft(name + "-tables-after", ["list", "tables"])
            if any(item.get("table", {}).get("name") == table for item in tables["nftables"]):
                raise ValueError("kernel table survived reported cleanup")
            if snapshot(nft(name + "-unrelated-after", ["list", "table", "inet", sentinel])) != sentinel_before:
                raise ValueError("unrelated root-owned nft table changed")
            result["owner_process_exited"] = True
            result["kernel_gate_removed"] = True
            result["journal_cleared"] = True
            result["unrelated_table_preserved"] = True
            result["status"] = "passed_scoped_hosted_sdk_kernel_experiment"
            receipt["cases"][name] = result
        if digest(executable) != receipt["executable"]["sha256"]:
            raise ValueError("test executable changed during ordinary/root/probe execution")
        receipt["status"] = "passed_scoped_hosted_sdk_kernel_experiment"
    except Exception as error:
        receipt["failure"] = type(error).__name__ + ": " + str(error)
        print(receipt["failure"], flush=True)
    finally:
        # Recover only exact product journals after their test owner exits.
        # Unrecoverable/foreign state remains on the disposable VM and is
        # reported as failed; no flush or blanket table deletion is used.
        for name, root, case_output in roots:
            if executable is not None:
                # Installation may reject a real kernel serialization before
                # publishing its receipt. Preserve the raw, narrowly selected
                # table before recovery validates it again. This observation
                # grants no cleanup authority and never lists other tables.
                if name not in receipt["cases"]:
                    try:
                        plan_path = case_output / "private-plan" / "plan.json"
                        plan = json.loads(plan_path.read_text())
                        owner = str(uuid.UUID(plan["owner_id"]))
                        if owner != plan["owner_id"]:
                            raise ValueError("noncanonical diagnostic owner")
                        execute(name + "-failure-owned-table", [
                            "sudo", "--non-interactive", "nft", "--json", "--handle", "--numeric",
                            "list", "table", "inet", "nlp_" + owner.replace("-", ""),
                        ])
                    except Exception as error:
                        receipt.setdefault("diagnostic_failures", []).append(str(error))
                try:
                    # The original root helper may still hold its exact
                    # journal while observing the just-exited test owner.
                    # Retry only that explicit lock contention, within one
                    # fixed budget; other recovery failures remain failures.
                    deadline = time.monotonic() + 8
                    attempt = 0
                    while True:
                        attempt += 1
                        code, diagnostic = execute(name + f"-finally-recover-{attempt}", role("recover", root), timeout=5)
                        if code == 0:
                            break
                        if ("the original gate owner or nft transaction still holds this journal" not in diagnostic
                            or time.monotonic() >= deadline):
                            raise RuntimeError(f"{name} final recovery failed ({code}); see retained command log")
                        time.sleep(0.1)
                    receipt.setdefault("final_recovery", {})[name] = inspect(name + "-finally-inspect", root)
                except Exception as error:
                    receipt["status"] = "failed"
                    receipt.setdefault("cleanup_failures", []).append(str(error))
        if sentinel_before is not None:
            try:
                if snapshot(nft("sentinel-final", ["list", "table", "inet", sentinel])) != sentinel_before:
                    raise ValueError("changed unrelated sentinel preserved for operator review")
                nft("sentinel-remove", ["delete", "table", "inet", sentinel])
            except Exception as error:
                receipt["status"] = "failed"
                receipt.setdefault("cleanup_failures", []).append(str(error))
        if executable is not None and not receipt.get("cleanup_failures"):
            try:
                executable.unlink(missing_ok=True)
                executable_directory.rmdir()
            except Exception as error:
                receipt["status"] = "failed"
                receipt.setdefault("cleanup_failures", []).append(str(error))
        receipt["source_after"] = {
            "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "status": subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], text=True),
            "dependency_lock_sha256": digest(source / "Cargo.lock"),
        }
        if (receipt["source_after"]["revision"] != receipt["source_revision"]
            or receipt["source_after"]["status"]
            or receipt["source_after"]["dependency_lock_sha256"] != receipt["dependency_lock_sha256"]):
            receipt["status"], receipt["failure"] = "failed", "source or dependency lock changed"
        receipt["evidence_files"] = {str(path.relative_to(output)): digest(path)
                                     for path in sorted(output.rglob("*")) if path.is_file()}
        (output / "local-port-gate-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("local-port-gate: " + receipt["status"], flush=True)
    return 0 if receipt["status"] == "passed_scoped_hosted_sdk_kernel_experiment" else 1


if __name__ == "__main__":
    raise SystemExit(main())
