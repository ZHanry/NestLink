"""Run actual kernel tests, each exclusively in a fresh Linux network namespace.

Build as the normal user; only each exact test executable invocation runs under
unshare with CAP_NET_ADMIN. Tests verify their namespace differs from PID 1 before
changing interfaces, addresses or routes. This is development evidence, not a
physical adapter, suspend or installed-product acceptance result.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


EVENT_TEST = "linux::tests::actual_isolated_ipv4_ipv6_route_and_link_events"
PINNING_TEST = "linux::path_tests::actual_isolated_dual_stack_interface_pinning_and_fail_closed_lifecycle"
TESTS = (EVENT_TEST, PINNING_TEST)
EVENT_OPERATIONS = [
    ["link", "set", "lo", "up"],
    ["address", "add", "192.0.2.10/32", "dev", "lo"],
    ["-6", "address", "add", "2001:db8::10/128", "dev", "lo", "nodad"],
    ["route", "add", "198.51.100.0/24", "dev", "lo"],
    ["link", "set", "lo", "down"],
]
NAMESPACE = re.compile(r"^isolated network namespace: self=net:\[(\d+)\], init=net:\[(\d+)\]$", re.MULTILINE)


def validate_execution(test_name, returncode, output):
    """Reject successful process exits unless the exact test and its work ran."""
    errors = []
    if test_name not in TESTS:
        return ["unknown-test"]
    if returncode != 0:
        errors.append("process-exit")
    if re.findall(r"^running (\d+) tests?$", output, re.MULTILINE) != ["1"]:
        errors.append("exact-test-count")
    if re.findall(r"^test (.+) \.\.\. (.+)$", output, re.MULTILINE) != [(test_name, "ok")]:
        errors.append("exact-test-passed")
    results = re.findall(r"^test result: .+$", output, re.MULTILINE)
    success = r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+"
    if len(results) != 1 or re.fullmatch(success, results[0]) is None:
        errors.append("one-successful-result")
    if output.count(f"---- {test_name} stdout ----") != 1:
        errors.append("captured-test-output")
    namespaces = NAMESPACE.findall(output)
    if len(namespaces) != 1 or namespaces[0][0] == namespaces[0][1]:
        errors.append("isolated-namespace")
    if test_name == EVENT_TEST:
        markers = re.findall(r"^isolated kernel notification: (\[.*\]), generation ([1-9]\d*)$", output, re.MULTILINE)
        try:
            operations = [json.loads(operation) for operation, _ in markers]
        except json.JSONDecodeError:
            operations = []
        generations = [int(generation) for _, generation in markers]
        if operations != EVENT_OPERATIONS or any(old >= new for old, new in zip(generations, generations[1:])):
            errors.append("kernel-event-operations")
    else:
        markers = re.findall(
            r"^isolated Linux media route: ipv4_ipv6_same_socket=true, pinned_ifindex=([1-9]\d*), "
            r"replacement_ifindex=([1-9]\d*), wrong_source_down_rename_delete_no_fallback=true$", output, re.MULTILINE)
        if len(markers) != 1 or markers[0][0] == markers[0][1]:
            errors.append("pinned-interface-lifecycle")
    return errors


def execute_cases(root, executable):
    """Keep a separate unshare lifetime for each test and retain every failure."""
    executions = []
    for test_name in TESTS:
        command = ([] if os.geteuid() == 0 else ["sudo", "-n"]) + [
            "unshare", "--net", str(executable.resolve()), "--ignored", "--exact", test_name, "--show-output"]
        try:
            result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False, timeout=120)
            raw, returncode = result.stdout, result.returncode
        except subprocess.TimeoutExpired as error:
            raw, returncode = error.stdout or b"", None
        except OSError as error:
            raw, returncode = f"Could not start isolated kernel test: {error}\n".encode("utf-8"), None
        output = raw.decode("utf-8", errors="replace")
        errors = validate_execution(test_name, returncode, output)
        namespaces = NAMESPACE.findall(output)
        executions.append({"test": test_name, "command": command, "returncode": returncode,
            "namespace": {"self": namespaces[0][0], "init": namespaces[0][1]} if len(namespaces) == 1 else None,
            "stdout_sha256": hashlib.sha256(raw).hexdigest(), "errors": errors, "output": output})
    return executions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/core-verification/linux-network-events.log"))
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("Network namespace verification must run on Linux.")
    root = Path(__file__).resolve().parents[1]
    executable = args.test_executable
    if executable is None:
        build = subprocess.run(["cargo", "test", "-p", "nestlink-platform-network", "--locked", "--no-run", "--message-format=json"],
            cwd=root, stdout=subprocess.PIPE, check=False)
        if build.returncode:
            raise SystemExit(build.returncode)
        entries = [json.loads(line) for line in build.stdout.splitlines()]
        binaries = [entry["executable"] for entry in entries if entry.get("reason") == "compiler-artifact"
            and entry.get("executable") and entry["target"]["name"] == "nestlink_platform_network" and entry["profile"]["test"]]
        if len(binaries) != 1:
            raise SystemExit("Expected one compiled platform-network test executable.")
        executable = Path(binaries[0])
    executions = execute_cases(root, executable)
    target = args.output if args.output.is_absolute() else root / args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    log = "\n".join(f"=== {execution['test']} ===\n{execution['output']}" for execution in executions)
    target.write_text(log, encoding="utf-8")
    receipt = {"schema": 1, "scope": "isolated-linux-network-development",
        "test_executable": str(executable.resolve()), "passed": all(not item["errors"] for item in executions),
        "executions": [{key: value for key, value in item.items() if key != "output"} for item in executions]}
    target.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(log)
    if not receipt["passed"]:
        raise SystemExit("Isolated kernel verification failed: " + "; ".join(
            f"{item['test']}: {', '.join(item['errors'])}" for item in executions if item["errors"]))


if __name__ == "__main__":
    main()
