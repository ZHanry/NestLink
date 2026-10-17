"""Run real kernel-event tests exclusively in a fresh Linux network namespace.

Build as the normal user; only the test executable runs under unshare with
CAP_NET_ADMIN. The test itself checks its namespace differs from PID 1 before
changing loopback addresses/routes. This is development evidence, not a physical
adapter, suspend or installed-product acceptance result.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


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
        binaries = [e["executable"] for e in entries if e.get("reason") == "compiler-artifact"
            and e.get("executable") and e["target"]["name"] == "nestlink_platform_network" and e["profile"]["test"]]
        if len(binaries) != 1:
            raise SystemExit("Expected one compiled platform-network test executable.")
        executable = Path(binaries[0])
    command = ([] if os.geteuid() == 0 else ["sudo", "-n"]) + ["unshare", "--net", str(executable.resolve()),
        "--ignored", "--exact", "linux::tests::actual_isolated_ipv4_ipv6_route_and_link_events", "--nocapture"]
    result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    target = args.output if args.output.is_absolute() else root / args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(result.stdout)
    print(result.stdout.decode("utf-8", errors="replace"))
    if result.returncode:
        raise SystemExit(result.returncode)
    if b"test result: ok. 1 passed; 0 failed; 0 ignored" not in result.stdout:
        raise SystemExit("The isolated kernel-event test did not actually run.")


if __name__ == "__main__":
    main()
