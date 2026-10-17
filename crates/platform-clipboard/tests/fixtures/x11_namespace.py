"""Run only owned clipboard Xvfb fixtures in independent local namespaces.

The Rust fixture creates its own server, random Xauthority, windows and text,
checks SO_PEERCRED against that child PID and always kills/reaps the child.
This launcher changes no host mount, network or user namespace.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--namespace-launcher", choices=("unprivileged", "sudo"), default="unprivileged")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--original-namespaces", help=argparse.SUPPRESS)
    args = parser.parse_args()
    executable = args.test_executable.resolve(strict=True)
    if not args.inside:
        original = {name: os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "net", "user")}
        command = (["sudo", "-n"] if args.namespace_launcher == "sudo" else []) + [
            "unshare", "--user", "--map-root-user", "--mount", "--net", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), "--inside", "--test-executable", str(executable),
            "--output", str(args.output.resolve()), "--original-namespaces", json.dumps(original),
        ]
        return subprocess.run(command, check=False).returncode
    original = json.loads(args.original_namespaces or "{}")
    for name in ("mnt", "net", "user"):
        if name not in original or os.readlink(f"/proc/self/ns/{name}") == original[name]:
            raise RuntimeError("Clipboard fixture requires distinct mount, network and user namespaces")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=1777,nosuid,nodev,noexec", "tmpfs", "/tmp/.X11-unix"], check=True)
    result = subprocess.run([str(executable), "x11::tests::owned_xvfb", "--ignored", "--test-threads=1", "--nocapture"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45, check=False)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result.stdout)
    print(result.stdout.decode("utf-8", errors="replace"))
    if result.returncode == 0 and b"test result: ok. 3 passed; 0 failed; 0 ignored" not in result.stdout:
        raise RuntimeError("The isolated clipboard tests did not actually run")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
