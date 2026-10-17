"""Exercise production portal/capture APIs against owned services in namespaces.

This is development evidence, not compositor or installed-product acceptance.
The caller's system/session buses, screen and input devices are never used.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


TEST = "production_portal_pipewire_joint_revocation"
NAMESPACES = ("mnt", "net", "user")


def namespaces():
    return {name: os.readlink(f"/proc/self/ns/{name}") for name in NAMESPACES}


def host_namespaces():
    # A child user namespace cannot read the host PID 1 namespace symlinks on
    # many distros. Snapshot them before unshare; if the caller cannot read
    # them either, its own actual namespaces remain the required outer bound.
    try:
        return {name: os.readlink(f"/proc/1/ns/{name}") for name in NAMESPACES}
    except PermissionError:
        return namespaces()


def isolated(original, host):
    current = namespaces()
    if set(original) != set(NAMESPACES) or any(current[name] == original[name] for name in NAMESPACES):
        raise RuntimeError("Portal verification requires fresh mount, network and user namespaces.")
    if set(host) != set(NAMESPACES) or any(current[name] == host[name] for name in NAMESPACES):
        raise RuntimeError("Portal verification cannot mount over the host's service namespace.")
    if os.geteuid() != 0:
        raise RuntimeError("The isolated namespace must map the caller to root for its private system bus.")


def stop_child(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)


def stop_group(child):
    # The test is launched in its own session. Its owned PipeWire children must
    # also be reaped after a timeout; never signal the launcher's process group.
    if child.pid <= 1 or child.pid == os.getpgrp() or child.returncode is not None:
        raise RuntimeError("Invalid owned test process group.")
    # Keep the group leader's PID allocated (possibly as a zombie) until all
    # group signals finish. Reaping first would permit PID/PGID reuse by an
    # unrelated host process, since we intentionally do not share its PID ns.
    try:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2
        while not exited(child) and time.monotonic() < deadline:
            time.sleep(0.02)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    finally:
        child.wait(timeout=2)


def exited(child):
    """Observe an owned child without reaping its process-group identity."""
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def bus(directory, name, address):
    log = (directory / (name + ".log")).open("w+b")
    try:
        child = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--print-address=1", "--address", address],
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 5
            while True:
                output = os.pread(log.fileno(), 4097, 0)
                if len(output) > 4096 or child.poll() is not None:
                    raise RuntimeError(f"Owned {name} bus failed to start: {output[-2048:]!r}")
                if address.encode("utf-8") + b",guid=" in output and b"\n" in output:
                    return child, log
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"Owned {name} bus readiness timed out.")
                time.sleep(0.01)
        except BaseException:
            stop_child(child)
            raise
    except BaseException:
        log.close()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", type=Path)
    parser.add_argument("--namespace-launcher", choices=("unprivileged", "sudo"), default="unprivileged")
    parser.add_argument("--service-namespace", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--original-namespaces", help=argparse.SUPPRESS)
    parser.add_argument("--host-namespaces", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, default=Path("artifacts/core-verification/linux-portal-capture.log"))
    args = parser.parse_args()
    if sys.platform != "linux" or any(not shutil.which(name) for name in ("dbus-daemon", "pipewire", "pw-link", "pw-cli", "pw-dump", "unshare")):
        raise SystemExit("This verification requires Linux, D-Bus, PipeWire tools and unshare.")
    root = Path(__file__).resolve().parents[1]
    executable = args.test_executable
    if executable is None:
        result = subprocess.run(
            ["cargo", "test", "-p", "nestlink-platform-capture", "--locked", "--test", "portal_session", "--no-run", "--message-format=json"],
            cwd=root, stdout=subprocess.PIPE, check=False,
        )
        if result.returncode:
            raise SystemExit(result.returncode)
        entries = [json.loads(line) for line in result.stdout.splitlines()]
        binaries = [entry["executable"] for entry in entries if entry.get("reason") == "compiler-artifact"
                    and entry.get("executable") and entry["target"]["name"] == "portal_session" and entry["profile"]["test"]]
        if len(binaries) != 1:
            raise SystemExit("Expected one compiled portal_session integration test executable.")
        executable = Path(binaries[0])
    if not args.service_namespace:
        command = (["sudo", "-n"] if args.namespace_launcher == "sudo" else []) + [
            "unshare", "--user", "--map-root-user", "--mount", "--net", "--propagation", "private",
            sys.executable, str(Path(__file__).resolve()), "--service-namespace", "--test-executable", str(executable.resolve()),
            "--output", str(args.output.resolve()), "--original-namespaces", json.dumps(namespaces()),
            "--host-namespaces", json.dumps(host_namespaces()),
        ]
        raise SystemExit(subprocess.run(command, cwd=root, check=False).returncode)
    original = json.loads(args.original_namespaces or "{}")
    isolated(original, json.loads(args.host_namespaces or "{}"))
    target = Path("/run/dbus")
    if target.is_symlink() or not target.is_dir() or target.resolve() != target:
        raise RuntimeError("Expected a real /run/dbus directory inside the private mount namespace.")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755,nosuid,nodev,noexec", "tmpfs", str(target)], check=True)
    with tempfile.TemporaryDirectory(prefix="nestlink-portal-joint-") as temporary:
        directory = Path(temporary)
        children = []
        try:
            system = "unix:path=/run/dbus/system_bus_socket"
            session = "unix:path=" + str(directory / "session-bus")
            children.append(bus(directory, "system", system))
            children.append(bus(directory, "session", session))
            environment = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=session,
                               DBUS_SYSTEM_BUS_ADDRESS=system,
                               NESTLINK_TEST_PORTAL_NAMESPACES=json.dumps(original),
                               NESTLINK_TEST_PORTAL_PID=str(os.getpid()))
            for name in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "PIPEWIRE_REMOTE", "PIPEWIRE_RUNTIME_DIR"):
                environment.pop(name, None)
            with (directory / "test.log").open("w+b") as log:
                child = subprocess.Popen([str(executable.resolve()), "--ignored", "--exact", TEST, "--nocapture"],
                                         cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                         start_new_session=True)
                try:
                    deadline = time.monotonic() + 60
                    outcome = exited(child)
                    while outcome is None:
                        if time.monotonic() >= deadline or os.fstat(log.fileno()).st_size > 4 * 1024 * 1024:
                            raise RuntimeError("Owned portal integration test exceeded time/output budget.")
                        time.sleep(0.02)
                        outcome = exited(child)
                    log.seek(0)
                    output = log.read(4 * 1024 * 1024 + 1)
                    if len(output) > 4 * 1024 * 1024:
                        raise RuntimeError("Owned portal integration output exceeded budget.")
                    report = args.output if args.output.is_absolute() else root / args.output
                    report.parent.mkdir(parents=True, exist_ok=True)
                    report.write_bytes(b"scope: private D-Bus + synthetic PipeWire joint fixture; product_acceptance:false\n" + output)
                    print(output.decode("utf-8", errors="replace"))
                    exit_code = outcome.si_status if outcome.si_code == os.CLD_EXITED else -outcome.si_status
                    if exit_code:
                        raise SystemExit(exit_code)
                    if b"test result: ok. 1 passed; 0 failed; 0 ignored" not in output:
                        raise RuntimeError("The isolated portal joint test did not actually run.")
                finally:
                    stop_group(child)
        finally:
            for child, log in reversed(children):
                stop_child(child)
                log.close()


if __name__ == "__main__":
    main()
