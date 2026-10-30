"""Run production Linux audio against private D-Bus/PipeWire software services.

Development evidence only. No existing sound server, microphone or speaker is
used. The mount operation is restricted to fresh user/mount/network namespaces.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

TEST = "linux::fixture::production_linux_audio_private_services"


def load_helpers():
    path = Path(__file__).with_name("refactor-portal-capture.py")
    spec = importlib.util.spec_from_file_location("nestlink_service_namespaces", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", type=Path)
    parser.add_argument("--output", type=Path, default=Path("artifacts/core-verification/linux-system-audio.log"))
    parser.add_argument("--namespace-launcher", choices=("unprivileged", "sudo"), default="unprivileged")
    parser.add_argument("--service-namespace", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--original-namespaces", help=argparse.SUPPRESS)
    parser.add_argument("--host-namespaces", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if sys.platform != "linux" or any(not shutil.which(name) for name in ("dbus-daemon", "pipewire", "pw-link", "pw-cli", "pw-dump", "unshare")):
        raise SystemExit("Linux, D-Bus, PipeWire tools and unshare are required.")
    helper = load_helpers()
    root = Path(__file__).resolve().parents[1]
    executable = args.test_executable
    if executable is None:
        result = subprocess.run(["cargo", "test", "--locked", "-p", "nestlink-platform-audio", "--lib", "--no-run", "--message-format=json"],
                                cwd=root, stdout=subprocess.PIPE, check=False)
        if result.returncode:
            for line in result.stdout.splitlines():
                entry = json.loads(line)
                if entry.get("reason") == "compiler-message":
                    diagnostic = entry.get("message", {}).get("rendered")
                    if diagnostic:
                        print(diagnostic, file=sys.stderr, end="")
            raise SystemExit(result.returncode)
        entries = [json.loads(line) for line in result.stdout.splitlines()]
        binaries = [entry["executable"] for entry in entries if entry.get("reason") == "compiler-artifact"
                    and entry.get("executable") and entry["target"]["name"] == "nestlink_platform_audio" and entry["profile"]["test"]]
        if len(binaries) != 1:
            raise SystemExit("Expected one compiled Linux audio test binary.")
        executable = Path(binaries[0])
    if not args.service_namespace:
        command = helper.namespace_command(args.namespace_launcher, [
            sys.executable, str(Path(__file__).resolve()), "--service-namespace", "--test-executable", str(executable.resolve()),
            "--output", str(args.output.resolve()), "--original-namespaces", json.dumps(helper.namespaces()),
            "--host-namespaces", json.dumps(helper.host_namespaces()),
        ])
        raise SystemExit(subprocess.run(command, cwd=root, check=False).returncode)
    original = json.loads(args.original_namespaces or "{}")
    helper.isolated(original, json.loads(args.host_namespaces or "{}"))
    target = Path("/run/dbus")
    if target.is_symlink() or not target.is_dir() or target.resolve() != target:
        raise RuntimeError("A real /run/dbus directory is required inside the fresh namespace.")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755,nosuid,nodev,noexec", "tmpfs", str(target)], check=True)
    with tempfile.TemporaryDirectory(prefix="nestlink-audio-namespaces-") as temporary:
        directory = Path(temporary)
        system, system_log = helper.bus(directory, "system", "unix:path=/run/dbus/system_bus_socket")
        try:
            environment = dict(os.environ, NESTLINK_TEST_AUDIO_NAMESPACES=json.dumps(original))
            for name in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
                         "DBUS_SYSTEM_BUS_ADDRESS", "PIPEWIRE_REMOTE", "PIPEWIRE_RUNTIME_DIR", "PULSE_SERVER"):
                environment.pop(name, None)
            with (directory / "test.log").open("w+b") as log:
                child = subprocess.Popen([str(executable.resolve()), "--ignored", "--exact", TEST, "--nocapture"],
                                         cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    deadline = time.monotonic() + 90
                    outcome = helper.exited(child)
                    while outcome is None:
                        if time.monotonic() >= deadline or os.fstat(log.fileno()).st_size > 4 * 1024 * 1024:
                            raise RuntimeError("Owned audio test exceeded time/output budget.")
                        time.sleep(0.02)
                        outcome = helper.exited(child)
                    log.seek(0)
                    output = log.read(4 * 1024 * 1024 + 1)
                    if len(output) > 4 * 1024 * 1024:
                        raise RuntimeError("Owned audio test output exceeded budget.")
                    report = args.output if args.output.is_absolute() else root / args.output
                    report.parent.mkdir(parents=True, exist_ok=True)
                    report.write_bytes(b"scope: private system bus and synthetic PipeWire audio; product_acceptance:false\n" + output)
                    print(output.decode("utf-8", errors="replace"))
                    code = outcome.si_status if outcome.si_code == os.CLD_EXITED else -outcome.si_status
                    if code:
                        raise SystemExit(code)
                    if b"test result: ok. 1 passed; 0 failed; 0 ignored" not in output:
                        raise RuntimeError("The isolated audio test did not actually run.")
                finally:
                    helper.stop_group(child)
        finally:
            helper.stop_child(system)
            system_log.close()


if __name__ == "__main__":
    main()
