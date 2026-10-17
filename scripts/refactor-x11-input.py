"""Verify native input on an owned, authenticated Xvfb desktop only.

The display is selected by Xvfb, with TCP disabled and a temporary random
Xauthority cookie. The harness never connects to the user's DISPLAY. This is
development evidence; actual GNOME/KDE, IME, lock and monitor acceptance remain
separate requirements.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time


TEST = "x11::tests::actual_isolated_x11_input_and_idle_platform_change"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", type=Path)
    parser.add_argument("--namespace-launcher", choices=("unprivileged", "sudo"), default="unprivileged",
                        help="Use sudo -n for namespace setup on CI hosts restricting unprivileged user namespaces; compilation still runs as the caller.")
    parser.add_argument("--socket-namespace", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--original-namespaces", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path, default=Path("artifacts/core-verification/linux-x11-input.log"))
    args = parser.parse_args()
    if sys.platform != "linux" or not shutil.which("Xvfb"):
        raise SystemExit("This verification requires Linux and Xvfb.")
    root = Path(__file__).resolve().parents[1]
    executable = args.test_executable
    if executable is None:
        build = subprocess.run(["cargo", "test", "-p", "nestlink-platform-input", "--locked", "--lib", "--no-run", "--message-format=json"],
                               cwd=root, stdout=subprocess.PIPE, check=False)
        if build.returncode:
            raise SystemExit(build.returncode)
        entries = [json.loads(line) for line in build.stdout.splitlines()]
        binaries = [e["executable"] for e in entries if e.get("reason") == "compiler-artifact" and e.get("executable")
                    and e["target"]["name"] == "nestlink_platform_input" and e["profile"]["test"]]
        if len(binaries) != 1:
            raise SystemExit("Expected one compiled platform-input test executable.")
        executable = Path(binaries[0])
    if not args.socket_namespace:
        # WSLg mounts /tmp/.X11-unix read-only. Create a separate mount and
        # network namespace rather than changing that mount or reusing :0.
        path = Path(__file__).with_name("refactor-linux-namespaces.py")
        spec = importlib.util.spec_from_file_location("nestlink_linux_namespaces", path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        command = helper.command(args.namespace_launcher, [
                   sys.executable, str(Path(__file__).resolve()), "--socket-namespace", "--test-executable", str(executable.resolve()),
                   "--output", str(args.output), "--original-namespaces",
                   json.dumps({name: os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "net", "user")})])
        raise SystemExit(subprocess.run(command, cwd=root, check=False).returncode)
    # Refuse to mount anything unless this process really has isolated namespaces.
    original = json.loads(args.original_namespaces or "{}")
    for namespace in ("mnt", "net", "user"):
        if namespace not in original or os.readlink(f"/proc/self/ns/{namespace}") == original[namespace]:
            raise SystemExit("X11 verification requires isolated mount, network and user namespaces.")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=1777,nosuid,nodev,noexec", "tmpfs", "/tmp/.X11-unix"], check=True)
    with tempfile.TemporaryDirectory(prefix="nestlink-x11-") as temporary:
        authority = Path(temporary) / "Xauthority"
        fields = [b"", b"", b"MIT-MAGIC-COOKIE-1", secrets.token_bytes(16)]
        record = struct.pack(">H", 65535) + b"".join(struct.pack(">H", len(field)) + field for field in fields)
        authority.write_bytes(record)
        authority.chmod(0o600)
        read_fd, write_fd = os.pipe()
        try:
            with (Path(temporary) / "xvfb.log").open("wb") as server_log:
                server = subprocess.Popen(["Xvfb", "-displayfd", str(write_fd), "-nolisten", "tcp", "-auth", str(authority),
                                           "-screen", "0", "1024x768x24", "-noreset"],
                                          pass_fds=(write_fd,), stdout=server_log, stderr=subprocess.STDOUT)
                os.close(write_fd)
                write_fd = None
                try:
                    deadline = time.monotonic() + 10
                    value = bytearray()
                    while b"\n" not in value:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([read_fd], [], [], remaining)[0]:
                            raise RuntimeError("Owned Xvfb did not become ready.")
                        chunk = os.read(read_fd, 32)
                        if not chunk or len(value) + len(chunk) > 16:
                            server_log.flush()
                            diagnostic = (Path(temporary) / "xvfb.log").read_text(errors="replace")[-4096:]
                            raise RuntimeError("Owned Xvfb returned no valid display.\n" + diagnostic)
                        value.extend(chunk)
                    display = value.decode("ascii").strip()
                    if not display.isdecimal() or int(display) > 65535 or server.poll() is not None:
                        server_log.flush()
                        diagnostic = (Path(temporary) / "xvfb.log").read_text(errors="replace")[-4096:]
                        raise RuntimeError("Owned Xvfb returned an invalid display: " + repr(display) + "\n" + diagnostic)
                    environment = dict(os.environ, DISPLAY=":" + display, XAUTHORITY=str(authority),
                                       NESTLINK_TEST_X11_DISPLAY=":" + display, NESTLINK_TEST_X11_PID=str(server.pid))
                    environment.pop("WAYLAND_DISPLAY", None)
                    result = subprocess.run([str(executable.resolve()), "--ignored", "--exact", TEST, "--nocapture"],
                                            cwd=root, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30, check=False)
                    target = args.output if args.output.is_absolute() else root / args.output
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(result.stdout)
                    print(result.stdout.decode("utf-8", errors="replace"))
                    if result.returncode:
                        raise SystemExit(result.returncode)
                    if b"test result: ok. 1 passed; 0 failed; 0 ignored" not in result.stdout:
                        raise SystemExit("The isolated X11 input test did not actually run.")
                finally:
                    # Only this child is signalled, and always reaped.
                    if server.poll() is None:
                        server.terminate()
                    try:
                        server.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server.kill()
                        server.wait(timeout=3)
        finally:
            os.close(read_fd)
            if write_fd is not None:
                os.close(write_fd)


if __name__ == "__main__":
    main()
