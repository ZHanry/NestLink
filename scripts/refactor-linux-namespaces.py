"""Create private test namespaces while keeping the caller's filesystem access."""
import argparse
import os
from pathlib import Path
import select
import subprocess
import sys


def command(launcher, child):
    if launcher == "unprivileged":
        return ["unshare", "--user", "--map-root-user", "--mount", "--net",
                "--propagation", "private", *child]
    if launcher != "sudo":
        raise ValueError("Unknown namespace launcher")
    # Mapping sudo's host root to namespace root loses access to runner-owned
    # private checkout directories. Map the original caller instead. The
    # privileged parent writes the maps; the test then runs as that host user.
    return ["sudo", "-n", sys.executable, str(Path(__file__).resolve()),
            "--uid", str(os.geteuid()), "--gid", str(os.getegid()), "--", *child]


def run(uid, gid, child):
    if sys.platform != "linux" or os.geteuid() != 0 or uid < 0 or gid < 0 or not child:
        raise ValueError("A privileged Linux mapper, valid caller IDs and command are required")
    ready_read, ready_write = os.pipe()
    mapped_read, mapped_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_read)
            os.close(mapped_write)
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWNET)
            os.write(ready_write, b"1")
            os.close(ready_write)
            if os.read(mapped_read, 1) != b"1":
                raise RuntimeError("Caller namespace mapping failed")
            os.close(mapped_read)
            os.setgroups([])
            os.setgid(0)
            os.setuid(0)
            subprocess.run(["mount", "--make-rprivate", "/"], check=True)
            os.execvpe(child[0], child, os.environ)
        except BaseException as error:
            print("Private namespace child failed: " + str(error), file=sys.stderr, flush=True)
            os._exit(1)
    os.close(ready_write)
    os.close(mapped_read)
    try:
        if not select.select([ready_read], [], [], 10)[0] or os.read(ready_read, 1) != b"1":
            raise RuntimeError("Private namespace child did not become ready")
        # Only the owned, unreaped child can receive these maps.
        Path(f"/proc/{pid}/uid_map").write_text(f"0 {uid} 1\n", encoding="ascii")
        Path(f"/proc/{pid}/gid_map").write_text(f"0 {gid} 1\n", encoding="ascii")
        os.write(mapped_write, b"1")
    finally:
        os.close(ready_read)
        os.close(mapped_write)
        _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    parser.add_argument("child", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    raise SystemExit(run(args.uid, args.gid, args.child[1:] if args.child[:1] == ["--"] else args.child))
