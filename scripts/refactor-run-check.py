"""Run one selected development check with a retained log and owned scratch.

Usage: python scripts/refactor-run-check.py --log artifacts/check.log -- cargo test ...
The compiler cache and acceptance evidence are retained. Tests must close their
own service processes; this wrapper terminates the command tree on interruption.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time


def git_environment(root):
    """Read a Windows-created worktree from WSL without rewriting its metadata."""
    env = os.environ.copy()
    pointer = root / ".git"
    if os.name != "nt" and pointer.is_file():
        text = pointer.read_text(encoding="utf-8").strip()
        match = re.fullmatch(r"gitdir: ([A-Za-z]):[/\\](.+)", text)
        if match:
            drive, tail = match.groups()
            gitdir = Path("/mnt") / drive.lower() / tail.replace("\\", "/")
            if not gitdir.is_dir():
                raise ValueError("Windows worktree git directory is unavailable in WSL: " + str(gitdir))
            env.update(GIT_DIR=str(gitdir), GIT_WORK_TREE=str(root))
    return env


def source_snapshot(root, prefixes):
    """Hash only selected versioned/unignored build inputs, never build caches."""
    selected = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", *prefixes]
    for prefix in selected:
        candidate = (root / prefix).resolve()
        if prefix.startswith("-") or not candidate.is_relative_to(root):
            raise ValueError("source scope must stay inside the repository")
        if not candidate.exists():
            raise ValueError("source scope does not exist: " + prefix)
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", *selected],
        cwd=root,
        env=git_environment(root),
    ).decode("utf-8").split("\0")
    result = []
    for name in sorted(set(filter(None, paths))):
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("source input cannot follow an external/symbolic path")
        if path.is_file():
            result.append({"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return result


@contextmanager
def owned_scratch(parent):
    scratch = tempfile.TemporaryDirectory(prefix="check-", dir=parent)
    try:
        yield scratch.name
    finally:
        # A just-exited JVM can briefly retain its extracted JNA DLL or log.
        # Retry only this invocation's unique owned directory; report a real
        # cleanup failure after five seconds rather than masking it as success.
        for attempt in range(11):
            try:
                scratch.cleanup()
                break
            except PermissionError:
                if attempt == 10:
                    print("Owned test scratch could not be removed: " + scratch.name,
                          file=sys.stderr, flush=True)
                    raise
                time.sleep(0.5)


def terminate(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--source-prefix", action="append", default=[],
                        help="Record before/after input hashes for this repository path; repeat for dependencies")
    parser.add_argument("--workdir", type=Path, default=Path("."),
                        help="Command directory inside the repository (default: repository root)")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")
    root = Path(__file__).resolve().parents[1]
    workdir = (root / args.workdir).resolve()
    if not workdir.is_relative_to(root) or not workdir.is_dir():
        parser.error("workdir must be an existing directory inside the repository")
    log = (root / args.log).resolve()
    artifacts = (root / "artifacts").resolve()
    if not log.is_relative_to(artifacts):
        parser.error("log must be inside the workspace artifacts directory")
    log.parent.mkdir(parents=True, exist_ok=True)
    sources_before = source_snapshot(root, args.source_prefix) if args.source_prefix else None
    started_at = datetime.now(timezone.utc).isoformat()
    # protoc's Windows argv handling cannot use non-ASCII temporary paths.
    # Own only a unique child of this named system-temp directory; preserve
    # all other users' files and the shared build cache.
    scratch_root = (Path(tempfile.gettempdir()) / "nestlink-development-checks").resolve()
    scratch_root.mkdir(parents=True, exist_ok=True)
    with owned_scratch(scratch_root) as scratch:
        if not Path(scratch).resolve().is_relative_to(scratch_root.resolve()):
            raise RuntimeError("scratch directory escaped the owned root")
        env = os.environ.copy()
        env.update(TEMP=scratch, TMP=scratch, TMPDIR=scratch, PYTHONDONTWRITEBYTECODE="1")
        with log.open("wb") as output:
            process = subprocess.Popen(command, cwd=workdir, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            try:
                assert process.stdout is not None
                for line in process.stdout:
                    output.write(line)
                    output.flush()
                    sys.stdout.buffer.write(line)
                    sys.stdout.buffer.flush()
                code = process.wait()
            finally:
                terminate(process)
                if process.stdout is not None:
                    process.stdout.close()
    print("Owned test scratch removed; retained log: " + str(log), flush=True)
    if sources_before is not None:
        sources_after = source_snapshot(root, args.source_prefix)
        receipt = {
            "schema_version": 1,
            "scope": "Selected development command; not fixed-product or platform acceptance",
            "command": command,
            "working_directory": workdir.relative_to(root).as_posix(),
            "source_prefixes": args.source_prefix,
            "started_at": started_at,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "source_revision": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, env=git_environment(root)).decode().strip(),
            "source_tree_dirty": bool(subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=root, env=git_environment(root))),
            "source_files_before": sources_before,
            "source_files_after": sources_after,
            "source_inputs_unchanged": sources_before == sources_after,
            "exit_code": code,
            "log": log.relative_to(root).as_posix(),
            "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest(),
            "owned_scratch_removed": True,
        }
        receipt_path = log.with_suffix(".receipt.json")
        receipt_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print("Retained source/log receipt: " + str(receipt_path), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
