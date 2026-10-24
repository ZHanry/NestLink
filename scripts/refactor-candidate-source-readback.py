#!/usr/bin/env python3
"""Read-only bounded source diagnostics; optionally guard a build command."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

MAX_STATUS = 64 * 1024
MAX_ENTRIES = 32
MAX_PATH = 256


def path_record(root, raw):
    value = {"path": raw[:MAX_PATH].decode("utf-8", "backslashreplace"),
             "path_sha256": hashlib.sha256(raw).hexdigest(),
             "path_truncated": len(raw) > MAX_PATH}
    # Never follow repository symlinks or read file contents for diagnostics.
    # The raw porcelain hash is the authoritative byte-level receipt.
    parts = raw.split(b"/")
    if not raw or raw.startswith(b"/") or any(p in (b"", b".", b"..") for p in parts):
        value["kind"] = "unsafe-path"
        return value
    path = root
    try:
        for index, part in enumerate(parts):
            path = path / os.fsdecode(part)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                value["kind"] = "symlink"
                return value
            if index != len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                value["kind"] = "non-directory-parent"
                return value
        value["kind"] = "file" if stat.S_ISREG(info.st_mode) else "other"
        value["size"] = info.st_size
    except OSError:
        value["kind"] = "missing-or-unreadable"
    return value


def readback(root, phase):
    """Hash exact git status bytes, then emit only a bounded path/status sample."""
    digest = hashlib.sha256()
    prefix = bytearray()
    total = 0
    with tempfile.TemporaryFile() as output:
        completed = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=root, stdout=output, stderr=subprocess.DEVNULL, timeout=30, check=False)
        output.seek(0)
        while chunk := output.read(64 * 1024):
            digest.update(chunk)
            total += len(chunk)
            prefix.extend(chunk[:max(0, MAX_STATUS - len(prefix))])
    result = {"schema_version": 1, "phase": phase, "git_exit_code": completed.returncode,
              "status_raw_sha256": digest.hexdigest(), "status_raw_bytes": total,
              "changed": total != 0, "entries": [], "truncated": total > MAX_STATUS}
    chunks = bytes(prefix).split(b"\0")
    # Ignore an incomplete last record when the captured sample is truncated.
    chunks.pop()
    position = 0
    while position < len(chunks) and len(result["entries"]) < MAX_ENTRIES:
        record = chunks[position]
        position += 1
        if len(record) < 4 or record[2:3] != b" ":
            result["malformed_status"] = True
            break
        state = record[:2].decode("ascii", "backslashreplace")
        entry = {"status": state, **path_record(root, record[3:])}
        if "R" in state or "C" in state:
            if position >= len(chunks):
                result["truncated"] = True
                break
            entry["original"] = path_record(root, chunks[position])
            position += 1
        result["entries"].append(entry)
    result["truncated"] |= position < len(chunks)
    return result


def emit(root, phase):
    try:
        result = readback(root, phase)
    except (OSError, subprocess.SubprocessError):
        result = {"schema_version": 1, "phase": phase, "diagnostic_failed": True}
    # ensure_ascii escapes control/non-UTF8 path bytes; no contents/environment.
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")), flush=True)
    return int(result.get("diagnostic_failed", False) or result.get("changed", True)
               or result.get("git_exit_code", 1) != 0 or result.get("malformed_status", False))


def guarded(root, phase, command, cwd, timeout=4800):
    before = emit(root, phase + "-before")
    code = before
    try:
        if not before:
            code = subprocess.run(command, cwd=cwd, check=False, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        code = 124
    except OSError:
        code = 127
    finally:
        after = emit(root, phase + "-finally")
    # A dirty readback fails a successful build, but never replaces its failure.
    return code if code else after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--phase", required=True)
    parser.add_argument("--cwd", type=Path)
    parser.add_argument("--timeout", type=int, default=4800)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.phase or len(args.phase) > 64 or not all(c.isascii() and (c.isalnum() or c in "-_") for c in args.phase):
        parser.error("phase must be a bounded ASCII label")
    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    root = args.root.resolve()
    if command:
        if not 1 <= args.timeout <= 4800:
            parser.error("timeout must be within 1..4800 seconds")
        return guarded(root, args.phase, command, args.cwd or root, args.timeout)
    return emit(root, args.phase)


if __name__ == "__main__":
    raise SystemExit(main())
