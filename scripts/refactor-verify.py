"""Run the v15 development checks and retain exact source/log evidence.

Configure cargo/rustup in PATH first. --offline-audit requires separately
verifying the recorded advisory-db commit against RustSec's current main.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def stamp():
    return datetime.now(timezone(timedelta(hours=8))).isoformat()


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args]).decode("utf-8").strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-executable", default="cargo-deny")
    parser.add_argument("--offline-audit", action="store_true")
    parser.add_argument("--advisory-revision", required=True)
    parser.add_argument("--output", type=Path, default=Path("docs/refactor/verification.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    logs = root / "artifacts/core-verification" / datetime.now().strftime("%Y%m%d-%H%M%S")
    logs.mkdir(parents=True, exist_ok=True)
    commands = [
        ("format", ["cargo", "fmt", "--all", "--exclude", "fast-socks5", "--", "--check"]),
        ("clippy", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"]),
        ("security-tests", ["cargo", "test", "--workspace", "--locked"]),
        ("acceptance-tool-tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests/refactor", "-p", "test_*.py"]),
        ("wasm-contract", ["cargo", "check", "--locked", "--target", "wasm32-unknown-unknown", "-p", "nestlink-protocol", "-p", "nestlink-policy", "-p", "nestlink-connectivity", "-p", "nestlink-sdk"]),
        ("contract-and-workspace", ["cargo", "xtask", "check"]),
        ("default-policy", ["cargo", "xtask", "policy", "config/network-policy.default.json"]),
        ("self-hosted-relay-policy", ["cargo", "xtask", "policy", "config/network-policy.self-hosted-relay.json"]),
        ("dependencies", [args.audit_executable, "--all-features", "--locked"] + (["--offline"] if args.offline_audit else []) + ["check", "--hide-inclusion-graph"]),
    ]
    source_paths = list(root.glob("crates/**/*")) + list(root.glob("protocol-spec/*")) + list(root.glob("xtask/**/*")) + list(root.glob("apps/server/**/*")) + list(root.glob("packaging/**/*"))
    source_paths += [root / f for f in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "deny.toml", "compatibility.json", ".github/workflows/rust-core.yml", "scripts/refactor-verify.py", "scripts/refactor-network-events.py", "scripts/refactor-x11-input.py", "scripts/refactor-signatures.py", "scripts/refactor-test-vectors.py")]
    source_paths += list(root.glob("tests/refactor/*.py"))
    source_paths += list(root.glob("scripts/refactor-*.py"))
    source_paths += [root / "scripts/test-vp8-boundary-sanitizer.sh", root / "scripts/test-pipewire-audio-sanitizer.sh", root / "docs/refactor/native-codecs.lock.json", root / "docs/refactor/source-ledger.json"]
    source_paths += list(root.glob("tests/vectors/*")) + list(root.glob("config/*"))
    hashes = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths if p.is_file()}
    result = {"schema_version": 1, "scope": "security, SDK native/WASM, signaling, control HTTP, QUIC/TLS/WSS, session lifecycle and platform input/capture development checks; not product acceptance", "timezone": "Asia/Shanghai",
        "source_revision": git(root, "rev-parse", "HEAD"), "source_tree_dirty": bool(git(root, "status", "--porcelain")),
        "source_files": [{"path": path, "sha256": digest} for path, digest in sorted(hashes.items())], "advisory_database_revision": args.advisory_revision,
        "advisory_fetch_mode": "offline against independently verified current commit" if args.offline_audit else "online",
        "started_at": stamp(), "checks": []}
    for name, command in commands:
        started = stamp()
        output = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        log = logs / (name + ".log")
        log.write_bytes(output.stdout)
        result["checks"].append({"name": name, "command": command, "started_at": started, "finished_at": stamp(),
            "exit_code": output.returncode, "log": log.relative_to(root).as_posix(), "log_sha256": hashlib.sha256(output.stdout).hexdigest()})
        print(name + ": " + ("passed" if output.returncode == 0 else "FAILED"), flush=True)
        if output.returncode:
            print(output.stdout.decode("utf-8", errors="replace"), flush=True)
            break
    result["finished_at"] = stamp()
    result["all_checks_passed"] = len(result["checks"]) == len(commands) and all(c["exit_code"] == 0 for c in result["checks"])
    target = root / args.output
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    if not result["all_checks_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
