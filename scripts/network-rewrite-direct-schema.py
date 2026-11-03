#!/usr/bin/env python3
"""Execute an unchanged pinned schema-50 Store against a real schema-51 lineage.

Runs only in hosted network-upgrade Actions. Private database, identities and
credentials never enter the artifact; command receipts and hashes do.
"""
from __future__ import annotations
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OLD_SOURCE = "c5893625ebbe3b50406810bd7eb34c60cbbea849"
ROLE = "network_paths::direct_recovery::schema_fixture_role"
SPEC = importlib.util.spec_from_file_location("direct_schema_evidence", ROOT / "scripts/network-rewrite-ci.py")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
EVIDENCE.WORKFLOW_PATH = ".github/workflows/network-upgrade.yml"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def snapshot(directory):
    facts = {}
    for path in [directory, *sorted(directory.rglob("*"))]:
        require(not path.is_symlink(), "unexpected private fixture symlink")
        status = path.stat()
        facts[path.relative_to(directory).as_posix()] = {
            "mode": stat.S_IMODE(status.st_mode), "uid": status.st_uid, "gid": status.st_gid,
            "kind": "directory" if path.is_dir() else "file",
            **({"bytes": status.st_size, "sha256": EVIDENCE.sha256_file(path)} if path.is_file() else {}),
        }
    return facts


def artifact(log, target, suffix):
    matches = []
    for line in log.read_text(errors="replace").splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == target:
            paths = [item.get("executable")] if suffix == "executable" else item.get("filenames", [])
            matches.extend(Path(path) for path in paths if path and (suffix == "executable" or path.endswith(suffix)))
    unique = sorted(set(matches))
    require(len(unique) == 1, "exactly one actual Cargo artifact is required for " + target)
    return unique[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = EVIDENCE.validate_actions_environment(os.environ)
    require(identity["runner"]["os"] == "Linux" and os.geteuid() != 0, "ordinary hosted Linux required")
    args.output = EVIDENCE.validate_output_path(args.output, ROOT, Path(os.environ["RUNNER_TEMP"]))
    args.output.mkdir(parents=True, exist_ok=False)
    commands = []
    before = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
    require(before["exact_source"] and before["clean"], "exact clean current source required")
    report = {"schema_version": 1, "passed": False, "failure": None,
              "build_provenance": identity, "source_before": before, "commands": commands,
              "old_source_revision": OLD_SOURCE, "old_store_source_modified": False,
              "acceptance_claims": [], "limitations": ["Real schema-50 Store library and schema-51 direct lineage only; no installed upgrade or complete acceptance claim"]}

    def run(name, argv, cwd=ROOT, timeout=1200):
        entry = EVIDENCE.run_command(name, [str(arg) for arg in argv], cwd, args.output, commands, timeout)
        require(entry["return_code"] == 0 and not entry["timed_out"], "original command failed: " + name)
        return args.output / entry["log"]

    try:
        run("build-current-storage-fixture", ["cargo", "test", "--locked", "-p", "nestlink-storage", "--test", "control", "--no-run", "--message-format=json"])
        executable = artifact(args.output / "build-current-storage-fixture.log", "control", "executable")
        with tempfile.TemporaryDirectory(prefix="nestlink-direct-schema-", dir=os.environ["RUNNER_TEMP"]) as temporary:
            private = Path(temporary)
            fixture = private / "fixture"
            fixture.mkdir(mode=0o700)
            deployment = "10000000-0000-4000-8000-" + secrets.token_hex(6)
            env = ["env", "NESTLINK_DIRECT_SCHEMA_DIRECTORY=" + str(fixture),
                   "NESTLINK_DIRECT_SCHEMA_DEPLOYMENT=" + deployment]
            run("create-real-current-lineage", [*env, "NESTLINK_DIRECT_SCHEMA_MODE=create", executable, "--ignored", "--exact", ROLE, "--nocapture"])
            with sqlite3.connect("file:" + str(fixture / "control.sqlite3") + "?mode=ro", uri=True) as database:
                require(database.execute("PRAGMA user_version").fetchone()[0] == 51, "fixture is not actual schema 51")
                require(database.execute("SELECT count(*) FROM network_direct_recovery_lineage").fetchone()[0] == 1, "real dual-signed child lineage missing")
            (fixture / "server.toml").write_text('schema_fixture = "owned-direct-lineage"\n')
            (fixture / "server.toml").chmod(0o600)
            old = private / "old-source"
            run("checkout-exact-schema50", ["git", "worktree", "add", "--detach", old, OLD_SOURCE], timeout=120)
            try:
                report["old_source_before"] = EVIDENCE.source_snapshot(old, OLD_SOURCE)
                require(report["old_source_before"]["clean"], "old Store source must be unchanged")
                old_target = private / "old-build"
                build = run("build-unchanged-old-storage", ["env", "CARGO_TARGET_DIR=" + str(old_target), "cargo", "build", "--locked", "-p", "nestlink-storage", "--lib", "--message-format=json"], old)
                library = artifact(build, "nestlink_storage", ".rlib")
                probe = private / "old-store-probe"
                native = [argument for path in sorted((old_target / "debug/build").glob("*/out")) for argument in ["-L", "native=" + str(path)]]
                run("link-current-probe-to-unchanged-old-library", ["rustc", "--edition=2024", "--crate-name", "nestlink_direct_schema_probe", ROOT / "scripts/fixtures/direct-store-schema-probe.rs", "--extern", "nestlink_storage=" + str(library), "-L", "dependency=" + str(old_target / "debug/deps"), *native, "-o", probe])
                report["old_library_sha256"] = EVIDENCE.sha256_file(library)
                report["old_probe_sha256"] = EVIDENCE.sha256_file(probe)
                original = snapshot(fixture)
                for entry in ("existing", "open"):
                    log = run("old-store-" + entry + "-refuses-real-lineage", [probe, entry, fixture / "control.sqlite3", deployment], timeout=60)
                    require("OLD_SCHEMA50_STORE_REJECTED_NEW_SCHEMA" in log.read_text(), "old Store did not reach the exact unsupported-schema failure")
                    require(snapshot(fixture) == original, "old refusal changed database/configuration/ownership/permissions or created a sidecar")
                report["both_old_store_entries_refused_without_writes"] = True
                report["refusal_fixture_file_hashes_and_permissions"] = original
                report["old_source_after"] = EVIDENCE.source_snapshot(old, OLD_SOURCE)
                require(report["old_source_before"] == report["old_source_after"], "old Store source or lock changed")
                run("current-reopens-and-enforces-ancestor-revocation", [*env, "NESTLINK_DIRECT_SCHEMA_MODE=verify", executable, "--ignored", "--exact", ROLE, "--nocapture"])
            finally:
                run("remove-owned-old-source", ["git", "worktree", "remove", old], timeout=120)
        report["source_after"] = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
        require(report["source_after"] == before, "current source changed during qualification")
        report["passed"] = True
    except Exception as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        report["artifact_files"] = EVIDENCE.artifact_files(args.output)
        (args.output / "direct-schema-evidence.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
