#!/usr/bin/env python3
"""Run real retained 0.7 RC server bytes against the current schema CLI.

Only hosted native runners may execute this experiment. It preserves the old
release's pinned manifest/package and uses private, disposable deployments.
The seeded accounting/revocation records are fixtures, not enrolled devices.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import tempfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OLD_SOURCE = "82f1c8dfb31bdf0872ea7430b5608e205c1cbb08"
OLD_SCHEMA = 25
MANIFEST_SHA256 = "2d5a7768424f6cc2ea8875ba2b8cb8fb21ff360911b084ed4a95e2bc07fd793c"
OLD_PACKAGES = {
    "x86_64": ("x64", "517818a8ad3fbd737d9e4d01529229887465c050b5afe5317929cc776e789e5a"),
    "aarch64": ("arm64", "91ef3c6ab8e3a00e98a21ecfe8bcdff500e0a785c75ac15cc6d81c0aaf39514a"),
}
ACCOUNT = "10000000-0000-4000-8000-000000000001"
REVOKED = "10000000-0000-4000-8000-000000000002"
LATER_REVOKED = "10000000-0000-4000-8000-000000000003"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def download(name, destination, expected):
    request = urllib.request.Request("https://github.com/ZHanry/NestLink/releases/download/v0.7.0-rc.1/" + name,
                                     headers={"User-Agent": "NestLink-explicit-upgrade-qualification"})
    with urllib.request.urlopen(request, timeout=90) as incoming, destination.open("xb") as outgoing:
        total = 0
        while chunk := incoming.read(1024 * 1024):
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise ValueError("retained old artifact exceeds bounded download")
            outgoing.write(chunk)
    if sha(destination) != expected:
        raise ValueError("retained old artifact differs from the reviewed public release")


def facts(directory):
    with sqlite3.connect(directory / "control.sqlite3") as database:
        return {
            "schema": database.execute("PRAGMA user_version").fetchone()[0],
            "epoch": database.execute("SELECT security_epoch FROM deployment WHERE singleton=1").fetchone()[0],
            "revoked": database.execute("SELECT revoked FROM devices WHERE id=?", (REVOKED,)).fetchone()[0],
            "later_revoked": database.execute("SELECT revoked FROM devices WHERE id=?", (LATER_REVOKED,)).fetchone()[0],
            "spent": database.execute("SELECT spent_bytes FROM service_quota_ledgers WHERE scope_kind='account' AND scope_key=?", (ACCOUNT,)).fetchone()[0],
            "quota_fenced": database.execute("SELECT restore_fenced FROM service_quota_settings WHERE singleton=1").fetchone()[0],
        }


def qualify(args):
    if platform.system() != "Linux" or os.geteuid() == 0 or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("upgrade qualification requires an ordinary hosted native Linux runner")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if source != os.environ["GITHUB_SHA"] or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT).strip():
        raise ValueError("upgrade experiment must use the exact clean workflow SHA")
    match = re.search(r"pub const SCHEMA_VERSION: i32 = ([0-9]+);", (ROOT / "crates/storage/src/lib.rs").read_text(encoding="utf-8"))
    current_schema = int(match[1])
    if current_schema <= OLD_SCHEMA:
        raise ValueError("the reviewed old/current schema pair no longer requires migration")
    architecture, package_hash = OLD_PACKAGES[platform.machine()]
    args.output.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": 1, "status": "failed", "source_revision": source,
              "build_provenance": {"workflow": os.environ["GITHUB_WORKFLOW_REF"], "run_id": os.environ["GITHUB_RUN_ID"],
                                   "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"], "cargo_lock_sha256": sha(ROOT / "Cargo.lock"),
                                   "current_server_sha256": sha(args.current)},
              "execution_provenance": {"runner_environment": os.environ["RUNNER_ENVIRONMENT"],
                                       "machine": platform.machine(), "ordinary_uid": os.geteuid()},
              "old_release": {"tag": "v0.7.0-rc.1", "source_revision": OLD_SOURCE,
                              "manifest_sha256": MANIFEST_SHA256, "package_sha256": package_hash},
              "old_schema": OLD_SCHEMA, "current_schema": current_schema, "commands": [],
              "limitations": ["Real retained Linux server executables and CLI schema transactions only; no mixed-client or node transport negotiation claim",
                              "Quota/revocation rows are owned SQLite fixtures; live authorization and accounting use their separate regression suites",
                              "Unsigned old/new development bytes; certificate-backed installed upgrades and physical targets remain pending"]}

    def command(name, argv, success=True):
        completed = subprocess.run([str(item) for item in argv], cwd=ROOT, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180, check=False)
        path = args.output / (name + ".log")
        path.write_bytes(completed.stdout)
        report["commands"].append({"name": name, "return_code": completed.returncode,
                                   "log": path.name, "sha256": sha(path)})
        if (completed.returncode == 0) != success:
            raise ValueError("unexpected real CLI result: " + name)
        return completed.stdout

    try:
        manifest_path = args.output / "old-candidate-build-manifest.json"
        download("candidate-build-manifest.json", manifest_path, MANIFEST_SHA256)
        manifest = json.loads(manifest_path.read_bytes())
        name = "NestLink-candidate-linux-" + architecture + "-server.deb"
        old_item = next(item for item in manifest["artifacts"] if item["role"] == "linux-" + architecture + "-server")
        if manifest["source_revision"] != OLD_SOURCE or old_item["sha256"] != package_hash or old_item["source_revision"] != OLD_SOURCE:
            raise ValueError("old package does not belong to its retained source cohort")
        with tempfile.TemporaryDirectory(prefix="nestlink-actual-upgrade-") as temporary:
            private = Path(temporary)
            package = private / name
            download(name, package, package_hash)
            extracted = private / "old-extracted"
            command("extract-pinned-old-package", ["dpkg-deb", "--extract", package, extracted])
            old = extracted / "opt/nestlink-rc/server/nestlink-server"
            report["old_release"]["server_sha256"] = sha(old)
            command("old-version", [old, "--version"])
            command("current-version", [args.current, "--version"])
            deployment = private / "deployment"
            init = ["init", "--directory", deployment, "--management-origin", "http://127.0.0.1:28740", "--allow-loopback-http"]
            command("old-init", [old, *init])
            config = deployment / "server.toml"
            old_configuration = config.read_bytes()
            deployment_id = tomllib.loads(config.read_text())["deployment_id"]
            with sqlite3.connect(deployment / "control.sqlite3") as database:
                database.execute("PRAGMA foreign_keys=ON")
                database.execute("INSERT INTO accounts(id,name) VALUES(?,'upgrade-fixture')", (ACCOUNT,))
                for device, byte, revoked in ((REVOKED, b"a", 1), (LATER_REVOKED, b"b", 0)):
                    database.execute("INSERT INTO devices(id,account_id,key_sha256,revoked) VALUES(?,?,?,?)", (device, ACCOUNT, byte * 32, revoked))
                database.execute("INSERT INTO service_quota_limits VALUES('account',?,1000000,1)", (ACCOUNT,))
                database.execute("INSERT INTO service_quota_ledgers VALUES('account',?,4173)", (ACCOUNT,))
            original = facts(deployment)
            if original["schema"] != OLD_SCHEMA:
                raise ValueError("retained 0.7 RC did not create its reviewed source schema")
            keys = {name: sha(deployment / name) for name in ("vault.key", "permit.key")}
            command("old-check-old-schema", [old, "check", "--config", config])
            command("new-refuses-old-schema", [args.current, "check", "--config", config], success=False)
            if facts(deployment) != original:
                raise ValueError("refused new business entry migrated or changed old state")
            password = private / "password"
            password.write_bytes(os.urandom(32).hex().encode())
            password.chmod(0o600)
            migration = [args.current, "migrate", "--config", config, "--from-schema", str(OLD_SCHEMA), "--to-schema", str(current_schema), "--password-file", password]
            first = json.loads(command("fenced-forward-migration", [*migration, "--backup", private / "first.nl15", "--defer-admission"]))
            command("new-business-refuses-fenced-transaction", [args.current, "check", "--config", config], success=False)
            command("explicit-pre-admission-rollback", [args.current, "recover-migration", "--directory", deployment, "--transaction", first["transaction_id"], "--rollback"])
            if facts(deployment) != original:
                raise ValueError("pre-admission rollback changed original debts or authority")
            command("old-works-after-exact-rollback", [old, "check", "--config", config])
            second = json.loads(command("admitted-forward-migration", [*migration, "--backup", private / "second.nl15"]))
            migrated = facts(deployment)
            if migrated != {**original, "schema": current_schema} or any(sha(deployment / name) != expected for name, expected in keys.items()):
                raise ValueError("forward migration changed identity, epoch, revocation or cumulative debt")
            command("new-check-new-schema", [args.current, "check", "--config", config])
            # Current serialization can add optional config fields unknown to
            # the old strict parser. Reuse its exact original configuration so
            # this negative case actually reaches the old database schema gate.
            old_config = deployment / "old-check.toml"
            old_config.write_bytes(old_configuration)
            old_config.chmod(0o600)
            command("new-accepts-old-config-new-schema", [args.current, "check", "--config", old_config])
            command("old-refuses-new-schema", [old, "check", "--config", old_config], success=False)
            with sqlite3.connect(deployment / "control.sqlite3") as database:
                database.execute("UPDATE devices SET revoked=1 WHERE id=?", (LATER_REVOKED,))
                database.execute("UPDATE service_quota_ledgers SET spent_bytes=9111 WHERE scope_kind='account' AND scope_key=?", (ACCOUNT,))
            advanced = facts(deployment)
            command("post-admission-rollback-refused", [args.current, "recover-migration", "--directory", deployment, "--transaction", second["transaction_id"], "--rollback"], success=False)
            if facts(deployment) != advanced:
                raise ValueError("old transaction resurrected revoked authority or cleared admitted debt")
            restored = private / "restored"
            command("restore-old-backup-new-directory", [args.current, "restore", "--input", private / "second.nl15", "--directory", restored,
                                                       "--expected-deployment", deployment_id, "--password-file", password])
            restored_facts = facts(restored)
            if restored_facts["epoch"] == original["epoch"] or restored_facts["quota_fenced"] != 1 or restored_facts["revoked"] != 1:
                raise ValueError("old backup was restored without a new epoch and cumulative quota fence")
            report["facts"] = {"original": original, "migrated": migrated, "post_admission": advanced, "restored": restored_facts}
        report["status"] = "passed"
    finally:
        report["files"] = [{"path": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
                           for path in sorted(args.output.iterdir()) if path.is_file()]
        (args.output / "network-upgrade-evidence.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"source_revision": source, "architecture": architecture, "status": report["status"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    qualify(parser.parse_args())
