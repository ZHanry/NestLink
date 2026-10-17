#!/usr/bin/env python3
"""Preserve the final clean source as a small independent archive supplement.

prepare creates a standalone Git bundle, restores it in a fresh bare store and
checks every ref, the final commit and strict Git object closure. It removes only
its own temporary restore store afterwards. No old 16 GB assets are recopied.
Other actions upload/verify this supplement; none rename or delete repositories.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import urllib.error
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("final_source_archive_transfer", ROOT / "scripts/refactor-history-archive-publish.py")
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


def command(args):
    result = subprocess.run([str(item) for item in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    A.require(result.returncode == 0, "Source preservation command failed: " + str(args[0]))
    return result.stdout.decode("utf-8").strip()


def plan_items(plan, path):
    checksum = A.digest(path)
    return plan["files"] + [{"asset_name": "history-archive-plan-" + checksum + ".json", "path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": checksum, "role": "archive-plan"}]


def prepare(args):
    revision = command(["git", "-C", ROOT, "rev-parse", "HEAD"])
    A.require(re.fullmatch(r"[0-9a-f]{40}", revision) and revision == args.expected_source, "Expected source differs from HEAD")
    A.require(not command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=all"]), "Final source must include every untracked source file in a clean commit")
    A.require(not args.directory.exists(), "Final source output directory must be create-new")
    args.directory.mkdir(parents=True)
    bundle = args.directory / ("NestLink-final-source-" + revision[:12] + ".bundle")
    restore = args.directory / "restore.git"
    command(["git", "-C", ROOT, "bundle", "create", bundle.resolve(), "--all", "HEAD"])
    heads = {}
    for line in command(["git", "bundle", "list-heads", bundle.resolve()]).splitlines():
        oid, name = line.split(" ", 1)
        if name != "HEAD":
            heads[name] = oid
    A.require(heads and revision in heads.values(), "Final source is absent from the advertised bundle refs")
    command(["git", "init", "--bare", restore.resolve()])
    command(["git", "-C", restore.resolve(), "fetch", "--no-tags", "--no-recurse-submodules", bundle.resolve(), "+refs/*:refs/*"])
    restored = {}
    for line in command(["git", "-C", restore.resolve(), "for-each-ref", "--format=%(objectname) %(refname)"]).splitlines():
        oid, name = line.split(" ", 1)
        restored[name] = oid
    A.require(restored == heads, "Independent restore changed the final source ref map")
    A.require(command(["git", "-C", restore.resolve(), "cat-file", "-t", revision]) == "commit", "Final source commit is absent after independent restoration")
    objects = command(["git", "-C", restore.resolve(), "rev-list", "--objects", "--missing=print", "--all"])
    A.require(not any(line.startswith("?") for line in objects.splitlines()), "Final bundle has missing Git objects")
    command(["git", "-C", restore.resolve(), "fsck", "--full", "--strict", "--no-reflogs", "--no-dangling"])
    tree = command(["git", "-C", restore.resolve(), "rev-parse", revision + "^{tree}"])
    bundle_record = A.record(bundle, bundle.name, "final-source-bundle")
    report = {"schema_version": 1, "purpose": "final-source-preservation", "source_revision": revision, "source_tree": tree, "bundle": {"path": str(bundle.resolve()), "bytes": bundle_record["bytes"], "sha256": bundle_record["sha256"]}, "refs": heads, "restored_refs": len(restored), "bundle_standalone_verified": True, "restored_ref_map_verified": True, "strict_fsck_passed": True, "gitlink_scope": "Git object closure preserves gitlink references; this does not recover the three documented unavailable external historical hbb_common commits.", "user_full_functional_acceptance": "pending"}
    report_path = args.directory / "final-source-report.json"
    A.create_json(report_path, report)
    plan = {"schema_version": 1, "purpose": "final-source-archive", "repository_node_id": A.P.REPOSITORY_ID, "source_revision": revision, "tag_target": revision, "tag": "history-archive-final-" + revision[:12], "files": [bundle_record, A.record(report_path, "final-source-report.json", "final-source-report")], "final_product_source_preserved": True, "user_full_functional_acceptance": "pending"}
    A.create_json(args.plan, plan)
    # This directory was created above solely for the independent restore.
    # Verify its exact absolute location before recursive cleanup on Windows.
    expected_restore = args.directory.resolve() / "restore.git"
    A.require(restore.resolve() == expected_restore and restore.parent.resolve() == args.directory.resolve() and not restore.is_symlink(), "Refusing cleanup outside the owned restore directory")
    def remove_owned_readonly(function, path, error):
        # Git pack files are read-only on Windows. Retry only inside the fresh
        # restore store after validating the failing path; never widen cleanup.
        A.require(isinstance(error[1], PermissionError) and Path(path).resolve().is_relative_to(expected_restore), "Refusing cleanup retry outside the owned restore directory")
        Path(path).chmod(stat.S_IREAD | stat.S_IWRITE)
        function(path)
    shutil.rmtree(restore, onerror=remove_owned_readonly)
    return {"status": "prepared", "plan": str(args.plan), "source_revision": revision, "bytes": sum(item["bytes"] for item in plan["files"]), "refs": len(heads), "temporary_restore_removed": True, "remote_mutation_performed": False}


def validate(plan):
    A.require(plan.get("schema_version") == 1 and plan.get("purpose") == "final-source-archive" and plan.get("repository_node_id") == A.P.REPOSITORY_ID, "Unexpected final source archive identity")
    revision = plan.get("source_revision", "")
    A.require(re.fullmatch(r"[0-9a-f]{40}", revision) and plan.get("tag_target") == revision and plan.get("tag") == "history-archive-final-" + revision[:12], "Final source archive tag differs from its source")
    A.require(plan.get("final_product_source_preserved") is True and plan.get("user_full_functional_acceptance") == "pending", "Source preservation must not claim user acceptance")
    A.require(isinstance(plan.get("files"), list) and len(plan["files"]) == 2 and {item["role"] for item in plan["files"]} == {"final-source-bundle", "final-source-report"}, "Final source bundle/report pair is required")
    for item in plan["files"]:
        A.require(A.SAFE.fullmatch(item.get("asset_name", "")) and A.HEX.fullmatch(item.get("sha256", "")) and type(item.get("bytes")) is int and 0 < item["bytes"] <= 2 * 1024**3, "Invalid final source file descriptor")


def verify_published_plan(github, repository, plan, receipt, plan_hash, plan_bytes):
    """Verify the complete fixed archive mapping without redundant blob downloads."""
    if plan.get("purpose") == "history-archive":
        A.validate(plan)
    else:
        validate(plan)
    A.require(receipt.get("purpose") in ("history-archive-receipt", "final-source-archive-receipt") and receipt.get("repository_node_id") == A.P.REPOSITORY_ID and receipt.get("plan_sha256") == plan_hash and receipt.get("tag") == plan["tag"] and receipt.get("durable_remote_preservation_verified") is True, "Archive receipt is incomplete or refers to different fixed bytes")
    A.P.identity(github, repository, A.P.REPOSITORY_ID)
    release = github.request("GET", "/repos/" + repository + "/releases/tags/" + plan["tag"])
    A.require(release.get("id") == receipt.get("release_id") and release.get("draft") is False and release.get("tag_name") == plan["tag"], "The archived material must be publicly published at its fixed Release identity")
    A.require(A.P.verify_tag(github, repository, plan["tag_target"], plan["tag"]), "Published archive tag changed")
    expected = {item["asset_name"]: item for item in plan["files"]}
    plan_name = "history-archive-plan-" + plan_hash + ".json"
    expected[plan_name] = {"asset_name": plan_name, "bytes": plan_bytes, "sha256": plan_hash, "role": "archive-plan"}
    recorded = {item["asset_name"]: item for item in receipt.get("uploads", [])}
    A.require(len(recorded) == len(receipt.get("uploads", [])) and set(recorded) == set(expected), "Archive receipt does not cover every expected file")
    current = github.pages("/repos/" + repository + "/releases/" + str(release["id"]) + "/assets")
    observed = {item["name"]: item for item in current}
    A.require(len(observed) == len(current), "Archive asset names collide")
    for name, wanted in expected.items():
        saved, actual = recorded[name], observed.get(name)
        A.require(actual is not None and actual.get("id") == saved.get("asset_id") and (saved.get("bytes"), saved.get("sha256"), saved.get("role")) == (wanted["bytes"], wanted["sha256"], wanted["role"]), "Archive identities changed after the fixed receipt")
        checksum, _ = A.remote_digest(github, repository, actual, wanted["bytes"])
        A.require(checksum == wanted["sha256"], "Archived remote bytes differ from their fixed mapping")
    return {"release_id": release["id"], "tag": plan["tag"], "files": len(expected), "bytes": sum(item["bytes"] for item in expected.values())}


def transfer(args, github=None):
    plan_hash = A.digest(args.plan)
    plan = A.H.bounded_json(args.plan)
    validate(plan)
    github = github or A.GitHub(A.github_token())
    A.P.identity(github, args.repository, A.P.REPOSITORY_ID)
    main = github.request("GET", "/repos/" + args.repository + "/git/ref/heads/main")["object"]
    A.require(main.get("sha") == plan["source_revision"] and main.get("type") == "commit", "Remote main differs from the final source archive")
    tag_exists = A.P.verify_tag(github, args.repository, plan["source_revision"], plan["tag"])
    try:
        release = github.request("GET", "/repos/" + args.repository + "/releases/tags/" + plan["tag"])
    except A.P.Missing:
        release = None
    items = plan_items(plan, args.plan)
    A.require(A.digest(args.plan) == plan_hash, "Final source plan changed during verification")
    if args.action != "verify":
        for item in items:
            A.require(A.digest(Path(item["path"])) == item["sha256"], "Final source input changed")
        if not tag_exists:
            github.request("POST", "/repos/" + args.repository + "/git/refs", value={"ref": "refs/tags/" + plan["tag"], "sha": plan["source_revision"]})
        if release is None:
            release = github.request("POST", "/repos/" + args.repository + "/releases", value={"tag_name": plan["tag"], "target_commitish": plan["source_revision"], "name": "NestLink final source preservation", "draft": True, "prerelease": True, "make_latest": "false", "body": "Standalone final-source Git bundle with independent restoration and strict Git object checks. Final user product acceptance remains pending. The separate legacy archive preserves original source identities and older Release bytes."})
    A.require(release is not None and type(release.get("id")) is int and release["id"] > 0 and release.get("tag_name") == plan["tag"], "Final source archive Release is absent or changed")
    release_id = release["id"]
    existing = {item["name"]: item for item in github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")}
    verified = []
    for item in items:
        actual = existing.get(item["asset_name"])
        if actual is None:
            A.require(args.action != "verify" and release.get("draft") is True, "A fixed final-source archive asset is missing")
            with Path(item["path"]).open("rb") as stream:
                actual = github.request("POST", "/repos/" + args.repository + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(item["asset_name"], safe=""), upload=True, stream=stream, length=item["bytes"])
        actual = github.request("GET", "/repos/" + args.repository + "/releases/assets/" + str(actual["id"]))
        checksum, method = A.remote_digest(github, args.repository, actual, item["bytes"])
        A.require(actual.get("name") == item["asset_name"] and checksum == item["sha256"], "Final source archive conflict; no overwrite is allowed")
        verified.append({"asset_name": item["asset_name"], "asset_id": actual["id"], "bytes": item["bytes"], "sha256": checksum, "role": item["role"], "verification": method})
    A.require(A.P.verify_tag(github, args.repository, plan["source_revision"], plan["tag"]), "Final source tag changed during upload")
    final_main = github.request("GET", "/repos/" + args.repository + "/git/ref/heads/main")["object"]
    A.require(final_main.get("sha") == plan["source_revision"] and final_main.get("type") == "commit", "Remote main changed during final source preservation")
    final_assets = {item["name"]: item for item in github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")}
    A.require(all(name in final_assets and final_assets[name].get("id") == item["asset_id"] and final_assets[name].get("size") == item["bytes"] and final_assets[name].get("state") == "uploaded" for item in verified for name in (item["asset_name"],)), "Final source asset identities changed after verification")
    if args.action == "publish" and release.get("draft") is True:
        release = github.request("PATCH", "/repos/" + args.repository + "/releases/" + str(release_id), value={"draft": False, "prerelease": True, "make_latest": "false"})
    return {"schema_version": 1, "purpose": "final-source-archive-receipt", "status": "verified" if args.action == "verify" else "published" if release.get("draft") is False else "draft-uploaded", "repository": args.repository, "repository_node_id": A.P.REPOSITORY_ID, "release_id": release_id, "tag": plan["tag"], "source_revision": plan["source_revision"], "plan_sha256": plan_hash, "durable_remote_preservation_verified": True, "final_product_source_preserved": True, "user_full_functional_acceptance": "pending", "uploads": verified, "remote_mutation_performed": args.action != "verify", "repository_finalization_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "upload-draft", "publish"))
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--expected-source")
    parser.add_argument("--repository", choices=sorted(A.P.ALLOWED_REPOSITORIES), default="ZHanry/home-tunnel")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            A.require(args.directory is not None and args.expected_source and not args.plan.exists(), "prepare requires a new directory/plan and exact expected-source")
            result = prepare(args)
        else:
            A.require(args.output is not None and not args.output.exists(), "A create-new receipt path is required")
            result = transfer(args)
            A.create_json(args.output, result)
        print(json.dumps({key: value for key, value in result.items() if key != "uploads"}))
        return 0
    except (ValueError, OSError, TypeError, KeyError, A.P.Missing, subprocess.SubprocessError, urllib.error.URLError) as error:
        print("Final source archive refused: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
