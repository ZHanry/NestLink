#!/usr/bin/env python3
"""Deliver fixed v15 candidate and preserved history before the user's final tests.

The verify action is read-only. upload-draft and publish upload unchanged bytes
to the approved main repository. Publication is always a GitHub prerelease and
never authorizes production updates. Pending user tests and signing identities
remain explicit. This tool does not rename repositories or delete anything.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


HANDOFF = module("repository_delivery_handoff", "scripts/refactor-release-handoff.py")
ARCHIVE = module("repository_delivery_archives", "scripts/refactor-final-source-archive.py")
# The live client raises this exact publisher's Missing class. Loading a
# second copy would make absent tags/releases bypass the intended handlers.
PUBLISH = ARCHIVE.A.P
TAG = "v15.0.0-preview.1"
ARCHIVE_ROLES = frozenset(("history-archive-plan", "history-archive-receipt", "final-source-archive-plan", "final-source-archive-receipt"))
REQUIRED_CASES = (HANDOFF.REQUIRED_CASES - {"72-hour-soak"}) | {"90-minute-soak"}
COMPLETION = frozenset(("implementation", "targeted_verification", "release_bytes_frozen", "legacy_preservation_review", "user_full_functional_acceptance"))
SIGNING = frozenset(("windows", "android", "linux_update", "oci"))
SIGNING_STATES = frozenset(("not-configured", "development-only", "unverified"))


def require(condition, message):
    PUBLISH.require(condition, message)


def validate(plan):
    HANDOFF.object_keys(plan, ("schema_version", "product", "purpose", "version", "source_revision", "repository_node_id", "completion", "signing", "artifacts", "acceptance_cases"))
    require(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["product"] == "NestLink-v15" and plan["purpose"] == "repository-delivery" and plan["version"] == "15.0.0", "Unexpected repository delivery identity")
    require(plan["repository_node_id"] == PUBLISH.REPOSITORY_ID and isinstance(plan["source_revision"], str) and re.fullmatch(r"[0-9a-f]{40}", plan["source_revision"]), "A fixed source commit and the approved repository identity are required")
    HANDOFF.object_keys(plan["completion"], COMPLETION)
    require(all(value == "passed" for key, value in plan["completion"].items() if key != "user_full_functional_acceptance"), "Implementation, targeted verification, frozen bytes and preservation review must be complete")
    require(plan["completion"]["user_full_functional_acceptance"] == "pending", "User-followup delivery must retain pending final user acceptance")
    HANDOFF.object_keys(plan["signing"], SIGNING)
    require(all(value in SIGNING_STATES for value in plan["signing"].values()), "This delivery route cannot assert verified production signing")
    require(isinstance(plan["acceptance_cases"], list), "The final user acceptance checklist is required")
    require(any(case.get("status") == "pending" for case in plan["acceptance_cases"] if isinstance(case, dict)), "The delivery checklist must identify outstanding user tests")
    require(all(isinstance(case, dict) and case.get("status") in ("passed", "pending") for case in plan["acceptance_cases"]), "A failed or invalid case cannot be delivered as pending")
    HANDOFF.validate_contents({**plan, "legacy_assets": []}, allowed_case_statuses=frozenset(("passed", "pending")), preservation_roles=ARCHIVE_ROLES, required_cases=REQUIRED_CASES)


def local_plan(args):
    plan_hash = HANDOFF.verify.sha256(args.plan)
    plan = HANDOFF.bounded_json(args.plan)
    validate(plan)
    revision = HANDOFF.verify.command(["git", "-C", ROOT, "rev-parse", "HEAD"]).decode().strip()
    require(revision == plan["source_revision"] and not HANDOFF.verify.command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=all"]).strip(), "Delivery requires the exact clean source commit, including all untracked source")
    require(not args.expected_source or args.expected_source == revision, "Requested source differs from the fixed delivery source")
    plan_relative = args.plan.resolve().relative_to(args.bundle.resolve()).as_posix()
    uploads = []
    for item in plan["artifacts"]:
        HANDOFF.fixed_file(args.bundle, item)
        uploads.append({"asset_name": item["id"] + "--" + Path(item["path"]).name, "local_path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"], "role": item["role"]})
    by_role = {item["role"]: item for item in plan["artifacts"]}
    archives = []
    for prefix in ("history", "final-source"):
        manifest_item = by_role[prefix + "-archive-plan"]
        manifest = HANDOFF.bounded_json(HANDOFF.fixed_file(args.bundle, manifest_item))
        receipt = HANDOFF.bounded_json(HANDOFF.fixed_file(args.bundle, by_role[prefix + "-archive-receipt"]))
        if prefix == "history":
            ARCHIVE.A.validate(manifest)
        else:
            ARCHIVE.validate(manifest)
            require(manifest["source_revision"] == revision and receipt.get("source_revision") == revision and receipt.get("final_product_source_preserved") is True, "Final source archive differs from this fixed product source")
        require(receipt.get("durable_remote_preservation_verified") is True and receipt.get("plan_sha256") == manifest_item["sha256"], "Historical archive has not completed durable preservation")
        archives.append((manifest, receipt, manifest_item["sha256"], manifest_item["bytes"]))
    uploads.append({"asset_name": "repository-delivery-15.0.0.json", "local_path": plan_relative, "bytes": args.plan.stat().st_size, "sha256": plan_hash, "role": "repository-delivery-plan"})
    require(all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", item["asset_name"]) and 0 <= item["bytes"] <= 2 * 1024**3 for item in uploads), "Unsafe upload name or GitHub asset larger than 2 GiB")
    require(len({item["asset_name"].casefold() for item in uploads}) == len(uploads), "Delivery upload names collide")
    require(HANDOFF.verify.sha256(args.plan) == plan_hash, "Delivery statement changed during local verification")
    return plan, uploads, archives


def remote_check(github, repository, plan, archives):
    identity = PUBLISH.identity(github, repository, PUBLISH.REPOSITORY_ID)
    require(identity.get("default_branch") == "main", "The main repository must retain main as its default branch")
    main = github.request("GET", "/repos/" + repository + "/git/ref/heads/main")["object"]
    require(main.get("type") == "commit" and main.get("sha") == plan["source_revision"], "Remote main differs from the fixed delivery source")
    tag_exists = PUBLISH.verify_tag(github, repository, plan["source_revision"], TAG)
    for manifest, receipt, checksum, length in archives:
        ARCHIVE.verify_published_plan(github, repository, manifest, receipt, checksum, length)
    try:
        release = github.request("GET", "/repos/" + repository + "/releases/tags/" + TAG)
    except PUBLISH.Missing:
        release = None
    if release is not None:
        require(release.get("tag_name") == TAG and type(release.get("id")) is int and release["id"] > 0, "Unexpected candidate Release identity")
        require(release.get("draft") is True or release.get("prerelease") is True, "User-followup delivery cannot change an existing formal Release")
    return tag_exists, release


def release_body(plan):
    pending = [case["id"] for case in plan["acceptance_cases"] if case["status"] == "pending"]
    return ("NestLink 15.0.0 candidate, delivered before the user's final full-function tests.\n\n"
            "Final user acceptance: pending. Production update authorization: false. "
            "This prerelease does not claim completed hardware, installed-product, external-network or long-running acceptance.\n\n"
            "Signing states: " + ", ".join(key + "=" + plan["signing"][key] for key in sorted(SIGNING)) + ".\n\n"
            "Fixed source: `" + plan["source_revision"] + "`. The attached repository-delivery-15.0.0.json records exact artifact bytes and the user checklist. Separate original-history and final-source archive plans/receipts are attached; the old binaries remain in those archive Releases.\n\n"
            "Pending cases: " + ", ".join(pending) + ".")


def deliver(args, github=None):
    plan, uploads, archives = local_plan(args)
    unavailable = archives[0][1].get("unavailable_historical_gitlinks", [])
    github = github or ARCHIVE.A.GitHub(ARCHIVE.A.github_token())
    tag_exists, release = remote_check(github, args.repository, plan, archives)
    if args.action == "verify":
        return {"schema_version": 1, "status": "verified", "remote_mutation_performed": False, "source_revision": plan["source_revision"], "upload_count": len(uploads), "user_full_functional_acceptance": "pending", "production_update_authorized": False, "unavailable_historical_gitlinks": unavailable}
    if not tag_exists:
        github.request("POST", "/repos/" + args.repository + "/git/refs", value={"ref": "refs/tags/" + TAG, "sha": plan["source_revision"]})
        require(PUBLISH.verify_tag(github, args.repository, plan["source_revision"], TAG), "Created candidate tag did not read back at the fixed source")
    if release is None:
        release = github.request("POST", "/repos/" + args.repository + "/releases", value={"tag_name": TAG, "target_commitish": plan["source_revision"], "name": "NestLink 15.0.0 — awaiting user acceptance", "draft": True, "prerelease": True, "make_latest": "false", "body": release_body(plan)})
        require(release.get("draft") is True and release.get("prerelease") is True and type(release.get("id")) is int and release["id"] > 0, "GitHub did not create the intended candidate draft")
    release_id = release["id"]
    current = github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")
    require(all(isinstance(item.get("name"), str) for item in current), "Invalid existing candidate asset name")
    names = {item["name"].casefold(): item for item in current}
    require(len(names) == len(current) and set(names) <= {item["asset_name"].casefold() for item in uploads}, "Unexpected or duplicate existing candidate assets; no assets are overwritten or removed")
    durable = []
    for item in uploads:
        local = HANDOFF.fixed_file(args.bundle, {"path": item["local_path"], "bytes": item["bytes"], "sha256": item["sha256"]})
        existing = names.get(item["asset_name"].casefold())
        if existing is None:
            require(release.get("draft") is True, "Cannot append missing assets to a published candidate")
            with local.open("rb") as stream:
                existing = github.request("POST", "/repos/" + args.repository + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(item["asset_name"], safe=""), stream=stream, upload=True, length=item["bytes"])
        require(existing.get("name") == item["asset_name"] and type(existing.get("id")) is int and existing.get("size") == item["bytes"] and existing.get("state") == "uploaded", "Candidate asset identity or size differs; keep the source repositories and draft")
        observed = github.request("GET", "/repos/" + args.repository + "/releases/assets/" + str(existing["id"]))
        checksum, verification = ARCHIVE.A.remote_digest(github, args.repository, observed, item["bytes"])
        require(observed.get("name") == item["asset_name"] and observed.get("id") == existing["id"] and checksum == item["sha256"], "Candidate readback differs from fixed local bytes; keep the source repositories and draft")
        durable.append({"asset_name": item["asset_name"], "asset_id": existing["id"], "bytes": item["bytes"], "sha256": item["sha256"], "role": item["role"], "readback": "passed", "verification": verification})
    final_tag_exists, checked_release = remote_check(github, args.repository, plan, archives)
    require(final_tag_exists, "Candidate tag disappeared during upload")
    require(checked_release is not None and checked_release["id"] == release_id, "Candidate Release changed during upload")
    final_assets = github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")
    require({(item.get("name"), item.get("id"), item.get("size"), item.get("state")) for item in final_assets} == {(item["asset_name"], item["asset_id"], item["bytes"], "uploaded") for item in durable}, "Candidate asset identities changed after readback")
    if args.action == "publish":
        release = github.request("PATCH", "/repos/" + args.repository + "/releases/" + str(release_id), value={"draft": False, "prerelease": True, "make_latest": "false", "name": "NestLink 15.0.0 — awaiting user acceptance", "body": release_body(plan)})
        require(release.get("draft") is False and release.get("prerelease") is True, "GitHub did not retain candidate prerelease status")
    final = github.request("GET", "/repos/" + args.repository + "/releases/" + str(release_id))
    require(final.get("id") == release_id and final.get("tag_name") == TAG, "Final candidate Release identity changed")
    require(args.action != "publish" or (final.get("draft") is False and final.get("prerelease") is True), "The candidate must remain a prerelease")
    require(PUBLISH.verify_tag(github, args.repository, plan["source_revision"], TAG), "Final candidate tag is absent")
    return {"schema_version": 1, "status": "prerelease-published" if final.get("draft") is False else "draft-uploaded", "repository": args.repository, "repository_node_id": PUBLISH.REPOSITORY_ID, "release_id": release_id, "tag": TAG, "source_revision": plan["source_revision"], "remote_mutation_performed": True, "durable_remote_preservation_verified": True, "user_full_functional_acceptance": "pending", "production_update_authorized": False, "signing": plan["signing"], "unavailable_historical_gitlinks": unavailable, "uploads": durable, "repository_finalization_ready": False, "repository_deletion_performed": False, "branch_deletion_performed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "upload-draft", "publish"))
    parser.add_argument("--repository", choices=sorted(PUBLISH.ALLOWED_REPOSITORIES), required=True)
    for name in ("bundle", "plan", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-source")
    args = parser.parse_args()
    try:
        require(not args.output.exists(), "Delivery receipt must be create-new")
        result = deliver(args)
        producer = module("repository_delivery_producer", "scripts/refactor-release-producer.py")
        producer.create_json(args.output, result)
        print(json.dumps({key: value for key, value in result.items() if key != "uploads"}))
    except (ValueError, OSError, TypeError, KeyError, PUBLISH.Missing, subprocess.SubprocessError, urllib.error.URLError) as error:
        print("Repository delivery refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
