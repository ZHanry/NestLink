#!/usr/bin/env python3
"""Plan and preserve legacy bytes in a separate GitHub history-archive Release.

prepare is offline and never copies the old 16 GB asset archive. verify is
read-only. upload-draft/publish stream original files directly, reuse matching
assets, reject conflicts, and never overwrite/delete source bytes or assets.
GitHub SHA-256 metadata is preferred; downloads are needed only without digest.
"""
from __future__ import annotations

import argparse
import email.utils
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


P = module("history_archive_publish", "scripts/refactor-release-publish.py")
H = module("history_archive_handoff", "scripts/refactor-release-handoff.py")
HEX = re.compile(r"[0-9a-f]{64}")
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}")


def require(value, message):
    P.require(value, message)


def digest(path):
    return H.verify.sha256(path)


def record(path, name, role):
    path = Path(path).resolve(strict=True)
    require(SAFE.fullmatch(name), "Unsafe archive asset name")
    info = H.verify.regular(path)
    require(info.st_size <= 2 * 1024**3, "Archive asset exceeds the 2 GiB GitHub limit; split it before preparing")
    return {"asset_name": name, "path": str(path), "bytes": info.st_size, "sha256": digest(path), "role": role}


def create_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def expected_inventory(inventory):
    require(set(inventory.get("components", {})) == set(H.REPOSITORIES), "Inventory must identify all four approved repositories")
    result = {}
    for component, identity in H.REPOSITORIES.items():
        source = inventory["components"][component]
        require((source.get("repository"), source.get("repository_node_id")) == identity, "Source repository identity changed")
        require(source.get("asset_count") == len(source.get("assets", [])), "Original source asset count differs from its inventory")
        for item in source["assets"]:
            key = (component, item["release_id"], item["asset_id"])
            require(key not in result and item.get("state") == "uploaded" and HEX.fullmatch(item.get("github_sha256", "")), "Invalid original asset descriptor")
            result[key] = item
    return result


def prepare(args):
    require(not args.plan.exists(), "Archive plan must be create-new")
    inventory = H.bounded_json(args.inventory)
    archived = H.bounded_json(args.archive_report)
    source = H.bounded_json(args.source_report)
    require(archived.get("all_inventory_bytes_verified") is True, "The complete prior local byte-verification report is required")
    expected = expected_inventory(inventory)
    require(len(expected) == archived.get("inventory_asset_count") == archived.get("verified_assets"), "Prior local archive does not cover the complete source inventory")
    files, seen = [], set()
    archive_root = Path(archived["archive_root"]).resolve(strict=True)
    for item in archived["assets"]:
        key = (item["component"], item["release_id"], item["asset_id"])
        original = expected.get(key)
        require(original is not None and key not in seen and item.get("verified") is True and (item["bytes"], item["sha256"]) == (original["bytes"], original["github_sha256"]), "Prior verified asset differs from the current source inventory")
        seen.add(key)
        path = H.verify.artifact_path(archive_root, item["archive_path"])
        require(H.verify.regular(path).st_size == item["bytes"], "Previously verified local archive asset is missing or truncated")
        # Reuse the exact prior hash here. Upload verifies local bytes once just
        # before use, so prepare does not rehash/copy all 16 GB unnecessarily.
        files.append({"asset_name": "legacy-" + key[0] + "-" + str(key[1]) + "-" + str(key[2]) + ".blob", "path": str(path), "bytes": item["bytes"], "sha256": item["sha256"], "role": "legacy-release-asset", "original": {"component": key[0], "release_id": key[1], "asset_id": key[2], "filename": item["original_filename"], "tag": item["tag"]}})
    require(seen == set(expected), "Original asset coverage is incomplete")
    require(all(source.get(key) is True for key in ("bundle_standalone_verified", "restored_ref_map_verified", "strict_fsck_passed")), "Original source bundle restore/fsck evidence is required")
    bundle = Path(source["bundle"]["path"])
    files += [record(bundle, "legacy-source-original.bundle", "legacy-source-bundle"), record(args.source_report, "legacy-source-report.json", "legacy-source-report"), record(args.inventory, "legacy-release-inventory.json", "legacy-release-inventory"), record(args.archive_report, "legacy-release-local-verification.json", "legacy-release-local-verification")]
    require((files[-4]["bytes"], files[-4]["sha256"]) == (source["bundle"]["bytes"], source["bundle"]["sha256"]), "Original source bundle bytes changed")
    if args.dirty_report:
        dirty = H.bounded_json(args.dirty_report)
        files.append(record(args.dirty_report, "legacy-dirty-worktree-report.json", "dirty-worktree-report"))
        for component in dirty["components"]:
            require(component.get("source_and_zip_bytes_reverified") is True and component.get("status_unchanged") is True, "Dirty-worktree backup evidence is incomplete")
            zipped = component["zip"]
            saved = record(zipped["path"], "legacy-dirty-" + component["component"] + ".zip", "dirty-worktree-backup")
            require((saved["bytes"], saved["sha256"]) == (zipped["bytes"], zipped["sha256"]), "Dirty-worktree ZIP changed")
            files.append(saved)
            for sibling in sorted(Path(zipped["path"]).parent.iterdir()):
                if sibling.is_file() and sibling.name != Path(zipped["path"]).name:
                    files.append(record(sibling, "legacy-dirty-" + component["component"] + "-" + sibling.name, "dirty-worktree-metadata"))
    for extra in args.extra_file:
        name, separator, path = extra.partition("=")
        require(separator and name and path, "Extra file requires SAFE_NAME=ABSOLUTE_PATH")
        files.append(record(path, name, "additional-preservation-evidence"))
    plan = {"schema_version": 1, "purpose": "history-archive", "repository_node_id": P.REPOSITORY_ID, "tag": args.tag, "tag_target": args.tag_target, "preservation_review": "passed", "source_inventory_sha256": digest(args.inventory), "source_assets": [{"component": key[0], "release_id": key[1], "asset_id": key[2], "bytes": item["bytes"], "sha256": item["github_sha256"]} for key, item in expected.items()], "files": files, "unavailable_historical_gitlinks": source.get("unavailable_gitlinks", []), "final_product_source_preserved": False, "user_full_functional_acceptance": "pending"}
    validate(plan)
    create_json(args.plan, plan)
    return {"status": "prepared", "plan": str(args.plan), "files": len(files), "bytes": sum(item["bytes"] for item in files), "additional_payload_copy_bytes": 0, "remote_mutation_performed": False}


def validate(plan):
    require(plan.get("schema_version") == 1 and plan.get("purpose") == "history-archive" and plan.get("repository_node_id") == P.REPOSITORY_ID and plan.get("preservation_review") == "passed", "Unreviewed archive plan or repository identity")
    require(isinstance(plan.get("tag"), str) and re.fullmatch(r"history-archive-[A-Za-z0-9._-]{1,100}", plan["tag"]) and re.fullmatch(r"[0-9a-f]{40}", plan.get("tag_target", "")), "Invalid archive tag/target")
    require(plan.get("user_full_functional_acceptance") == "pending" and plan.get("final_product_source_preserved") is False, "Legacy archive cannot claim final product source or user acceptance")
    require(isinstance(plan.get("files"), list) and 1 <= len(plan["files"]) <= 10000, "Invalid archive file list")
    names = set()
    for item in plan["files"]:
        require(isinstance(item, dict) and SAFE.fullmatch(item.get("asset_name", "")) and item["asset_name"].casefold() not in names, "Unsafe or colliding archive names")
        names.add(item["asset_name"].casefold())
        require(Path(item["path"]).is_absolute() and type(item.get("bytes")) is int and 0 <= item["bytes"] <= 2 * 1024**3 and HEX.fullmatch(item.get("sha256", "")), "Archive file has invalid path, size or digest")
    sources = plan.get("source_assets", [])
    keys = [(item.get("component"), item.get("release_id"), item.get("asset_id")) for item in sources]
    require(len(keys) == len(set(keys)) and all(key[0] in H.REPOSITORIES and type(key[1]) is int and key[1] > 0 and type(key[2]) is int and key[2] > 0 for key in keys), "Invalid source asset identities")
    archived = {(item["original"]["component"], item["original"]["release_id"], item["original"]["asset_id"]): (item["bytes"], item["sha256"]) for item in plan["files"] if item["role"] == "legacy-release-asset"}
    require(len(archived) == sum(item["role"] == "legacy-release-asset" for item in plan["files"]) and archived == {key: (item["bytes"], item["sha256"]) for key, item in zip(keys, sources)}, "Archive payload does not preserve every planned original asset")


def retry_delay(headers, attempt, now=None):
    now = time.time() if now is None else now
    retry = headers.get("Retry-After")
    if retry:
        try:
            return max(1, min(60, float(retry)))
        except ValueError:
            try:
                return max(1, min(60, email.utils.parsedate_to_datetime(retry).timestamp() - now))
            except (ValueError, TypeError, OverflowError):
                pass
    if headers.get("X-RateLimit-Remaining") == "0":
        try:
            return max(1, min(60, float(headers.get("X-RateLimit-Reset", "0")) - now))
        except ValueError:
            pass
    return min(60, 10 * 2**attempt)


class GitHub(P.GitHub):
    def request(self, method, path, *, value=None, stream=None, upload=False, length=None, binary=False):
        require(path.startswith("/") and "\r" not in path and "\n" not in path, "Unsafe GitHub API path")
        require(not (value is not None and stream is not None), "Ambiguous GitHub request body")
        host = "uploads.github.com" if upload else "api.github.com"
        headers = {"Authorization": "Bearer " + self.token, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "NestLink-history-preservation", "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
        data = json.dumps(value).encode() if value is not None else stream
        if value is not None:
            headers["Content-Type"] = "application/json"
        if stream is not None:
            require(type(length) is int and 0 <= length <= 2 * 1024**3, "Invalid upload length")
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(length)})
        for attempt in range(7):
            if stream is not None:
                stream.seek(0)
            request = urllib.request.Request("https://" + host + path, data=data, headers=headers, method=method)
            try:
                response = self.opener.open(request, timeout=180)
            except urllib.error.HTTPError as error:
                if error.code == 404:
                    raise P.Missing("GitHub object is absent") from None
                body = error.read(65536).lower()
                limited = error.code == 429 or (error.code == 403 and (error.headers.get("Retry-After") or error.headers.get("X-RateLimit-Remaining") == "0" or b"secondary rate limit" in body or b"rate limit exceeded" in body))
                if attempt < 6 and (limited or (method == "GET" and error.code in (500, 502, 503, 504))):
                    delay = retry_delay(error.headers, attempt)
                    print(json.dumps({"status": "rate-limit-backoff" if limited else "retry-read", "http_status": error.code, "retry_seconds": delay, "attempt": attempt + 1}), flush=True)
                    time.sleep(delay)
                    continue
                raise ValueError("GitHub refused " + method + " (HTTP " + str(error.code) + "); existing assets remain; resume after review") from None
            if binary:
                return response
            with response:
                raw = response.read(32 * 1024**2 + 1)
            require(len(raw) <= 32 * 1024**2, "GitHub metadata exceeds its budget")
            return json.loads(raw)
        raise ValueError("GitHub retry budget exhausted")


def remote_digest(github, repository, asset, size):
    require(asset.get("size") == size and asset.get("state") == "uploaded" and type(asset.get("id")) is int and asset["id"] > 0, "Remote asset is incomplete or has a different length")
    metadata = asset.get("digest")
    if isinstance(metadata, str) and metadata.startswith("sha256:") and HEX.fullmatch(metadata[7:]):
        return metadata[7:], "github-sha256"
    return github.download_digest(repository, asset["id"], size), "streamed-readback"


def source_check(github, repository, plan):
    inventory = {"legacy_assets": plan["source_assets"], "current_repository": repository, "preservation_tags": [plan["tag"]]}
    P.legacy_inventory(github, inventory, H.REPOSITORIES)


def github_token():
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        return token
    # Capture the configured CLI credential privately. It is never printed,
    # included in a command argument, persisted, or attached to a Release.
    result = subprocess.run(["gh", "auth", "token"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    require(result.returncode == 0 and result.stdout.strip(), "No GitHub credential is available")
    return result.stdout.strip()


def execute(args, github=None):
    plan_hash = digest(args.plan)
    plan = H.bounded_json(args.plan)
    validate(plan)
    github = github or GitHub(github_token())
    P.identity(github, args.repository, P.REPOSITORY_ID)
    tag_exists = P.verify_tag(github, args.repository, plan["tag_target"], plan["tag"])
    try:
        release = github.request("GET", "/repos/" + args.repository + "/releases/tags/" + plan["tag"])
    except P.Missing:
        release = None
    items = plan["files"] + [{"asset_name": "history-archive-plan-" + plan_hash + ".json", "path": str(args.plan.resolve()), "bytes": args.plan.stat().st_size, "sha256": plan_hash, "role": "archive-plan"}]
    if args.action != "verify":
        source_check(github, args.repository, plan)
        # Existence/length checks cover the whole batch before the first write.
        # The potentially large bytes are hashed once, immediately before use.
        require(digest(args.plan) == plan_hash, "Archive plan changed during source review")
        for item in items:
            require(H.verify.regular(Path(item["path"])).st_size == item["bytes"], "Local archive file is missing or truncated")
        if not tag_exists:
            github.request("POST", "/repos/" + args.repository + "/git/refs", value={"ref": "refs/tags/" + plan["tag"], "sha": plan["tag_target"]})
            require(P.verify_tag(github, args.repository, plan["tag_target"], plan["tag"]), "Archive tag did not read back at its fixed target")
        if release is None:
            release = github.request("POST", "/repos/" + args.repository + "/releases", value={"tag_name": plan["tag"], "target_commitish": plan["tag_target"], "name": "NestLink preserved legacy history", "body": "Historical source, original Release bytes and local work backups. Original identities and limitations are in the attached immutable archive plan. This archive is independent of new product Releases and does not assert final user acceptance or complete external submodule checkout.", "draft": True, "prerelease": True, "make_latest": "false"})
    require(release is not None and release.get("tag_name") == plan["tag"] and type(release.get("id")) is int and release["id"] > 0, "The expected archive Release is absent or has a different identity")
    release_id = release["id"]
    current = github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")
    require(all(isinstance(item.get("name"), str) for item in current), "Invalid archive asset name")
    names = {item["name"].casefold(): item for item in current}
    require(len(names) == len(current), "Archive contains colliding asset names")
    verified, missing, uploaded = [], [], 0
    deadline = time.monotonic() + args.max_seconds
    for item in items:
        existing = names.get(item["asset_name"].casefold())
        if existing is None and args.action == "verify":
            missing.append(item["asset_name"])
            continue
        if existing is None:
            if time.monotonic() >= deadline or (args.max_files is not None and uploaded >= args.max_files):
                missing.append(item["asset_name"])
                continue
            require(release.get("draft") is True, "Cannot append files to a published archive; prepare a separate supplement Release")
            local = Path(item["path"])
            require(H.verify.regular(local).st_size == item["bytes"] and digest(local) == item["sha256"], "Local archive bytes changed; no upload is performed for that file")
            with local.open("rb") as stream:
                existing = github.request("POST", "/repos/" + args.repository + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(item["asset_name"], safe=""), upload=True, stream=stream, length=item["bytes"])
            uploaded += 1
        require(existing.get("name") == item["asset_name"], "Existing remote name differs in case; refusing a collision")
        # Re-fetch by asset ID before trusting metadata; an earlier listing is
        # only a locator and cannot stand in for the final digest observation.
        observed = github.request("GET", "/repos/" + args.repository + "/releases/assets/" + str(existing["id"]))
        require(observed.get("name") == item["asset_name"] and observed.get("id") == existing["id"], "Remote archive asset identity changed")
        actual, method = remote_digest(github, args.repository, observed, item["bytes"])
        require(actual == item["sha256"], "Existing/uploaded archive content differs; it is never overwritten")
        verified.append({"asset_name": item["asset_name"], "asset_id": observed["id"], "bytes": item["bytes"], "sha256": actual, "role": item["role"], "verification": method})
        print(json.dumps({"status": "asset-verified", "verified": len(verified), "total": len(items), "asset_name": item["asset_name"], "verification": method}), flush=True)
    complete = not missing
    if complete and args.action != "verify":
        source_check(github, args.repository, plan)
    require(P.verify_tag(github, args.repository, plan["tag_target"], plan["tag"]), "Archive tag changed during verification")
    final_assets = github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")
    present = {(item.get("name"), item.get("id"), item.get("size"), item.get("state")) for item in final_assets}
    require(all((item["asset_name"], item["asset_id"], item["bytes"], "uploaded") in present for item in verified), "Verified archive asset identities changed")
    if complete and args.action == "publish" and release.get("draft") is True:
        release = github.request("PATCH", "/repos/" + args.repository + "/releases/" + str(release_id), value={"draft": False, "prerelease": True, "make_latest": "false"})
        require(release.get("draft") is False, "Archive publication failed")
    return {"schema_version": 1, "purpose": "history-archive-receipt", "status": "verified" if args.action == "verify" else "published" if complete and release.get("draft") is False else "draft-partial" if missing else "draft-uploaded", "repository": args.repository, "repository_node_id": P.REPOSITORY_ID, "release_id": release_id, "tag": plan["tag"], "plan_sha256": plan_hash, "durable_remote_preservation_verified": complete, "remote_mutation_performed": args.action != "verify", "files_verified": len(verified), "bytes_verified": sum(item["bytes"] for item in verified), "missing_assets": missing, "uploads": verified, "unavailable_historical_gitlinks": plan["unavailable_historical_gitlinks"], "final_product_source_preserved": False, "user_full_functional_acceptance": "pending", "repository_finalization_ready": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "verify", "upload-draft", "publish"))
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--repository", choices=sorted(P.ALLOWED_REPOSITORIES), default="ZHanry/home-tunnel")
    for name in ("inventory", "archive-report", "source-report", "dirty-report", "output"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--extra-file", action="append", default=[])
    parser.add_argument("--tag", default="history-archive-2026-10-17")
    parser.add_argument("--tag-target")
    parser.add_argument("--max-seconds", type=int, default=5400)
    parser.add_argument("--max-files", type=int)
    args = parser.parse_args()
    try:
        require(1 <= args.max_seconds <= 5400 and (args.max_files is None or args.max_files > 0), "Archive batch must be bounded to at most 90 minutes")
        if args.action == "prepare":
            require(all(getattr(args, name) for name in ("inventory", "archive_report", "source_report", "tag_target")), "prepare requires inventory, archive-report, source-report and tag-target")
            result = prepare(args)
        else:
            require(args.output is not None and not args.output.exists(), "A create-new receipt path is required")
            result = execute(args)
            create_json(args.output, result)
        print(json.dumps({key: value for key, value in result.items() if key not in ("uploads", "missing_assets")}))
        return 0 if result.get("durable_remote_preservation_verified", True) else 2
    except (ValueError, OSError, TypeError, KeyError, P.Missing, subprocess.SubprocessError, urllib.error.URLError) as error:
        print("History archive refused: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
