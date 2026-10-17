#!/usr/bin/env python3
"""Promote unchanged, accepted v15 bytes to the pinned GitHub repository.

The verify action is read-only. upload-draft and publish perform real remote
writes only when explicitly invoked, after verifying the signed acceptance
handoff, fixed producer cohort, and current historical source asset inventory.
No action deletes repositories, branches, old releases, tags, or assets.
For the user-authorized delivery before final user testing, use
refactor-repository-delivery.py; it publishes a separate, explicit prerelease.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ID = "R_kgDOTz-mRQ"
ALLOWED_REPOSITORIES = frozenset(("ZHanry/home-tunnel", "ZHanry/NestLink"))
CURRENT_RELEASE_TAGS = frozenset(("v15.0.0", "v15.0.0-preview.1"))


def require(value, message):
    if not value:
        raise ValueError(message)


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Missing(LookupError):
    pass


class RedirectPolicy(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port in (None, 443), "Unsafe GitHub asset redirect")
        require(parsed.hostname in {"api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}, "Unexpected GitHub asset redirect host")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if parsed.hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __init__(self, token):
        require(isinstance(token, str) and token and "\r" not in token and "\n" not in token, "GITHUB_TOKEN is unavailable")
        self.token = token
        self.opener = urllib.request.build_opener(RedirectPolicy())

    def request(self, method, path, *, value=None, stream=None, upload=False, length=None, binary=False):
        require(path.startswith("/") and "\r" not in path and "\n" not in path, "Unsafe GitHub API path")
        host = "uploads.github.com" if upload else "api.github.com"
        require(not (value is not None and stream is not None), "Ambiguous GitHub request body")
        headers = {"Authorization": "Bearer " + self.token, "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "NestLink-v15-fixed-byte-promoter",
                   "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
        data = json.dumps(value, separators=(",", ":")).encode("utf-8") if value is not None else stream
        if value is not None:
            headers["Content-Type"] = "application/json"
        if stream is not None:
            require(type(length) is int and 0 <= length <= 2 * 1024**3, "GitHub asset exceeds upload size limit")
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(length)})
        request = urllib.request.Request("https://" + host + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=120)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise Missing("GitHub object is absent") from None
            # Neither URL query strings nor server error bodies are replayed:
            # download redirects can contain short-lived bearer credentials.
            raise ValueError("GitHub API refused " + method + " (HTTP " + str(error.code) + ")") from None
        if binary:
            return response
        with response:
            raw = response.read(32 * 1024**2 + 1)
        require(len(raw) <= 32 * 1024**2, "GitHub response exceeds metadata budget")
        return json.loads(raw)

    def pages(self, path):
        require("?" not in path, "Pagination path must not contain query fields")
        result = []
        for page in range(1, 101):
            value = self.request("GET", path + "?per_page=100&page=" + str(page))
            require(isinstance(value, list) and len(value) <= 100, "Malformed GitHub pagination response")
            result.extend(value)
            require(len(result) <= 10000, "GitHub inventory exceeds reviewed budget")
            if len(value) < 100:
                return result
        raise ValueError("GitHub inventory did not terminate within its page budget")

    def download_digest(self, repository, asset_id, expected_bytes):
        require(type(asset_id) is int and asset_id > 0 and type(expected_bytes) is int and 0 <= expected_bytes <= 2 * 1024**3, "Invalid GitHub asset descriptor")
        value, total = hashlib.sha256(), 0
        with self.request("GET", "/repos/" + repository + "/releases/assets/" + str(asset_id), binary=True) as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                require(total <= expected_bytes, "Remote asset exceeds fixed byte count")
                value.update(chunk)
        require(total == expected_bytes, "Remote asset length differs from fixed bytes")
        return value.hexdigest()


def identity(github, repository, node_id):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository), "Invalid repository name")
    value = github.request("GET", "/repos/" + repository)
    require(value.get("node_id") == node_id and value.get("full_name") == repository, "GitHub repository identity differs from the reviewed repository")
    return value


def legacy_inventory(github, handoff, repositories):
    preservation_tags = handoff.get("preservation_tags", [])
    require(isinstance(preservation_tags, (list, tuple)) and all(isinstance(tag, str) and re.fullmatch(r"history-archive-[A-Za-z0-9._-]{1,100}", tag) for tag in preservation_tags), "Invalid preservation Release exclusions")
    expected = {(item["component"], item["release_id"], item["asset_id"]): (item["bytes"], item["sha256"]) for item in handoff["legacy_assets"]}
    actual = {}
    for component, (repository, node_id) in repositories.items():
        # The source repository may already have its approved new name.
        if component == "hub":
            repository = handoff.get("current_repository", repository)
        identity(github, repository, node_id)
        releases = github.pages("/repos/" + repository + "/releases")
        for release in releases:
            release_id = release.get("id")
            require(type(release_id) is int and release_id > 0, "Invalid historical Release identity")
            # The one new v15 cohort is deliberately excluded from legacy
            # source inventory during idempotent retry after a partial upload.
            if component == "hub" and release.get("tag_name") in CURRENT_RELEASE_TAGS | frozenset(preservation_tags):
                continue
            for asset in github.pages("/repos/" + repository + "/releases/" + str(release_id) + "/assets"):
                key = (component, release_id, asset.get("id"))
                require(key not in actual and type(asset.get("size")) is int and asset["size"] >= 0 and asset.get("state") == "uploaded", "Historical asset is duplicated or incomplete")
                expected_digest = asset.get("digest")
                if isinstance(expected_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", expected_digest):
                    checksum = expected_digest[7:]
                else:
                    checksum = github.download_digest(repository, asset["id"], asset["size"])
                actual[key] = (asset["size"], checksum)
    require(actual == expected, "Historical source inventory changed after signed preservation review; refresh and re-review before any write")
    return actual


def verify_tag(github, repository, revision, tag="v15.0.0"):
    require(isinstance(tag, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", tag), "Invalid release tag name")
    try:
        value = github.request("GET", "/repos/" + repository + "/git/ref/tags/" + tag)["object"]
    except Missing:
        return False
    for _ in range(5):
        if value.get("type") == "commit":
            require(value.get("sha") == revision, "Existing release tag points to a different commit")
            return True
        require(value.get("type") == "tag" and re.fullmatch(r"[0-9a-f]{40}", value.get("sha", "")), "Unsupported release tag object")
        value = github.request("GET", "/repos/" + repository + "/git/tags/" + value["sha"])["object"]
    raise ValueError("Release tag indirection exceeds budget")


def local_plan(args):
    producer = module("release_producer", "scripts/refactor-release-producer.py")
    handoff_module = module("release_handoff", "scripts/refactor-release-handoff.py")
    verify = module("release_verify", "packaging/native/release_verify.py")
    policy = producer.configuration(ROOT / "config/release-producer.json")
    require(policy["update_certificate_sha256"] == args.certificate_sha256, "Promotion trust anchor differs from the committed independent public pin")
    with tempfile.TemporaryDirectory(prefix="nestlink-promotion-review-") as scratch:
        # Authenticate and parse the same private snapshot. Reopening caller-
        # writable statements after signature verification could mix two
        # different release decisions, signatures or public certificates.
        statements, frozen = {}, []
        for source, name in ((args.cohort, "release-cohort.json"), (args.cohort_signature, "release-cohort.p7s"),
                             (args.handoff, "release-handoff.json"), (args.handoff_signature, "release-handoff.p7s"),
                             (args.certificate, "release-update.crt")):
            producer.regular(source)
            with source.open("rb") as stream:
                raw = stream.read(32 * 1024**2 + 1)
            require(0 < len(raw) <= 32 * 1024**2, "Signed release statement exceeds its metadata budget")
            snapshot = Path(scratch) / name
            with snapshot.open("xb") as stream:
                stream.write(raw)
            statements[name] = snapshot
            frozen.append({"asset_name": name, "local_path": str(source.absolute()),
                "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "role": "signed-release-statement"})
        cohort = producer.json_read(statements["release-cohort.json"])
        require(cohort.get("kind") == "nestlink-fixed-release" and cohort.get("version") == "15.0.0" and cohort.get("repository_node_id") == REPOSITORY_ID, "Unsupported fixed release statement")
        verify.verify_cms(statements["release-cohort.json"], statements["release-cohort.p7s"], statements["release-update.crt"], args.certificate_sha256, openssl=args.openssl)
        require(len(cohort.get("artifacts", [])) == len(producer.FINAL_ROLES) and {item.get("role") for item in cohort["artifacts"]} == producer.FINAL_ROLES, "Complete fixed producer cohort is required")
        for item in cohort["artifacts"]:
            producer.verify_record(args.bundle, item)
        upload = handoff_module.prepare(argparse.Namespace(plan=statements["release-handoff.json"], signature=statements["release-handoff.p7s"],
            certificate=statements["release-update.crt"], certificate_sha256=args.certificate_sha256, bundle=args.bundle,
            expected_source=cohort["source_revision"], output=Path(scratch) / "upload.json", openssl=args.openssl))
        handoff = producer.json_read(statements["release-handoff.json"])
        require(upload["handoff_sha256"] == next(item["sha256"] for item in frozen if item["asset_name"] == "release-handoff.json"), "Verified handoff differs from the frozen upload statement")
    by_role = {item["role"]: item for item in handoff["artifacts"]}
    for item in cohort["artifacts"]:
        require(item["role"] in by_role and all(by_role[item["role"]][field] == item[field] for field in ("path", "bytes", "sha256")), "Accepted handoff attempts to rebuild/substitute the fixed producer bytes")
    require({item["role"] for item in cohort["artifacts"]} == handoff_module.CURRENT_ROLES - {"acceptance"} and set(by_role) == handoff_module.CURRENT_ROLES | handoff_module.PRESERVATION_ROLES, "Fixed cohort/handoff roles differ")
    for item in frozen:
        source = Path(item["local_path"])
        require(producer.regular(source).st_size == item["bytes"] and producer.digest(source) == item["sha256"], "Signed release input changed during review")
        upload["uploads"].append(item)
    require(len({item["asset_name"].casefold() for item in upload["uploads"]}) == len(upload["uploads"]), "Auxiliary release statements collide with upload assets")
    return producer, handoff_module, handoff, upload


def remote_check(github, args, handoff_module, handoff, upload):
    require(args.repository in ALLOWED_REPOSITORIES, "Only the reviewed main repository name is allowed")
    repository = identity(github, args.repository, REPOSITORY_ID)
    require(repository.get("default_branch") == "main", "Default branch must be main before promotion")
    main = github.request("GET", "/repos/" + args.repository + "/git/ref/heads/main")
    require(main.get("object", {}).get("type") == "commit" and main["object"].get("sha") == upload["source_revision"], "Remote main differs from the final accepted source commit")
    tag_exists = verify_tag(github, args.repository, upload["source_revision"])
    actual = legacy_inventory(github, {**handoff, "current_repository": args.repository}, handoff_module.REPOSITORIES)
    try:
        release = github.request("GET", "/repos/" + args.repository + "/releases/tags/v15.0.0")
    except Missing:
        release = None
    if release is not None:
        require(release.get("tag_name") == "v15.0.0" and type(release.get("id")) is int and release["id"] > 0, "Existing release has an invalid identity")
    return tag_exists, release, actual


def promote(args, github=None):
    producer, handoff_module, handoff, upload = local_plan(args)
    github = github or GitHub(os.environ.get("GITHUB_TOKEN"))
    tag_exists, release, legacy = remote_check(github, args, handoff_module, handoff, upload)
    if args.action == "verify":
        return {"status": "verified", "remote_mutation_performed": False, "assets": len(upload["uploads"]), "historical_source_assets": len(legacy), "source_revision": upload["source_revision"]}
    # Every local final byte is rechecked immediately before mutation.
    for item in upload["uploads"]:
        path = Path(item["local_path"]) if Path(item["local_path"]).is_absolute() else producer.artifact(args.bundle, item["local_path"])
        require(path.stat().st_size == item["bytes"] and producer.digest(path) == item["sha256"], "Release input changed after signed review")
    if not tag_exists:
        github.request("POST", "/repos/" + args.repository + "/git/refs", value={"ref": "refs/tags/v15.0.0", "sha": upload["source_revision"]})
        require(verify_tag(github, args.repository, upload["source_revision"]), "Created tag did not read back at the accepted source")
    if release is None:
        release = github.request("POST", "/repos/" + args.repository + "/releases", value={"tag_name": "v15.0.0", "target_commitish": upload["source_revision"], "name": "NestLink 15.0.0", "draft": True, "prerelease": False,
            "body": "NestLink 15.0.0. All current product artifacts share the source commit recorded in release-cohort.json. Signed acceptance and preserved legacy bytes are attached. Historical source limitations are recorded in release-handoff.json."})
        require(release.get("draft") is True and type(release.get("id")) is int and release["id"] > 0, "GitHub did not create the intended draft release")
    release_id = release["id"]
    remote = github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")
    existing = {}
    for item in remote:
        require(isinstance(item.get("name"), str) and item["name"].casefold() not in existing, "Remote release contains colliding asset names")
        existing[item["name"].casefold()] = item
    expected_names = {item["asset_name"].casefold() for item in upload["uploads"]}
    require(set(existing) <= expected_names, "Remote release has unreviewed extra assets; review them explicitly")
    durable = []
    for item in upload["uploads"]:
        name = item["asset_name"]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name), "Unsafe upload asset name")
        remote_item = existing.get(name.casefold())
        if remote_item is None:
            require(release.get("draft") is True, "Cannot append missing assets to an already published release")
            path = Path(item["local_path"]) if Path(item["local_path"]).is_absolute() else producer.artifact(args.bundle, item["local_path"])
            require(producer.digest(path) == item["sha256"], "Upload bytes changed")
            with path.open("rb") as stream:
                remote_item = github.request("POST", "/repos/" + args.repository + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(name, safe=""), stream=stream, length=item["bytes"], upload=True)
        require(remote_item.get("name") == name and remote_item.get("size") == item["bytes"] and remote_item.get("state") == "uploaded", "Existing/uploaded asset identity or length differs; no overwrite is permitted")
        require(github.download_digest(args.repository, remote_item["id"], item["bytes"]) == item["sha256"], "Durable remote readback differs from the signed byte hash")
        durable.append({"asset_name": name, "asset_id": remote_item["id"], "bytes": item["bytes"], "sha256": item["sha256"], "role": item["role"], "readback": "passed"})
    # Repeat both source inventory and main/tag checks after potentially long
    # uploads. A concurrent legacy edit blocks publishing; no source is deleted.
    final_tag_exists, final_release, _ = remote_check(github, args, handoff_module, handoff, upload)
    require(final_tag_exists, "Release tag disappeared during upload; keep the release draft and re-review")
    require(final_release is not None and final_release.get("id") == release_id, "Reviewed Release identity changed during upload")
    final_assets = github.pages("/repos/" + args.repository + "/releases/" + str(release_id) + "/assets")
    require({(item.get("name"), item.get("id"), item.get("size"), item.get("state")) for item in final_assets} ==
            {(item["asset_name"], item["asset_id"], item["bytes"], "uploaded") for item in durable}, "Final remote asset identities changed after durable readback")
    if args.action == "publish" and release.get("draft"):
        require(verify_tag(github, args.repository, upload["source_revision"]), "Release tag is absent immediately before publication")
        release = github.request("PATCH", "/repos/" + args.repository + "/releases/" + str(release_id), value={"draft": False, "prerelease": False})
        require(release.get("draft") is False and release.get("prerelease") is False, "GitHub did not publish the final release")
    final = github.request("GET", "/repos/" + args.repository + "/releases/" + str(release_id))
    require(final.get("id") == release_id and final.get("tag_name") == "v15.0.0", "Final Release identity changed")
    require(args.action != "publish" or (final.get("draft") is False and final.get("prerelease") is False), "Final Release is not published")
    require(verify_tag(github, args.repository, upload["source_revision"]), "Final Release tag is absent")
    return {"schema_version": 1, "status": "published" if final.get("draft") is False else "draft-uploaded",
            "repository": args.repository, "repository_node_id": REPOSITORY_ID, "release_id": release_id,
            "tag": "v15.0.0", "source_revision": upload["source_revision"], "handoff_sha256": upload["handoff_sha256"],
            "remote_mutation_performed": True, "durable_remote_preservation_verified": True,
            "historical_source_inventory_rechecked": True, "historical_source_assets": len(legacy), "uploads": durable,
            "repository_deletion_performed": False, "branch_deletion_performed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "upload-draft", "publish"))
    parser.add_argument("--repository", choices=sorted(ALLOWED_REPOSITORIES), required=True)
    for name in ("bundle", "cohort", "cohort-signature", "handoff", "handoff-signature", "certificate", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        require(not args.output.exists(), "Promotion receipt must be create-new")
        result = promote(args)
        producer = module("release_producer", "scripts/refactor-release-producer.py")
        producer.create_json(args.output, result)
        print(json.dumps({key: value for key, value in result.items() if key != "uploads"}))
    except (ValueError, OSError, TypeError, KeyError, Missing, subprocess.SubprocessError, urllib.error.URLError) as error:
        print("Release promotion refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
