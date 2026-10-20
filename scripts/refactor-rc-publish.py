#!/usr/bin/env python3
"""Verify or publish the pinned, unsigned NestLink RC to its new repository.

verify performs no remote writes. upload-draft and publish only create the
fixed tag, a prerelease, and missing immutable assets. Existing conflicts are
refused; no action deletes or replaces repositories, branches, tags or assets.
This separate RC policy does not relax any formal or historical release gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = "ZHanry/NestLink"
REPOSITORY_ID = "R_kgDOVNHMvg"
VERSION = "0.7.0-rc.1"
TAG = "v" + VERSION
MAX_ASSET_BYTES = 2 * 1024**3
MANIFEST_NAME = "candidate-build-manifest.json"
CURRENT_ROLES = frozenset((
    "windows-x64-setup", "windows-x64-privileged-setup", "linux-x64-desktop", "linux-arm64-desktop",
    "linux-x64-server", "linux-arm64-server", "android-arm64", "android-x86_64",
    "web-static", "oci-x64", "oci-arm64", "source", "sbom", "licenses", "materials", "acceptance",
    "native-payload-manifest", "native-packages-manifest",
))
REQUIRED_CASES = frozenset((
    "windows-10-installed", "windows-11-installed", "windows-privileged-input", "linux-x64-x11-installed",
    "linux-arm64-x11-installed", "gnome-wayland-authorized", "kde-wayland-authorized",
    "android-arm64-physical", "chrome-current", "edge-current", "firefox-current", "company-to-home",
    "mobile-to-home", "90-minute-soak", "turn-capacity-and-revoke", "signature-windows",
    "signature-android", "signature-linux-update", "signature-oci", "install-upgrade-rollback-uninstall",
    "reinstall-new-identity-retained-data", "schema-migration-and-interruption-recovery", "license-and-source-audit",
) + tuple("android-api-" + str(api) for api in range(30, 37)))
SIGNING = {"windows": "not-configured", "android": "development-only",
           "linux_update": "not-configured", "oci": "not-configured"}


def require(value, message):
    if not value:
        raise ValueError(message)


class Missing(LookupError):
    """A GitHub 404; shared by this module's client and publication protocol."""


class RedirectPolicy(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        require(parsed.scheme == "https" and not parsed.username and not parsed.password
                and parsed.port in (None, 443), "Unsafe GitHub asset redirect")
        require(parsed.hostname in {"api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"},
                "Unexpected GitHub asset redirect host")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if parsed.hostname != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __init__(self, token):
        require(isinstance(token, str) and token and "\r" not in token and "\n" not in token,
                "GITHUB_TOKEN is unavailable")
        self.token = token
        self.opener = urllib.request.build_opener(RedirectPolicy())

    def request(self, method, path, *, value=None, stream=None, upload=False, length=None, binary=False):
        require(path.startswith("/") and "\r" not in path and "\n" not in path, "Unsafe GitHub API path")
        require(not (value is not None and stream is not None), "Ambiguous GitHub request body")
        host = "uploads.github.com" if upload else "api.github.com"
        headers = {"Authorization": "Bearer " + self.token, "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "NestLink-RC-fixed-byte-publisher",
                   "Accept": "application/octet-stream" if binary else "application/vnd.github+json"}
        data = json.dumps(value, separators=(",", ":")).encode("utf-8") if value is not None else stream
        if value is not None:
            headers["Content-Type"] = "application/json"
        if stream is not None:
            require(type(length) is int and 0 < length <= MAX_ASSET_BYTES, "GitHub asset exceeds upload size limit")
            headers.update({"Content-Type": "application/octet-stream", "Content-Length": str(length)})
        request = urllib.request.Request("https://" + host + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=120)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                raise Missing("GitHub object is absent") from None
            raise ValueError("GitHub API refused " + method + " (HTTP " + str(error.code) + ")") from None
        except urllib.error.URLError:
            # Redirect URLs may contain short-lived credentials. Never echo them.
            raise ValueError("GitHub transport failed") from None
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
            if len(value) < 100:
                return result
        raise ValueError("GitHub inventory did not terminate within its page budget")

    def download_digest(self, repository, asset_id, expected_bytes):
        require(repository == REPOSITORY and type(asset_id) is int and asset_id > 0
                and type(expected_bytes) is int and 0 < expected_bytes <= MAX_ASSET_BYTES,
                "Invalid GitHub asset descriptor")
        value, total = hashlib.sha256(), 0
        with self.request("GET", "/repos/" + repository + "/releases/assets/" + str(asset_id), binary=True) as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                require(total <= expected_bytes, "Remote asset exceeds fixed byte count")
                value.update(chunk)
        require(total == expected_bytes, "Remote asset length differs from fixed bytes")
        return value.hexdigest()


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400),
            "Expected a real, non-reparse directory")


def absolute(path):
    """Check ancestors before resolving; resolving first hides a junction."""
    path = Path(os.path.abspath(path))
    for parent in reversed(path.parents):
        directory(parent)
    return path


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400),
            "Expected a regular, non-reparse RC file")
    return info


def portable(value):
    require(isinstance(value, str) and 0 < len(value) <= 512 and "\\" not in value, "Expected a portable RC path")
    for part in value.split("/"):
        require(part not in ("", ".", "..") and not part.endswith((" ", ".")), "Unsafe RC path component")
        require(not any(ord(ch) < 32 or ord(ch) == 127 or ch in ':<>"|?*' for ch in part), "Nonportable RC path")
        require(not re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part), "Reserved RC path component")
    return value.split("/")


def artifact(root, value):
    parts = portable(value)
    directory(root)
    current = root
    for part in parts[:-1]:
        current /= part
        directory(current)
    current /= parts[-1]
    regular(current)
    return current


def digest_stream(stream):
    checksum, count = hashlib.sha256(), 0
    while chunk := stream.read(1024 * 1024):
        count += len(chunk)
        require(count <= MAX_ASSET_BYTES, "RC asset exceeds GitHub's 2 GiB limit")
        checksum.update(chunk)
    return count, checksum.hexdigest()


def fixed_file(path, size, checksum):
    require(regular(path).st_size == size, "Local RC byte count changed")
    with path.open("rb") as stream:
        require(digest_stream(stream) == (size, checksum), "Local RC bytes differ from the manifest")


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate RC metadata field")
        result[key] = value
    return result


def git(root, *command):
    # A caller's alternate index or worktree must never hide dirty source.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    result = subprocess.run(["git", "-C", str(root), *command], env=env, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    return result.stdout.decode("utf-8").strip()


def clean_source(root, revision):
    directory(root)
    require(Path(git(root, "rev-parse", "--show-toplevel")).resolve() == root.resolve(), "Source root is not the Git checkout root")
    require(git(root, "rev-parse", "HEAD") == revision, "Local source differs from the RC commit")
    require(git(root, "symbolic-ref", "--short", "HEAD") == "main", "RC source checkout must be on main")
    require(not git(root, "status", "--porcelain", "--untracked-files=all"), "RC requires clean source including untracked files")
    source_manifest = artifact(root, "Cargo.toml")
    value = tomllib.loads(source_manifest.read_text(encoding="utf-8"))
    require(value.get("workspace", {}).get("package", {}).get("version") == VERSION, "Clean source has the wrong public RC version")


def release_body(revision, checksum):
    return ("NestLink " + VERSION + " 开发候选版。\n\n"
            "- Windows 媒体 socket 支持跟随系统、优先物理接口和指定接口；实际 ICE 与原生 QUIC 使用同一 socket 工厂。\n"
            "- 直连能力协商启用累计 Trickle ICE；启动许可与运行短租约分离，30 秒启动预算仍受原授权截止约束。\n"
            "- Windows 增加 DXGI 采集、GDI 降级恢复和按签名协商的 Media Foundation H.264 硬编硬解；VP8 保留兼容。\n"
            "- 原生可靠视频加入发送截止、缓冲上界和本地码率/帧率调节；增加进入桌面、操作中心和脱敏实测诊断。\n"
            "- 完整整改状态与验收边界：https://github.com/ZHanry/NestLink/blob/" + revision + "/docs/refactor/REMEDIATION-0.7.0-RC1.md\n\n"
            "范围：浏览器仍为 VP8；当前媒体仍有 CPU 像素转换和上传。GPU 零拷贝、H.265、4:4:4/HDR、视频 datagram 尚未实现；1080p60、原 HL↔外部 Edge 百次直连、UU 配对 A/B 和 24 小时长稳尚未完成资格验收。本 RC 不宣称全部报告项目已通过。\n\n"
            "升级：请同时升级服务器、Web 和双方客户端。原生跨网络回退需管理员允许服务器转发及双方 relay；浏览器需可达 STUN，受限网络还需注册 TURN 节点并允许中继。升级不会自动放宽服务器策略，原生 WSS 不能替代浏览器 TURN。\n"
            "数据库升级到 schema 24；升级前备份，回滚旧版本须恢复升级前备份。恢复登录不会恢复屏幕、输入或文件授权。\n"
            "部署与排障：https://github.com/ZHanry/NestLink/blob/" + revision + "/docs/REMOTE-CONNECTION.md\n\n"
            "Source commit: " + revision + ". All 18 product artifacts are bound to this clean source commit.\n"
            "candidate-build-manifest.json SHA-256: " + checksum + ".\n\n"
            "Windows Authenticode, Linux update and OCI signing are not configured. Android uses a development signing key. "
            "Production update eligibility: false. Full functional user acceptance: pending.\n"
            "All 30 platform, signing, physical-device and real-network acceptance cases remain pending; "
            "automated development checks do not complete those cases. Android support covers Android 11–16 (API 30–36).\n")


def local_plan(args):
    require(args.repository == REPOSITORY, "RC publication is restricted to the new NestLink repository")
    source_root, bundle, manifest = (absolute(getattr(args, name)) for name in ("source_root", "bundle", "manifest"))
    directory(bundle)
    require(manifest == bundle / MANIFEST_NAME, "Use the original frozen candidate-build-manifest.json at the bundle root")
    require(0 < regular(manifest).st_size <= 2 * 1024**2, "RC manifest exceeds its metadata budget")
    raw = manifest.read_bytes()
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
    fields = {"schema_version", "kind", "product", "repository", "repository_node_id", "source_revision",
              "cohort_sha256", "version", "signing", "production_update_eligible", "user_full_functional_acceptance",
              "acceptance_cases", "artifacts"}
    require(isinstance(value, dict) and set(value) == fields, "Unexpected RC manifest fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["kind"] == "nestlink-development-candidate-build" and value["product"] == "NestLink"
            and value["repository"] == REPOSITORY and value["repository_node_id"] == REPOSITORY_ID
            and value["version"] == VERSION, "RC manifest repository or product identity differs")
    revision = value["source_revision"]
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "RC requires a full source commit")
    require(isinstance(value["cohort_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["cohort_sha256"]), "Invalid RC cohort hash")
    require(value["signing"] == SIGNING and value["production_update_eligible"] is False
            and value["user_full_functional_acceptance"] == "pending", "RC must retain development signing and pending user acceptance")
    cases = value["acceptance_cases"]
    require(isinstance(cases, list) and len(cases) == len(REQUIRED_CASES)
            and all(isinstance(item, dict) and set(item) == {"id", "status", "evidence_artifact_id"}
                    and isinstance(item["id"], str) and item["status"] == "pending" and item["evidence_artifact_id"] == "acceptance"
                    for item in cases) and {item["id"] for item in cases} == REQUIRED_CASES,
            "All 30 agreed RC acceptance cases must remain explicit and pending")
    products = value["artifacts"]
    require(isinstance(products, list) and len(products) == len(CURRENT_ROLES), "RC must contain all 18 artifact roles")
    uploads, roles, paths, names = [], set(), set(), {MANIFEST_NAME.casefold()}
    for item in products:
        require(isinstance(item, dict) and set(item) == {"id", "role", "path", "bytes", "sha256", "source_revision"},
                "Unexpected RC artifact fields")
        role = item["role"]
        require(isinstance(role, str) and role in CURRENT_ROLES and role not in roles
                and item["id"] == role and item["source_revision"] == revision, "RC artifact identity/source differs")
        roles.add(role)
        parts = portable(item["path"])
        require(len(parts) >= 2 and parts[0] == "files", "RC artifact must stay within files/")
        name = parts[-1]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", name)
                and name.casefold() not in names and item["path"].casefold() not in paths, "Unsafe or colliding GitHub asset name")
        require(type(item["bytes"]) is int and 0 < item["bytes"] <= MAX_ASSET_BYTES, "RC asset exceeds GitHub's 2 GiB limit")
        require(isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]), "Invalid RC artifact hash")
        path = artifact(bundle, item["path"])
        fixed_file(path, item["bytes"], item["sha256"])
        names.add(name.casefold())
        paths.add(item["path"].casefold())
        uploads.append({"asset_name": name, "local_path": path, "role": role, "bytes": item["bytes"], "sha256": item["sha256"]})
    require(roles == CURRENT_ROLES, "RC artifact role set differs")
    checksum = hashlib.sha256(raw).hexdigest()
    uploads.append({"asset_name": MANIFEST_NAME, "local_path": manifest, "role": "candidate-build-manifest",
                    "bytes": len(raw), "sha256": checksum})
    clean_source(source_root, revision)
    return {"source_root": source_root, "source_revision": revision, "manifest_sha256": checksum,
            "cohort_sha256": value["cohort_sha256"], "body": release_body(revision, checksum), "uploads": uploads}


def recheck_local(plan):
    clean_source(plan["source_root"], plan["source_revision"])
    for item in plan["uploads"]:
        absolute(item["local_path"])
        fixed_file(item["local_path"], item["bytes"], item["sha256"])


def verify_tag(github, revision):
    try:
        value = github.request("GET", "/repos/" + REPOSITORY + "/git/ref/tags/" + TAG)["object"]
    except Missing:
        return False
    for _ in range(5):
        if value.get("type") == "commit":
            require(value.get("sha") == revision, "Existing RC tag points to a different commit")
            return True
        require(value.get("type") == "tag" and isinstance(value.get("sha"), str)
                and re.fullmatch(r"[0-9a-f]{40}", value["sha"]), "Invalid RC tag object")
        value = github.request("GET", "/repos/" + REPOSITORY + "/git/tags/" + value["sha"])["object"]
    raise ValueError("RC tag indirection exceeds budget")


def validate_release(release, plan):
    require(isinstance(release, dict) and type(release.get("id")) is int and release["id"] > 0
            and release.get("tag_name") == TAG and type(release.get("draft")) is bool
            and release.get("prerelease") is True and release.get("name") == "NestLink " + VERSION
            and release.get("body") == plan["body"], "Existing RC release identity or pending acceptance declaration differs")


def remote_check(github, plan):
    base = "/repos/" + REPOSITORY
    value = github.request("GET", base)
    require(value.get("full_name") == REPOSITORY and value.get("node_id") == REPOSITORY_ID
            and value.get("default_branch") == "main", "Remote RC repository identity/default branch differs")
    main = github.request("GET", base + "/git/ref/heads/main")
    require(main.get("object", {}).get("type") == "commit" and main["object"].get("sha") == plan["source_revision"],
            "Remote main differs from the RC source commit")
    tag_exists = verify_tag(github, plan["source_revision"])
    try:
        release = github.request("GET", base + "/releases/tags/" + TAG)
    except Missing:
        # GitHub's tag endpoint only returns published releases. Drafts must
        # be discovered through the authenticated list, then read by ID.
        listed = github.pages(base + "/releases")
        require(all(isinstance(item, dict) and isinstance(item.get("tag_name"), str) for item in listed),
                "Malformed RC release inventory")
        matches = [item for item in listed if item["tag_name"] == TAG]
        require(len(matches) <= 1, "RC tag has ambiguous release entries")
        release = None
        if matches:
            candidate = matches[0]
            validate_release(candidate, plan)
            require(candidate["draft"] is True, "Published RC is absent from its tag lookup")
            release = github.request("GET", base + "/releases/" + str(candidate["id"]))
            require(isinstance(release, dict) and release.get("id") == candidate["id"] and release.get("draft") is True,
                    "RC draft identity or state changed during discovery")
    if release is not None:
        validate_release(release, plan)
        require(tag_exists, "Existing RC release has no matching tag")
    return tag_exists, release


def asset_identity(item, expected):
    require(isinstance(item, dict) and type(item.get("id")) is int and item["id"] > 0
            and item.get("name") == expected["asset_name"] and type(item.get("size")) is int
            and item["size"] == expected["bytes"] and item.get("state") == "uploaded",
            "Remote RC asset identity or byte count differs; overwriting is prohibited")


def remote_asset(github, listed, expected):
    asset_identity(listed, expected)
    item = github.request("GET", "/repos/" + REPOSITORY + "/releases/assets/" + str(listed["id"]))
    asset_identity(item, expected)
    require(item["id"] == listed["id"], "Remote RC asset ID changed")
    checksum = item.get("digest")
    if checksum is None:
        checksum = github.download_digest(REPOSITORY, item["id"], expected["bytes"])
        method = "download-sha256"
    else:
        require(isinstance(checksum, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", checksum), "Malformed GitHub SHA-256 digest")
        checksum = checksum[7:]
        method = "github-asset-id-sha256"
    require(checksum == expected["sha256"], "Remote RC asset SHA-256 differs; overwriting is prohibited")
    return {"asset_name": expected["asset_name"], "asset_id": item["id"], "role": expected["role"],
            "bytes": expected["bytes"], "sha256": checksum, "readback": method}


def inventory(github, release_id, plan):
    expected = {item["asset_name"].casefold(): item for item in plan["uploads"]}
    result, ids = {}, set()
    for item in github.pages("/repos/" + REPOSITORY + "/releases/" + str(release_id) + "/assets"):
        require(isinstance(item, dict) and isinstance(item.get("name"), str), "Malformed RC asset inventory")
        name = item["name"].casefold()
        require(name in expected and name not in result, "RC release contains unreviewed or colliding assets")
        record = remote_asset(github, item, expected[name])
        require(record["asset_id"] not in ids, "RC release contains duplicate asset IDs")
        ids.add(record["asset_id"])
        result[name] = record
    return result


def promote(args, github=None):
    require(args.action in ("verify", "upload-draft", "publish"), "Invalid RC publication action")
    plan = local_plan(args)
    github = github or GitHub(os.environ.get("GITHUB_TOKEN"))
    tag_exists, release = remote_check(github, plan)
    durable = inventory(github, release["id"], plan) if release is not None else {}
    if release is not None and release["draft"] is False:
        require(len(durable) == len(plan["uploads"]), "Published RC is incomplete; appending assets is prohibited")
    base_result = {"schema_version": 1, "kind": "nestlink-rc-publication", "repository": REPOSITORY,
                   "repository_node_id": REPOSITORY_ID, "version": VERSION, "tag": TAG,
                   "source_revision": plan["source_revision"], "manifest_sha256": plan["manifest_sha256"],
                   "cohort_sha256": plan["cohort_sha256"], "product_artifacts": len(CURRENT_ROLES),
                   "signing": SIGNING, "production_update_eligible": False, "user_full_functional_acceptance": "pending",
                   "pending_acceptance_cases": len(REQUIRED_CASES), "repository_deletion_performed": False,
                   "branch_deletion_performed": False}
    if args.action == "verify":
        recheck_local(plan)
        return {**base_result, "status": "verified", "remote_mutation_performed": False,
                "release_id": release["id"] if release else None, "tag_exists": tag_exists,
                "existing_assets_verified": len(durable), "expected_assets": len(plan["uploads"])}
    recheck_local(plan)
    mutated = False
    base = "/repos/" + REPOSITORY
    if not tag_exists:
        github.request("POST", base + "/git/refs", value={"ref": "refs/tags/" + TAG, "sha": plan["source_revision"]})
        mutated = True
        require(verify_tag(github, plan["source_revision"]), "Created RC tag failed readback")
    if release is None:
        release = github.request("POST", base + "/releases", value={"tag_name": TAG, "target_commitish": plan["source_revision"],
            "name": "NestLink " + VERSION, "body": plan["body"], "draft": True, "prerelease": True, "make_latest": "false"})
        mutated = True
        validate_release(release, plan)
        require(release["draft"] is True, "GitHub did not create the intended RC draft")
    release_id = release["id"]
    for expected in plan["uploads"]:
        name = expected["asset_name"]
        if name.casefold() in durable:
            continue
        require(release["draft"] is True, "Cannot append assets to a published RC")
        absolute(expected["local_path"])
        fixed_file(expected["local_path"], expected["bytes"], expected["sha256"])
        with expected["local_path"].open("rb") as stream:
            require(digest_stream(stream) == (expected["bytes"], expected["sha256"]), "RC upload stream changed")
            stream.seek(0)
            uploaded = github.request("POST", base + "/releases/" + str(release_id) + "/assets?name=" + urllib.parse.quote(name, safe=""),
                                      stream=stream, length=expected["bytes"], upload=True)
        mutated = True
        record = remote_asset(github, uploaded, expected)
        require(record["asset_id"] not in {value["asset_id"] for value in durable.values()}, "Uploaded RC asset ID collides")
        durable[name.casefold()] = record
    # After long uploads recheck all local bytes, repository/main/tag identity,
    # release declaration, and every immutable remote asset ID and digest.
    recheck_local(plan)
    final_tag, current_release = remote_check(github, plan)
    require(final_tag and current_release is not None and current_release["id"] == release_id
            and current_release["draft"] == release["draft"], "RC source or release changed during upload")
    final_assets = inventory(github, release_id, plan)
    def immutable_assets(records):
        return {name: {key: value for key, value in item.items() if key != "readback"} for name, item in records.items()}
    # GitHub may finish calculating its digest between two reads. Moving from
    # downloaded SHA-256 to the same API SHA-256 changes no immutable byte.
    require(immutable_assets(final_assets) == immutable_assets(durable) and len(final_assets) == len(plan["uploads"]),
            "RC asset inventory changed during upload")
    if args.action == "publish" and current_release["draft"]:
        release = github.request("PATCH", base + "/releases/" + str(release_id),
                                 value={"draft": False, "prerelease": True, "make_latest": "false"})
        mutated = True
        validate_release(release, plan)
        require(release["draft"] is False, "GitHub did not publish the RC prerelease")
    final = github.request("GET", base + "/releases/" + str(release_id))
    validate_release(final, plan)
    require(final["id"] == release_id and (args.action != "publish" or final["draft"] is False), "Final RC publication state differs")
    require(verify_tag(github, plan["source_revision"]), "Final RC tag is absent")
    return {**base_result, "status": "published-prerelease" if final["draft"] is False else "draft-uploaded",
            "release_id": release_id, "remote_mutation_performed": mutated, "remote_asset_readback_verified": True,
            "uploads": sorted(final_assets.values(), key=lambda item: item["asset_name"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("verify", "upload-draft", "publish"))
    parser.add_argument("--repository", choices=(REPOSITORY,), required=True)
    for name in ("manifest", "bundle", "source-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        # Reserve a create-new receipt before any remote action. It must not
        # dirty the source checkout or change frozen bundle bytes.
        output = Path(os.path.abspath(args.output))
        require(not output.exists() and not output.is_symlink(), "RC receipt must be create-new")
        require(not output.is_relative_to(Path(os.path.abspath(args.source_root)))
                and not output.is_relative_to(Path(os.path.abspath(args.bundle))), "RC receipt must be outside source and bundle")
        output.parent.mkdir(parents=True, exist_ok=True)
        absolute(output)
        with output.open("x", encoding="utf-8", newline="\n") as receipt:
            result = promote(args)
            json.dump(result, receipt, indent=2, sort_keys=True)
            receipt.write("\n")
            receipt.flush()
            os.fsync(receipt.fileno())
        print(json.dumps({key: value for key, value in result.items() if key != "uploads"}))
    except (ValueError, OSError, TypeError, KeyError, Missing, subprocess.SubprocessError) as error:
        print("RC publication refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
