#!/usr/bin/env python3
"""Verify or publish the pinned, unsigned NestLink RC to its new repository.

verify performs no remote writes. upload-draft and publish only create the
fixed tag, a prerelease, and missing immutable assets. Existing conflicts are
refused; no action deletes or replaces repositories, branches, tags or assets.
This separate RC policy does not relax any formal or historical release gate.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
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
import zipfile

REPOSITORY = "ZHanry/NestLink"
REPOSITORY_ID = "R_kgDOVNHMvg"
VERSION = "0.8.1-rc.1"
TAG = "v" + VERSION
MAX_ASSET_BYTES = 2 * 1024**3
MANIFEST_NAME = "candidate-build-manifest.json"
REMEDIATION_NAME = "remediation-acceptance.zip"
NETWORK_NAME = "network-rewrite-acceptance.zip"
DEFERRED_NAME = "rc-acceptance-status.json"
DEFERRED_POLICY = "config/rc-deferred-acceptance.json"
REPORT_SHA256 = "c6cac00cef64627e023eabf78fa77750b2093e9e1138567ad3ecad112c49905c"
REMEDIATION_CASES = frozenset((
    "N01", "N02", "N03", "N04", "M01", "M02", "M03", "M04", "T01", "T02",
    "R01", "U01", "U02", "U03", "Q01", "original-edge-100", "stratified-uu-200",
    "first-frame-p95", "native-1080p60", "input-display-ab", "weak-network-adaptation",
    "concurrent-file-input", "recovery-p95", "cross-day-24h-soak", "revocation-and-exit",
))
MAX_REMEDIATION_BYTES = 64 * 1024**2
CURRENT_ROLES = frozenset((
    "windows-x64-setup", "windows-x64-privileged-setup",
    "linux-x64-server", "linux-arm64-server",
    "linux-x64-network", "linux-arm64-network",
    "web-static", "oci-x64", "oci-arm64", "source", "sbom", "licenses", "materials", "acceptance",
    "native-payload-manifest", "native-packages-manifest",
))
REQUIRED_CASES = frozenset((
    "windows-10-installed", "windows-11-installed", "windows-privileged-input",
    "linux-x64-server-installed", "linux-arm64-server-installed",
    "linux-x64-network-installed", "linux-arm64-network-installed",
    "chrome-current", "edge-current", "firefox-current", "company-to-home",
    "mobile-to-home", "90-minute-soak", "turn-capacity-and-revoke", "signature-windows",
    "signature-linux-update", "signature-oci", "install-upgrade-rollback-uninstall",
    "reinstall-new-identity-retained-data", "schema-migration-and-interruption-recovery", "license-and-source-audit",
))
SIGNING = {"windows": "not-configured", "linux_update": "not-configured", "oci": "not-configured"}


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


def reviewed_acceptance(bundle, revision, manifest_sha256, *, name=REMEDIATION_NAME,
                        kind="nestlink-remediation-acceptance", required_cases=REMEDIATION_CASES,
                        bindings=None, metadata_fields=frozenset(), case_fields=frozenset()):
    """Check reviewed evidence binding, not the truth of a human measurement.

    Development bundles deliberately contain pending platform cases. Publishing
    additionally requires this independent, fully reviewed report evidence pack.
    It is never generated with passed statuses by the development producer.
    """
    bindings = {"report_sha256": REPORT_SHA256} if bindings is None else bindings
    path = artifact(bundle, name)
    require(0 < regular(path).st_size <= MAX_REMEDIATION_BYTES, "Report evidence archive exceeds its byte budget")
    with path.open("rb") as stream:
        raw = stream.read(MAX_REMEDIATION_BYTES + 1)
    require(0 < len(raw) <= MAX_REMEDIATION_BYTES, "Report evidence archive exceeds its byte budget")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries, folded, total = {}, set(), 0
            require(1 < len(archive.infolist()) <= 257, "Unexpected report evidence entry count")
            for item in archive.infolist():
                portable(item.filename)
                require(item.filename == item.orig_filename and item.filename.casefold() not in folded and not item.is_dir()
                        and not item.flag_bits & 1
                        and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                        and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG),
                        "Unsafe or duplicate report evidence entry")
                require(0 < item.file_size <= 16 * 1024**2, "Report evidence entry exceeds its byte budget")
                total += item.file_size
                require(total <= MAX_REMEDIATION_BYTES, "Expanded report evidence exceeds its byte budget")
                folded.add(item.filename.casefold())
                entries[item.filename] = item
            metadata = name.removesuffix(".zip") + ".json"
            require(metadata in entries and entries[metadata].file_size <= 1024**2, "Missing or oversized report acceptance metadata")
            value = json.loads(archive.read(metadata).decode("utf-8"), object_pairs_hook=unique_fields)
            fields = {"schema_version", "kind", "repository", "version", "source_revision", "manifest_sha256",
                      "status", "reviewer", "reviewed_at", "cases", "evidence"} | set(bindings) | set(metadata_fields)
            require(isinstance(value, dict) and set(value) == fields, "Unexpected report acceptance fields")
            require(type(value["schema_version"]) is int and value["schema_version"] == 1
                    and value["kind"] == kind and value["repository"] == REPOSITORY
                    and value["version"] == VERSION and value["source_revision"] == revision
                    and value["manifest_sha256"] == manifest_sha256
                    and all(value[key] == expected for key, expected in bindings.items()),
                    "Report acceptance does not bind this report and candidate")
            require(value["status"] == "passed", "All report acceptance cases must pass before RC publication")
            require(isinstance(value["reviewer"], str) and 1 <= len(value["reviewer"].strip()) <= 200
                    and all(ord(ch) >= 32 and ord(ch) != 127 for ch in value["reviewer"]), "Report evidence requires a named reviewer")
            timestamp = value["reviewed_at"]
            require(isinstance(timestamp, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp),
                    "Report evidence requires a UTC review timestamp")
            reviewed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            require(reviewed <= datetime.now(timezone.utc), "Report review timestamp is in the future")
            evidence = value["evidence"]
            require(isinstance(evidence, list) and 0 < len(evidence) <= 256, "Missing report evidence descriptors")
            verified = set()
            for item in evidence:
                require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"}, "Unexpected report evidence descriptor")
                parts = portable(item["path"])
                name = item["path"]
                require(len(parts) >= 2 and parts[0] == "evidence" and name in entries and name not in verified,
                        "Missing or duplicate report evidence file")
                require(type(item["bytes"]) is int and item["bytes"] == entries[name].file_size
                        and isinstance(item["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]),
                        "Invalid report evidence size or digest")
                require(hashlib.sha256(archive.read(name)).hexdigest() == item["sha256"], "Report evidence digest differs")
                verified.add(name)
            require(set(entries) == verified | {metadata}, "Report archive contains undeclared evidence")
            cases, seen, referenced = value["cases"], set(), set()
            require(isinstance(cases, list) and len(cases) == len(required_cases), "All reviewed acceptance cases are required")
            for item in cases:
                require(isinstance(item, dict) and set(item) == {"id", "status", "evidence"} | set(case_fields)
                        and isinstance(item["id"], str) and item["id"] in required_cases and item["id"] not in seen
                        and item["status"] == "passed", "Every report case must be unique and passed")
                refs = item["evidence"]
                require(isinstance(refs, list) and 0 < len(refs) <= len(verified)
                        and all(isinstance(ref, str) and ref in verified for ref in refs)
                        and len(set(refs)) == len(refs), "Every report case requires verified evidence")
                seen.add(item["id"])
                referenced.update(refs)
            require(seen == required_cases and referenced == verified, "Report case/evidence coverage differs")
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError) as error:
        raise ValueError("Invalid report evidence archive") from error
    return {"asset_name": name, "local_path": path, "role": kind.removeprefix("nestlink-"),
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def remediation_acceptance(bundle, revision, manifest_sha256):
    return reviewed_acceptance(bundle, revision, manifest_sha256)


def network_acceptance(bundle, revision, manifest_sha256, source_root, artifact_hashes):
    """Verify reviewed full-scope binding; metadata never proves measurements.

    Reuse the existing bounded archive/path/hash verifier. A separate archive
    avoids a source-SHA cycle in progress.json and cannot substitute for the
    inherited report gate or turn failed/not-run cases into passed evidence.
    """
    base = source_root / "docs/network-rewrite"
    spec_path = base / "NESTLINK-REWRITE-SPEC.md"
    tasks_path = base / "NESTLINK-TASKS.json"
    for path in (spec_path, tasks_path, source_root / "Cargo.lock"):
        absolute(path)
        regular(path)
    tasks = json.loads(tasks_path.read_text(encoding="utf-8"), object_pairs_hook=unique_fields)
    cases = {item["id"]: item for item in tasks["acceptance_cases"]}
    packages = {item["id"]: item for item in tasks["tasks"]}
    require(len(tasks["acceptance_cases"]) == len(cases) == 70
            and len(tasks["tasks"]) == len(packages) == 41
            and set(cases) == {f"AC{index:02d}" for index in range(1, 71)}
            and set(packages) == {f"W{index:02d}" for index in range(41)},
            "The full 70-case/41-work-package network scope is required")
    descriptor = reviewed_acceptance(
        bundle, revision, manifest_sha256, name=NETWORK_NAME,
        kind="nestlink-network-rewrite-acceptance", required_cases=frozenset(cases),
        bindings={"specification_sha256": hashlib.sha256(spec_path.read_bytes()).hexdigest(),
                  "tasks_sha256": hashlib.sha256(tasks_path.read_bytes()).hexdigest()},
        metadata_fields={"work_packages"},
        case_fields={"task_ids", "evidence_levels", "build_provenance", "execution_provenance"})
    with zipfile.ZipFile(descriptor["local_path"]) as archive:
        value = json.loads(archive.read("network-rewrite-acceptance.json"), object_pairs_hook=unique_fields)
    work = value["work_packages"]
    require(isinstance(work, list) and len(work) == len(packages), "Every network work package requires review")
    seen = set()
    for item in work:
        require(isinstance(item, dict) and set(item) == {"id", "status"}
                and isinstance(item["id"], str) and item["id"] in packages and item["id"] not in seen,
                "Invalid or duplicate reviewed network work package")
        required = packages[item["id"]]["required_evidence_levels"]
        allowed = {"verified_target"} if set(required) & {"L3", "L4"} else {"verified_lab", "verified_target"}
        require(item["status"] in allowed, "Unfinished network work package cannot qualify publication")
        seen.add(item["id"])
    lock = hashlib.sha256((source_root / "Cargo.lock").read_bytes()).hexdigest()
    for item in value["cases"]:
        expected = cases[item["id"]]
        require(item["task_ids"] == expected["task_ids"], "Network case/work-package mapping differs")
        levels = item["evidence_levels"]
        require(isinstance(levels, list) and len(levels) == len(set(levels))
                and set(levels) <= {"L0", "L1", "L2", "L3", "L4"}
                and set(expected["required_evidence_levels"]) <= set(levels),
                "Network case lacks its original required evidence levels")
        build = item["build_provenance"]
        fields = {"repository", "source_revision", "dependency_lock_sha256", "workflow", "workflow_revision",
                  "run_id", "run_attempt", "job_id", "runner_environment", "artifact_sha256"}
        require(isinstance(build, dict) and set(build) == fields
                and build["repository"] == REPOSITORY and build["source_revision"] == revision
                and build["dependency_lock_sha256"] == lock and build["workflow_revision"] == revision
                and build["runner_environment"] == "github-hosted"
                and isinstance(build["workflow"], str)
                and re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", build["workflow"])
                and all(type(build[key]) is int and build[key] > 0 for key in ("run_id", "run_attempt", "job_id"))
                and build["artifact_sha256"] in artifact_hashes,
                "Network build provenance must bind the exact hosted candidate bytes")
        executions = item["execution_provenance"]
        require(isinstance(executions, list) and 0 < len(executions) <= 32,
                "Network case requires actual execution provenance")
        observed = set()
        for execution in executions:
            require(isinstance(execution, dict) and set(execution) == {
                "kind", "source_revision", "artifact_sha256", "evidence_levels", "environment", "evidence"}
                    and execution["kind"] in ("hosted_actions", "target_device")
                    and execution["source_revision"] == revision
                    and execution["artifact_sha256"] == build["artifact_sha256"]
                    and isinstance(execution["environment"], dict) and execution["environment"],
                    "Network execution provenance differs from its build")
            actual = execution["evidence_levels"]
            refs = execution["evidence"]
            require(isinstance(actual, list) and actual and len(actual) == len(set(actual))
                    and set(actual) <= set(levels)
                    and (not set(actual) & {"L3", "L4"} or execution["kind"] == "target_device")
                    and isinstance(refs, list) and refs and len(refs) == len(set(refs))
                    and all(isinstance(ref, str) and ref in item["evidence"] for ref in refs),
                    "Hosted builds cannot substitute for required target execution")
            observed.update(actual)
        require(observed == set(levels), "Network evidence level coverage differs from actual execution")
    return descriptor


def release_body(revision, checksum):
    return ("NestLink " + VERSION + " 开发候选版。\n\n"
            "- 统一网络内核接入远控与四协议服务；空间成员、路径、业务和原始 IP 访问分别授权。\n"
            "- 新增受管 TUN、子网/重叠映射、标准 WireGuard 接入、私有目录与 Web 网关、多入口 HA 和有限离线路径。\n"
            "- Windows 媒体、实时队列、弱网策略、安装升级和撤销清理均按同源制品与适用目标设备证据核对。\n"
            "- 完整范围、升级限制及证据边界：https://github.com/ZHanry/NestLink/blob/" + revision + "/docs/network-rewrite/RELEASE-0.8.0-RC.md\n\n"
            "报告验收：15 个研发工作包与 10 项体验门槛的审阅凭据随 remediation-acceptance.zip 发布，并绑定本候选清单摘要。适用硬件、网络、原始样本与限制以包内证据为准；发布脚本只核验证据结构和绑定，不代替实测或人工审阅。\n\n"
            "网络重构验收：41 个工作包、70 组用例的独立审阅材料随 network-rewrite-acceptance.zip 发布。原始规格、任务映射、同源托管构建与实际执行来源分别绑定；未执行、失败或缺少必需现场证据不能取得发布资格。\n\n"
            "升级：请同时升级服务器、Web 和双方客户端。原生跨网络回退需管理员允许服务器转发及双方 relay；浏览器需可达 STUN，受限网络还需注册 TURN 节点并允许中继。升级不会自动放宽服务器策略，原生 WSS 不能替代浏览器 TURN。\n"
            "升级将执行对应制品的数据库迁移；升级前备份。已写入新授权状态的数据库须前向修复，禁止恢复旧授权数据库快照。恢复登录不会恢复屏幕、输入或文件授权。\n"
            "部署与排障：https://github.com/ZHanry/NestLink/blob/" + revision + "/docs/REMOTE-CONNECTION.md\n\n"
            f"Source commit: {revision}. All {len(CURRENT_ROLES)} product artifacts are bound to this clean source commit.\n"
            "candidate-build-manifest.json SHA-256: " + checksum + ".\n\n"
            "Windows Authenticode, Linux update and OCI signing are not configured. "
            "Production update eligibility: false. Report remediation acceptance: passed with reviewed evidence.\n"
            f"The frozen development manifest retains its {len(REQUIRED_CASES)} pending platform, signing, physical-device and real-network cases; "
            "the separate report evidence does not rewrite that historical checklist or claim formal signing. "
            "Clients support Windows 10/11 x64 and current Web browsers; Linux x64/ARM64 provides backend services.\n")


def deferred_status(source_root, revision, checksum):
    """Disclose actual source statuses; never manufacture reviewed passes."""
    paths = (DEFERRED_POLICY, "docs/network-rewrite/NESTLINK-TASKS.json",
             "docs/network-rewrite/NESTLINK-REWRITE-SPEC.md")
    inputs = {name: artifact(source_root, name).read_bytes() for name in paths}
    policy = json.loads(inputs[DEFERRED_POLICY], object_pairs_hook=unique_fields)
    require(policy.get("schema_version") == 1 and policy.get("repository") == REPOSITORY
            and policy.get("version") == VERSION and policy.get("prerelease_only") is True
            and policy.get("production_update_eligible") is False
            and policy.get("authorization") == "这些发布后我再自己验收",
            "Missing explicit user deferral policy for this prerelease")
    tasks = json.loads(inputs[paths[1]], object_pairs_hook=unique_fields)
    require({item["id"] for item in tasks["tasks"]} == {f"W{i:02d}" for i in range(41)}
            and len(tasks["tasks"]) == 41
            and {item["id"] for item in tasks["acceptance_cases"]} == {f"AC{i:02d}" for i in range(1, 71)}
            and len(tasks["acceptance_cases"]) == 70, "Incomplete source acceptance inventory")
    return {"schema_version": 1, "kind": "nestlink-user-deferred-rc-acceptance",
            "repository": REPOSITORY, "version": VERSION, "source_revision": revision,
            "manifest_sha256": checksum, "status": "incomplete-user-acceptance-pending",
            "production_update_eligible": False, "formal_qualification_claimed": False,
            "inputs": {name: hashlib.sha256(raw).hexdigest() for name, raw in inputs.items()},
            "policy": policy, "work_packages": tasks["tasks"], "cases": tasks["acceptance_cases"],
            "platform_cases": [{"id": name, "status": "pending"} for name in sorted(REQUIRED_CASES)],
            "report_remediation_acceptance": "not-qualified",
            "network_rewrite_acceptance": "not-qualified"}


def deferred_acceptance(bundle, revision, checksum, source_root):
    path = artifact(bundle, DEFERRED_NAME)
    require(0 < regular(path).st_size <= 8 * 1024**2, "Deferred acceptance disclosure exceeds budget")
    raw = path.read_bytes()
    actual = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_fields)
    require(actual == deferred_status(source_root, revision, checksum),
            "Deferred acceptance disclosure differs from actual source or user policy")
    return {"asset_name": DEFERRED_NAME, "local_path": path, "role": "deferred-acceptance-status",
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def deferred_release_body(revision, checksum):
    return ("NestLink 0.8.1RC（0.8.1-rc.1）预览版。\n\n"
            "本版按用户明确要求先发布，真机、手机、独立公网/NAT、固定双入口和跨日验收由用户发布后完成。"
            "全功能、性能和正式发布资格尚未通过；各工作包与70组用例的真实状态见 rc-acceptance-status.json。\n\n"
            "新增空间与分项授权、统一承载与安全恢复、私有服务与名称、TUN/子网、标准 WireGuard、"
            "浏览器网关、多入口与有限离线入口。Windows/Web/Linux 制品由同一源码在 GitHub Actions 构建。\n\n"
            "已知限制与待验：\n"
            "- Luanti 25秒断线显示检查失败，原检查、门槛和失败证据保留。\n"
            "- 第二台 Windows、GPU/H.264/HEVC/HDR、持续媒体性能及 VPN 共存仍需真机验收。\n"
            "- Android/iOS 标准 WireGuard、两处独立公网/NAT、固定入口与双 edge HA、配对网络性能和跨日24小时长稳待验。\n"
            "- Windows Authenticode、Linux更新和OCI正式签名未配置。本版不进入生产自动更新。\n\n"
            "升级前备份；服务器、Web与双方客户端一起升级。已写入新授权状态后使用前向修复，"
            "不要恢复旧授权数据库快照。恢复登录不会恢复屏幕、输入或文件授权。\n\n"
            "范围、操作及回滚：https://github.com/ZHanry/NestLink/blob/" + revision
            + "/docs/network-rewrite/RELEASE-0.8.0-RC.md\n"
            "部署：https://github.com/ZHanry/NestLink/blob/" + revision + "/docs/REMOTE-CONNECTION.md\n\n"
            "Source commit: " + revision + ".\n"
            "candidate-build-manifest.json SHA-256: " + checksum + ".\n"
            "Prerelease only. User acceptance pending. Production update eligibility: false.\n")


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
    require(isinstance(products, list) and len(products) == len(CURRENT_ROLES), "RC must contain every Windows/Web/backend artifact role")
    uploads, roles, paths, names = [], set(), set(), {MANIFEST_NAME.casefold(), REMEDIATION_NAME.casefold(), NETWORK_NAME.casefold(), DEFERRED_NAME.casefold()}
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
    deferred = getattr(args, "deferred_target_acceptance", False)
    if deferred:
        uploads.append(deferred_acceptance(bundle, revision, checksum, source_root))
    else:
        uploads.append(network_acceptance(bundle, revision, checksum, source_root,
                                          {item["sha256"] for item in products}))
        uploads.append(remediation_acceptance(bundle, revision, checksum))
    clean_source(source_root, revision)
    return {"source_root": source_root, "source_revision": revision, "manifest_sha256": checksum,
            "cohort_sha256": value["cohort_sha256"], "deferred_target_acceptance": deferred,
            "body": deferred_release_body(revision, checksum) if deferred else release_body(revision, checksum),
            "uploads": uploads}


def recheck_local(plan):
    clean_source(plan["source_root"], plan["source_revision"])
    for item in plan["uploads"]:
        absolute(item["local_path"])
        fixed_file(item["local_path"], item["bytes"], item["sha256"])
    bundle = plan["uploads"][-1]["local_path"].parent
    if plan.get("deferred_target_acceptance"):
        deferred_acceptance(bundle, plan["source_revision"], plan["manifest_sha256"], plan["source_root"])
    else:
        remediation_acceptance(bundle, plan["source_revision"], plan["manifest_sha256"])
        network_acceptance(bundle, plan["source_revision"], plan["manifest_sha256"],
                           plan["source_root"], {item["sha256"] for item in plan["uploads"] if item["role"] in CURRENT_ROLES})


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
    name = "NestLink 0.8.1RC" if plan.get("deferred_target_acceptance") else "NestLink " + VERSION
    require(isinstance(release, dict) and type(release.get("id")) is int and release["id"] > 0
            and release.get("tag_name") == TAG and type(release.get("draft")) is bool
            and release.get("prerelease") is True and release.get("name") == name
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
                   "report_remediation_acceptance": "passed", "report_acceptance_cases": len(REMEDIATION_CASES),
                   "report_evidence_sha256": plan["uploads"][-1]["sha256"],
                   "network_rewrite_acceptance": "passed", "network_acceptance_cases": 70,
                   "network_work_packages": 41, "network_evidence_sha256": plan["uploads"][-2]["sha256"],
                   "branch_deletion_performed": False}
    if plan["deferred_target_acceptance"]:
        base_result.update(report_remediation_acceptance="not-qualified",
                           report_evidence_sha256=None, network_rewrite_acceptance="not-qualified",
                           network_evidence_sha256=None, deferred_target_acceptance=True,
                           deferred_acceptance_sha256=plan["uploads"][-1]["sha256"])
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
            "name": "NestLink 0.8.1RC" if plan["deferred_target_acceptance"] else "NestLink " + VERSION,
            "body": plan["body"], "draft": True, "prerelease": True, "make_latest": "false"})
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
        recheck_local(plan)
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
    parser.add_argument("--deferred-target-acceptance", action="store_true",
                        help="User-authorized prerelease with exact, incomplete acceptance disclosure; no formal qualification")
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
