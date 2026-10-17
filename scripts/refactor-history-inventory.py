"""Read-only local history inventory; never imports, fetches, or approves source reuse."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
ENV = {
    **os.environ,
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_TERMINAL_PROMPT": "0",
}
EXCLUDED_REFS = {"hub": {"refs/heads/codex/nestlink-v15-core"}}
LICENSE_NAME = re.compile(r"^(?:licen[cs]e(?:[-._].*)?|copying(?:[-._].*)?|notice(?:[-._].*)?|copyright(?:[-._].*)?)$", re.I)
OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def git(repo, *args, data=None, optional=False):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=ENV, check=False,
    )
    if result.returncode and not optional:
        # Git stderr can contain private paths/URLs. Preserve only its digest.
        raise RuntimeError(f"git {args[0]} failed ({result.returncode}); stderr SHA256 {digest(result.stderr)}")
    return result.stdout if not result.returncode else None


def git_text(repo, *args, **kwargs):
    output = git(repo, *args, **kwargs)
    return None if output is None else output.decode("utf-8", "replace").strip()


def batch_objects(repo, ids):
    """Bounded Git object reads; yield bytes without writing historical source."""
    for offset in range(0, len(ids), 256):
        chunk = ids[offset:offset + 256]
        payload = git(repo, "cat-file", "--batch", data=("\n".join(chunk) + "\n").encode())
        position = 0
        for expected in chunk:
            end = payload.index(b"\n", position)
            fields = payload[position:end].decode("ascii").split()
            if len(fields) != 3 or fields[0] != expected:
                raise RuntimeError("Unexpected/missing Git object in read-only batch")
            size = int(fields[2])
            position = end + 1
            content = payload[position:position + size]
            if len(content) != size or payload[position + size:position + size + 1] != b"\n":
                raise RuntimeError("Truncated Git object in read-only batch")
            position += size + 1
            yield expected, fields[1], content


def tree_entries(content, oid_bytes):
    position = 0
    while position < len(content):
        separator = content.index(b" ", position)
        end = content.index(b"\0", separator)
        mode = content[position:separator].decode("ascii")
        name = content[separator + 1:end].decode("utf-8", "backslashreplace")
        entry_oid = content[end + 1:end + 1 + oid_bytes].hex()
        position = end + 1 + oid_bytes
        yield mode, name, entry_oid


def safe_source_url(raw):
    """Retain public repository provenance only; omit credentials/query/fragment."""
    raw = raw.strip()
    if raw.startswith(("../", "./")) and re.fullmatch(r"[./A-Za-z0-9_-]+", raw):
        return {"relative_repository": raw, "resolution_verified": False}
    if re.match(r"^[^/@\s]+@[^/:\s]+:", raw):
        raw = "ssh://" + raw.replace(":", "/", 1)
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if host in {"github.com", "gitlab.com", "codeberg.org"} and re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?", parsed.path):
            return {"public_repository_url": f"https://{host}{parsed.path}", "credentials_query_fragment_omitted": True}
    except ValueError:
        pass
    return {"unrecognized_url_sha256": digest(raw.encode()), "url_disclosed": False}


def license_identity(content):
    """Text identification is evidence, not a legal/compatibility approval."""
    text = content.decode("utf-8", "replace")
    compact = " ".join(text.split())
    identities = []
    signatures = {
        "AGPL-3.0-text": "GNU AFFERO GENERAL PUBLIC LICENSE Version 3",
        "GPL-3.0-text": "GNU GENERAL PUBLIC LICENSE Version 3",
        "GPL-2.0-text": "GNU GENERAL PUBLIC LICENSE Version 2",
        "LGPL-2.1-text": "GNU LESSER GENERAL PUBLIC LICENSE Version 2.1",
        "Apache-2.0-text": "Apache License Version 2.0",
        "MIT-text": "Permission is hereby granted, free of charge, to any person obtaining a copy",
        "BSD-family-text": "Redistribution and use in source and binary forms",
    }
    for name, marker in signatures.items():
        if marker.lower() in compact.lower():
            identities.append(name)
    # Emit a bounded SPDX expression, never arbitrary historical prose.
    spdx = sorted(set(re.findall(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+() -]{1,120})", text)))
    return {"text_signatures": identities, "spdx_identifiers": spdx, "legal_reuse_approved": False}


def snapshot_tree(repo, revision):
    entries = []
    for line in git(repo, "ls-tree", "-rz", revision).split(b"\0"):
        if not line:
            continue
        header, raw_path = line.split(b"\t", 1)
        mode, kind, object_id = header.decode("ascii").split()
        path = raw_path.decode("utf-8", "backslashreplace")
        if mode == "160000" or LICENSE_NAME.match(path.rsplit("/", 1)[-1]) or path.rsplit("/", 1)[-1] == ".gitmodules":
            entries.append({"path": path, "mode": mode, "type": kind, "oid": object_id})
    return entries


def inventory_repository(name, repo, baseline, artifact_dir):
    print(f"Auditing local objects: {name}", flush=True)
    before = git(repo, "for-each-ref", "--format=%(refname)%09%(objectname)%09%(objecttype)%09%(*objectname)%09%(*objecttype)")
    refs = []
    for line in before.decode().splitlines():
        ref, object_id, kind, peeled, peeled_kind = line.split("\t")
        excluded = ref in EXCLUDED_REFS.get(name, set())
        refs.append({
            "ref": ref, "oid": object_id, "type": kind,
            "peeled_oid": peeled or None, "peeled_type": peeled_kind or None,
            "scope": "current_nestlink_development_excluded" if excluded else "local_legacy_candidate",
            "proposed_preservation_ref": None if excluded else f"refs/tags/legacy/{name}/{ref.removeprefix('refs/')}",
        })
    observed_head = git_text(repo, "rev-parse", "--verify", "HEAD^{commit}", optional=True)
    roots = sorted({ref["oid"] for ref in refs if ref["scope"] == "local_legacy_candidate"} | ({observed_head} if observed_head else set()) | ({baseline} if baseline else set()))
    if not roots:
        raise RuntimeError(f"No refs, HEAD or baseline to inventory in {name}")
    revisions = ("\n".join(roots) + "\n").encode()
    object_lines = git(repo, "rev-list", "--objects", "--missing=print", "--stdin", data=revisions).decode("utf-8", "backslashreplace").splitlines()
    object_paths = {}
    missing = []
    for line in object_lines:
        object_id, _, path = line.partition(" ")
        if object_id.startswith("?"):
            missing.append(object_id[1:])
        else:
            if not OID.fullmatch(object_id):
                raise RuntimeError("Invalid Git object ID")
            object_paths[object_id] = path or None
    ids = sorted(object_paths)
    checked = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)", data=("\n".join(ids) + "\n").encode()).decode().splitlines()
    objects = {}
    for line in checked:
        fields = line.split()
        if len(fields) != 3:
            missing.append(fields[0])
            continue
        objects[fields[0]] = {"type": fields[1], "bytes": int(fields[2])}
    tree_ids = sorted(oid for oid, info in objects.items() if info["type"] == "tree")
    license_occurrences = defaultdict(list)
    gitmodule_occurrences = defaultdict(list)
    gitlinks = []
    oid_bytes = 32 if git_text(repo, "rev-parse", "--show-object-format") == "sha256" else 20
    for tree_id, _, content in batch_objects(repo, tree_ids):
        for mode, filename, object_id in tree_entries(content, oid_bytes):
            item = {"parent_tree_oid": tree_id, "entry_name": filename}
            if mode == "160000":
                gitlinks.append({**item, "commit_oid": object_id})
            elif mode in {"100644", "100755"} and LICENSE_NAME.match(filename):
                license_occurrences[object_id].append(item)
            elif filename == ".gitmodules" and mode in {"100644", "100755"}:
                gitmodule_occurrences[object_id].append(item)
    licenses = []
    modules = []
    read_ids = sorted(set(license_occurrences) | set(gitmodule_occurrences))
    for object_id, _, content in batch_objects(repo, read_ids):
        if object_id in license_occurrences:
            licenses.append({"oid": object_id, "sha256": digest(content), "bytes": len(content), "tree_occurrences": license_occurrences[object_id], **license_identity(content)})
        if object_id in gitmodule_occurrences:
            paths, sources = [], []
            for line in content.decode("utf-8", "replace").splitlines():
                key, separator, value = line.strip().partition("=")
                if separator and key.strip() == "path":
                    paths.append(value.strip())
                elif separator and key.strip() == "url":
                    sources.append(safe_source_url(value))
            modules.append({"oid": object_id, "sha256": digest(content), "bytes": len(content), "tree_occurrences": gitmodule_occurrences[object_id], "declared_paths": paths, "declared_sources": sources, "parse_scope": "literal path/url lines only; no config includes or URL resolution"})
    small_blobs = sorted(oid for oid, info in objects.items() if info["type"] == "blob" and info["bytes"] <= 1024)
    lfs = []
    common_dir = Path(git_text(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    for object_id, _, content in batch_objects(repo, small_blobs):
        if not content.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            continue
        lfs_oid = re.search(rb"^oid sha256:([0-9a-f]{64})$", content, re.M)
        lfs_size = re.search(rb"^size ([0-9]+)$", content, re.M)
        if lfs_oid and lfs_size:
            sha256 = lfs_oid[1].decode()
            local = common_dir / "lfs/objects" / sha256[:2] / sha256[2:4] / sha256
            available = local.is_file()
            verified = available and local.stat().st_size == int(lfs_size[1]) and file_digest(local) == sha256
            lfs.append({"pointer_oid": object_id, "sample_path": object_paths.get(object_id), "sha256": sha256, "bytes": int(lfs_size[1]), "standard_local_store_available": available, "local_bytes_verified": verified})
    snapshots = {}
    for ref in refs:
        if ref["scope"] != "local_legacy_candidate":
            continue
        commit_id = git_text(repo, "rev-parse", "--verify", ref["oid"] + "^{commit}", optional=True)
        if commit_id and commit_id not in snapshots:
            snapshots[commit_id] = snapshot_tree(repo, commit_id)
    if baseline and baseline not in snapshots:
        snapshots[baseline] = snapshot_tree(repo, baseline)
    if observed_head and observed_head not in snapshots:
        snapshots[observed_head] = snapshot_tree(repo, observed_head)
    commits = git(repo, "rev-list", "--stdin", data=revisions).decode().splitlines()
    root_commits = git(repo, "rev-list", "--max-parents=0", "--stdin", data=revisions).decode().splitlines()
    large = [{"oid": oid, "bytes": info["bytes"], "sample_path": object_paths[oid]} for oid, info in objects.items() if info["type"] == "blob" and info["bytes"] >= 10 * 1024 * 1024]
    large.sort(key=lambda item: (-item["bytes"], item["oid"]))
    partial = git_text(repo, "config", "--local", "--get-regexp", r"^(extensions\.partialclone|remote\..*\.promisor|remote\..*\.partialclonefilter)$", optional=True)
    after = git(repo, "for-each-ref", "--format=%(refname)%09%(objectname)%09%(objecttype)%09%(*objectname)%09%(*objecttype)")
    changed = before != after
    legacy_before = [ref for ref in refs if ref["scope"] == "local_legacy_candidate"]
    after_legacy = [line for line in after.decode().splitlines() if line.partition("\t")[0] not in EXCLUDED_REFS.get(name, set())]
    before_legacy = [line for line in before.decode().splitlines() if line.partition("\t")[0] not in EXCLUDED_REFS.get(name, set())]
    details = {
        "repository_key": name, "baseline_revision": baseline, "refs": refs,
        "reachable_commit_oids": sorted(set(commits)), "root_commit_oids": sorted(set(root_commits)),
        "large_blobs_at_least_10_mib": large, "licenses_all_reachable_trees": licenses,
        "gitmodules_all_reachable_trees": modules,
        "gitlinks_all_reachable_trees": sorted(gitlinks, key=lambda item: (item["parent_tree_oid"], item["entry_name"])),
        "baseline_and_ref_tip_entries": dict(sorted(snapshots.items())),
        "lfs_pointers": lfs, "missing_object_oids": sorted(set(missing)),
        "path_scope": "sample_path is one rev-list path; all-tree occurrences identify parent tree and entry name, not every historical full path",
    }
    details_path = artifact_dir / f"{name}-local-objects.json"
    write_json(details_path, details)
    summary = {
        "repository_key": name, "baseline_revision": baseline,
        "observed_head": observed_head,
        "head_snapshot_included": observed_head is not None,
        "shallow": git_text(repo, "rev-parse", "--is-shallow-repository") == "true",
        "partial_clone_configuration_present": bool(partial),
        "alternates_file_present": (common_dir / "objects/info/alternates").exists(),
        "environment_alternates_present": bool(ENV.get("GIT_ALTERNATE_OBJECT_DIRECTORIES")),
        "replace_ref_count": sum(ref["ref"].startswith("refs/replace/") for ref in refs),
        "grafts_file_present": (common_dir / "info/grafts").exists(),
        "all_local_ref_count": len(refs), "legacy_candidate_ref_count": len(legacy_before),
        "local_refs": refs,
        "tag_count": sum(ref["ref"].startswith("refs/tags/") for ref in legacy_before),
        "annotated_tag_count": sum(ref["type"] == "tag" for ref in legacy_before),
        "local_refs_changed_during_audit": changed,
        "legacy_refs_changed_during_audit": before_legacy != after_legacy,
        "legacy_reachable_commit_count": len(set(commits)),
        "legacy_reachable_object_counts": dict(sorted(Counter(info["type"] for info in objects.values()).items())),
        "legacy_reachable_uncompressed_object_bytes": sum(info["bytes"] for info in objects.values()),
        "missing_object_count": len(set(missing)),
        "large_blob_count_at_least_10_mib": len(large),
        "large_blob_count_at_least_100_mib": sum(item["bytes"] >= 100 * 1024 * 1024 for item in large),
        "largest_blobs": large[:5],
        "license_blob_count": len(licenses),
        "license_blobs": [{key: value for key, value in item.items() if key != "tree_occurrences"} | {"entry_names": sorted({occurrence["entry_name"] for occurrence in item["tree_occurrences"]})} for item in licenses],
        "license_text_signature_counts": dict(sorted(Counter(identity for item in licenses for identity in item["text_signatures"]).items())),
        "unrecognized_license_blob_count": sum(not item["text_signatures"] and not item["spdx_identifiers"] for item in licenses),
        "baseline_license_files": [entry for entry in snapshots.get(baseline, []) if LICENSE_NAME.match(entry["path"].rsplit("/", 1)[-1])],
        "gitmodule_blob_count": len(modules), "unique_gitlink_commit_count": len({item["commit_oid"] for item in gitlinks}),
        "gitlink_tree_occurrence_count": len(gitlinks),
        "lfs_pointer_count": len(lfs), "lfs_local_verified_count": sum(item["local_bytes_verified"] for item in lfs),
        "lfs_scan_scope": "all reachable blobs <=1024 bytes with standard LF version/oid/size lines; no custom LFS storage or remote fetch",
        "details": {"path": details_path.relative_to(ROOT).as_posix(), "sha256": file_digest(details_path)},
        "remote_refs_verified": False, "history_imported": False, "new_product_reuse_approved": False,
    }
    return summary, details


def release_inventory(integration, artifact_dir):
    manifests = []
    assets = []
    expected_names = set()
    for name in ("hub", "server", "client", "android"):
        path = integration / "final-audit" / f"{name}.json"
        if not path.is_file():
            manifests.append({"component": name, "present": False})
            continue
        old = json.loads(path.read_text(encoding="utf-8"))
        manifests.append({"component": name, "path": f"final-audit/{name}.json", "sha256": file_digest(path), "tag": old.get("tag"), "recorded_release_revision": old.get("release_revision"), "recorded_attachment_count": old.get("attachment_count"), "historical_claim_revalidated": False})
        for filename, asset in old.get("assets", {}).items():
            expected_names.add(filename)
            assets.append({"component": name, "tag": old.get("tag"), "filename": filename, "expected_sha256": asset.get("sha256"), "expected_bytes": asset.get("size_bytes"), "local_candidates": []})
    candidates = defaultdict(list)
    excluded = {".git", "toolchains", "node_modules", "target", ".gradle", ".dart_tool", "__pycache__", ".venv", "venv"}
    traversal_errors = []
    def walk_error(error):
        traversal_errors.append({"errno": error.errno, "message_disclosed": False})
    for base, dirs, files in os.walk(integration, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(directory for directory in dirs if directory not in excluded and not (Path(base) / directory).is_symlink())
        for filename in files:
            path = Path(base) / filename
            if filename in expected_names and path.is_file() and not path.is_symlink():
                candidates[filename].append(path)
    hashes = {}
    for asset in assets:
        for path in sorted(candidates[asset["filename"]]):
            if path not in hashes:
                hashes[path] = file_digest(path)
            actual_bytes = path.stat().st_size
            asset["local_candidates"].append({"path_relative_to_integration_root": path.relative_to(integration).as_posix(), "bytes": actual_bytes, "sha256": hashes[path], "matches_recorded_bytes_and_hash": actual_bytes == asset["expected_bytes"] and hashes[path] == asset["expected_sha256"]})
        asset["local_recorded_bytes_verified"] = any(item["matches_recorded_bytes_and_hash"] for item in asset["local_candidates"])
    downloads = []
    for path in sorted((integration / "downloads").glob("*")):
        if path.is_file() and not path.is_symlink():
            downloads.append({"filename": path.name, "bytes": path.stat().st_size, "sha256": file_digest(path), "relationship_to_complete_remote_release_inventory_verified": False})
    result = {
        "metadata_scope": "existing final-audit component JSON files only; historical claims are not fresh GitHub or download verification",
        "local_search_scope": "integration root recursively, excluding toolchains, .git, node_modules, target, .gradle, .dart_tool, Python caches/environments and directory symlinks",
        "search_errors": traversal_errors, "manifests": manifests, "assets": assets,
        "other_existing_downloads": downloads,
        "remote_release_list_verified": False, "remote_asset_list_verified": False,
        "remote_asset_bytes_downloaded_or_verified": False,
        "recorded_asset_count": len(assets),
        "recorded_assets_with_verified_local_bytes": sum(asset["local_recorded_bytes_verified"] for asset in assets),
    }
    path = artifact_dir / "local-release-assets.json"
    write_json(path, result)
    return {key: value for key, value in result.items() if key not in {"assets", "manifests"}} | {
        "recorded_manifests": manifests,
        "verified_local_assets": [{key: asset[key] for key in ("component", "tag", "filename", "expected_bytes", "expected_sha256")} | {"verified_local_paths": [item["path_relative_to_integration_root"] for item in asset["local_candidates"] if item["matches_recorded_bytes_and_hash"]]} for asset in assets if asset["local_recorded_bytes_verified"]],
        "details": {"path": path.relative_to(ROOT).as_posix(), "sha256": file_digest(path)},
        "missing_local_assets": [{key: asset[key] for key in ("component", "tag", "filename", "expected_bytes", "expected_sha256")} for asset in assets if not asset["local_recorded_bytes_verified"]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration-root", type=Path, default=Path(r"D:\home-tunnel-integration"))
    parser.add_argument("--additional-repository", action="append", default=[], metavar="NAME=PATH", help="Explicit local bare repository or checkout; repeat as needed. Requires separate report and artifact destinations.")
    parser.add_argument("--report", type=Path, help="JSON output under docs/refactor/history-audit; relative paths are workspace-relative.")
    parser.add_argument("--artifact-dir", type=Path, help="Evidence output under artifacts; relative paths are workspace-relative.")
    args = parser.parse_args()
    integration = args.integration_root.resolve()
    documents = ROOT / "docs/refactor/history-audit"
    default_artifacts = ROOT / "artifacts/history-audit"
    default_report = documents / "local-preservation-inventory-2026-10-13.json"
    artifact_dir = (ROOT / args.artifact_dir).resolve() if args.artifact_dir else default_artifacts
    report_path = (ROOT / args.report).resolve() if args.report else default_report
    if not artifact_dir.is_relative_to(ROOT / "artifacts") or not report_path.is_relative_to(documents) or report_path.suffix != ".json":
        parser.error("Report must be JSON under docs/refactor/history-audit; evidence must stay under artifacts")
    if args.additional_repository and (artifact_dir == default_artifacts or report_path == default_report):
        parser.error("Additional repositories require distinct --report and --artifact-dir to preserve the original audit")
    additional = {}
    for item in args.additional_repository:
        name, separator, raw_path = item.partition("=")
        if not separator or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name) or not raw_path or name in additional:
            parser.error("Each additional repository must have a unique NAME=PATH with a lowercase name")
        repo = (ROOT / Path(raw_path)).resolve()
        if not repo.is_dir() or (not (repo / ".git").exists() and git_text(repo, "rev-parse", "--is-bare-repository", optional=True) != "true"):
            parser.error(f"Additional repository {name} must be an existing bare repository or checkout")
        additional[name] = repo
    baseline_path = ROOT / "docs/refactor/baseline.json"
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    summaries, details, repos = {}, {}, {}
    for name, component in baseline["components"].items():
        repos[name] = integration / name
        summaries[name], details[name] = inventory_repository(name, repos[name], component["baseline_revision"], artifact_dir)
    # These initialized repositories were discovered locally; absent ones are recorded.
    auxiliary_paths = {
        "client-hbb-common": "client/client/libs/hbb_common",
        "android-core": "android/homedesk-core",
        "android-hbb-common": "android/homedesk-core/client/libs/hbb_common",
        "hbbs-upstream": "work-14.1.0/hbbs-upstream",
        "hbbs-hbb-common": "work-14.1.0/hbbs-upstream/libs/hbb_common",
    }
    if set(additional) & (set(repos) | set(auxiliary_paths)):
        parser.error("Additional repository names must not collide with primary or built-in auxiliary names")
    auxiliary = {}
    for name, relative in auxiliary_paths.items():
        repo = integration / relative
        if (repo / ".git").exists():
            repos[name] = repo
            auxiliary[name], details[name] = inventory_repository(name, repo, None, artifact_dir)
        else:
            auxiliary[name] = {"local_checkout_present": False}
    for name, repo in additional.items():
        repos[name] = repo
        auxiliary[name], details[name] = inventory_repository(name, repo, None, artifact_dir)
    # Check gitlink commit objects in every known object store. Availability is
    # not proof of origin, completeness of that commit's objects, or licensing.
    gitlink_ids = sorted({item["commit_oid"] for data in details.values() for item in data["gitlinks_all_reachable_trees"]})
    availability = {oid: [] for oid in gitlink_ids}
    for name, repo in repos.items():
        if not gitlink_ids:
            break
        output = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)", data=("\n".join(gitlink_ids) + "\n").encode()).decode().splitlines()
        for object_id, line in zip(gitlink_ids, output, strict=True):
            if line.endswith(" commit"):
                availability[object_id].append(name)
    submodule_path = artifact_dir / "gitlink-local-availability.json"
    write_json(submodule_path, {"scope": "commit object existence in known local stores only; commit closure checked only for commits reachable from inventoried refs", "commits": [{"oid": oid, "present_in_local_repositories": availability[oid]} for oid in gitlink_ids]})
    worktrees = []
    for name in baseline["components"]:
        repo = integration / "work-14.1.0" / name
        if (repo / ".git").exists():
            status = git(repo, "status", "--porcelain=v1", "-z")
            # Parse rename pairs so count does not double-count original paths.
            entries = status.split(b"\0")
            count, index = 0, 0
            while index < len(entries) and entries[index]:
                count += 1
                index += 2 if b"R" in entries[index][:2] or b"C" in entries[index][:2] else 1
            worktrees.append({"component": name, "head": git_text(repo, "rev-parse", "HEAD"), "porcelain_entry_count": count, "porcelain_sha256": digest(status), "modified_by_audit": False, "dirty_contents_preserved_elsewhere_by_audit": False})
    inputs = [baseline_path, ROOT / "docs/refactor/finalization.json", ROOT / "docs/refactor/history-audit-index.json", documents / "DISPOSITION.md"]
    report = {
        "schema_version": 1, "observed_date": "2026-10-13", "audit_kind": "read_only_local_preservation_inventory",
        "git_version": git_text(ROOT, "--version"),
        "script": {"path": "scripts/refactor-history-inventory.py", "sha256": file_digest(Path(__file__))},
        "inputs": [{"path": path.relative_to(ROOT).as_posix(), "sha256": file_digest(path)} for path in inputs],
        "scope": "legacy candidate local refs plus checked-out HEAD and fixed baseline commits; hub current NestLink development ref excluded from object/license counts; no reflog-only/unreachable object preservation claim",
        "read_only_controls": {key: ENV[key] for key in ("GIT_OPTIONAL_LOCKS", "GIT_NO_LAZY_FETCH", "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT")},
        "components": summaries, "auxiliary_local_repositories": auxiliary,
        "explicit_additional_repositories": [{"repository_key": name, "path": repo.relative_to(ROOT).as_posix() if repo.is_relative_to(ROOT) else str(repo), "selection": "explicit CLI input; no automatic repository discovery or network access"} for name, repo in additional.items()],
        "submodule_availability": {"unique_gitlink_commits": len(availability), "commit_objects_unavailable_locally": sum(not stores for stores in availability.values()), "unavailable_commits": [{"oid": oid, "occurrences": [{"repository_key": name, **entry} for name, data in details.items() for entry in data["gitlinks_all_reachable_trees"] if entry["commit_oid"] == oid]} for oid, stores in availability.items() if not stores], "details": {"path": submodule_path.relative_to(ROOT).as_posix(), "sha256": file_digest(submodule_path)}},
        "dirty_linked_worktrees": worktrees,
        "release_assets": release_inventory(integration, artifact_dir),
        "limits": [
            "No remote refs, hidden/pull-request refs, deleted refs, unreachable objects or reflogs were fetched or claimed complete.",
            "No repository was imported, deleted, renamed, uploaded, rewritten or modified by the audit.",
            "License filenames/text signatures are inventoried across all reachable trees; embedded notices, dependency source attribution, distribution obligations and compatibility require separate review.",
            "Preserving original commits and licenses does not approve any old source, credentials, permit test vectors or cloud project for NestLink product reuse.",
            "Existing finding classifications and DISPOSITION.md remain authoritative; no new secret scan or finding reclassification was performed.",
            "Historical Release manifests only describe their recorded versions; complete current remote Releases and asset bytes remain unverified.",
            "Dirty working trees are counted only; backup and preservation of uncommitted/ignored bytes remains a finalization prerequisite.",
        ],
        "history_imported": False, "new_product_reuse_approved": False, "finalization_ready": False,
    }
    write_json(report_path, report)
    print(json.dumps({"report": report_path.relative_to(ROOT).as_posix(), "components": {name: {key: info[key] for key in ("legacy_reachable_commit_count", "license_blob_count", "large_blob_count_at_least_10_mib", "missing_object_count")} for name, info in summaries.items()}, "submodules_missing_locally": report["submodule_availability"]["commit_objects_unavailable_locally"], "recorded_assets": report["release_assets"]["recorded_asset_count"], "recorded_assets_with_local_bytes": report["release_assets"]["recorded_assets_with_verified_local_bytes"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
