"""Verify isolated historical gitlink recovery evidence without network access."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("history_inventory", ROOT / "scripts/refactor-history-inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
git = inventory.git
git_text = inventory.git_text
sha256 = inventory.digest
file_sha256 = inventory.file_digest
write_json = inventory.write_json
BASE = ROOT / "artifacts/history-preservation"
TARGETS = [
    ("5a78ec42303ca046d808742e911a156636a2432b", "10f61ffdc28ca0b46dd0ab100e76bf08a0896527", "libs/hbb_common"),
    ("93f9445c69f30487f1479a9e4e1882773e00c7f9", "7792ac148139d8aead7d205baa335dbfaac50b22", "libs/hbb_common"),
    ("b0f50c8d55a015f3d49fe9e90fcefb585d74a25f", "838decccc44f83d7989fbcd1d404196d7783bbc3", "libs/hbb_common"),
    ("f857bbd3bc350c800d447eb0d809d21f101cd80b", "2b40c61d8ed62c5de4eeadc5f555fb3b3a6b29ee", "libs/hbb_common"),
    ("cecc93886ce839ec49b0041f072a573327acdf08", "2d9346087343c817b465e56276fb829adbd1f25f", "flatpak/shared-modules"),
]
SOURCES = {
    "rustdesk-hbb-common": "https://github.com/rustdesk/hbb_common",
    "21pages-hbb-common": "https://github.com/21pages/hbb_common",
    "flathub-shared-modules": "https://github.com/flathub/shared-modules.git",
}


def evidence_file(path):
    return {"path": path.relative_to(ROOT).as_posix(), "sha256": file_sha256(path), "bytes": path.stat().st_size}


def save_declaration(repo, revision, path, category):
    object_id = git_text(repo, "rev-parse", "--verify", f"{revision}:{path}", optional=True)
    if not object_id:
        return None
    content = git(repo, "cat-file", "blob", object_id)
    # Preserve declarations only. Never copy a historical source tree into products.
    output = BASE / "declarations" / f"{object_id}-{Path(path).name}"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(content)
    record = {"source_commit": revision, "source_path": path, "blob_oid": object_id, "category": category, "artifact": evidence_file(output)}
    if category == "license_text":
        record.update(inventory.license_identity(content))
    return record


def full_gitmodules(repo, revision):
    paths = [path for path in git_text(repo, "ls-tree", "-r", "--name-only", revision).splitlines() if path.rsplit("/", 1)[-1] == ".gitmodules"]
    return {"all_gitmodules_paths_in_tree": paths, "declarations": [save_declaration(repo, revision, path, "gitmodules") for path in paths]}


def root_licenses(repo, revision):
    paths = git_text(repo, "ls-tree", "--name-only", revision).splitlines()
    return [save_declaration(repo, revision, path, "license_text") for path in paths if inventory.LICENSE_NAME.fullmatch(path)]


def verify_recovered(repo, object_id):
    kind = git_text(repo, "cat-file", "-t", object_id, optional=True)
    if kind != "commit":
        return None
    payload = git(repo, "cat-file", "commit", object_id)
    computed_oid = hashlib.sha1(b"commit " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    if computed_oid != object_id:
        raise RuntimeError("Recovered commit bytes do not match original gitlink ID")
    tree_oid = payload.splitlines()[0].decode().removeprefix("tree ")
    tree = git(repo, "cat-file", "tree", tree_oid)
    computed_tree = hashlib.sha1(b"tree " + str(len(tree)).encode() + b"\0" + tree).hexdigest()
    if computed_tree != tree_oid:
        raise RuntimeError("Recovered tree bytes do not match commit's root tree ID")
    closure = git(repo, "rev-list", "--objects", "--missing=print", object_id)
    missing = [line[1:].decode() for line in closure.splitlines() if line.startswith(b"?")]
    # Strict fsck covers hashes, links and object formats in the isolated store.
    fsck = git(repo, "fsck", "--full", "--strict", "--no-reflogs", "--no-dangling", object_id)
    log_path = BASE / f"{repo.stem}-{object_id}-verified-fsck.log"
    log_path.write_bytes(fsck)
    closure_path = BASE / f"{repo.stem}-{object_id}-object-closure.txt"
    closure_path.write_bytes(closure)
    entries = inventory.snapshot_tree(repo, object_id)
    licenses = [save_declaration(repo, object_id, item["path"], "license_text") for item in entries if item["type"] == "blob" and inventory.LICENSE_NAME.fullmatch(item["path"].rsplit("/", 1)[-1])]
    nested = [item for item in entries if item["mode"] == "160000"]
    return {
        "repository_path": repo.relative_to(ROOT).as_posix(), "object_type": kind,
        "gitlink_oid": object_id, "recomputed_commit_oid": computed_oid, "commit_payload_sha256": sha256(payload),
        "root_tree_oid": tree_oid, "recomputed_tree_oid": computed_tree,
        "shallow": git_text(repo, "rev-parse", "--is-shallow-repository") == "true",
        "reachable_commit_count": int(git_text(repo, "rev-list", "--count", object_id)),
        "reachable_object_count": len(closure.splitlines()), "missing_object_oids": missing,
        "closure": evidence_file(closure_path), "git_fsck_strict_exit_code": 0,
        "fsck_stdout": evidence_file(log_path), "nested_gitlinks_at_recovered_commit": nested,
        "license_declarations_at_recovered_commit": licenses,
        "standalone_license_found": bool(licenses),
        "new_product_reuse_approved": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration-root", type=Path, default=Path(r"D:\home-tunnel-integration"))
    args = parser.parse_args()
    old_repo = args.integration_root.resolve() / "client"
    original = ROOT / "docs/refactor/history-audit/local-preservation-inventory-2026-10-13.json"
    original_hash = file_sha256(original)
    attempts_path = BASE / "fetch-attempts-2026-10-13.json"
    attempts = json.loads(attempts_path.read_text(encoding="utf-8"))
    for attempt in attempts:
        if attempt["url"] != SOURCES.get(attempt["repository_key"]):
            raise RuntimeError("Unexpected source in preserved fetch record")
        if attempt["requested_commit"] not in {item[0] for item in TARGETS}:
            raise RuntimeError("Unexpected commit in preserved fetch record")
        log_path = (ROOT / attempt["fetch_log"]).resolve()
        if not log_path.is_relative_to(BASE) or file_sha256(log_path) != attempt["fetch_log_sha256"]:
            raise RuntimeError("Fetch evidence digest mismatch")
        content = log_path.read_bytes()
        expected_error = f"fatal: remote error: upload-pack: not our ref {attempt['requested_commit']}".encode()
        attempt["result"] = "fetched" if attempt["exit_code"] == 0 else "remote_not_our_ref" if content.strip() == expected_error else "other_failure_review_log"
        attempt["read_only_remote_request"] = True
    candidate_commit = "9dd4fa86464a7a390716c9dada405d6ff9b81f09"
    candidate_declaration = save_declaration(old_repo, candidate_commit, ".gitmodules", "gitmodules")
    candidate_content = git(old_repo, "show", candidate_commit + ":.gitmodules")
    if b"url = https://github.com/21pages/hbb_common" not in candidate_content:
        raise RuntimeError("21pages candidate is not supported by recorded historical .gitmodules")
    workflow_commit = "2b40c61d8ed62c5de4eeadc5f555fb3b3a6b29ee"
    workflow_path = ".github/workflows/flutter-build.yml"
    workflow_oid = git_text(old_repo, "rev-parse", workflow_commit + ":" + workflow_path)
    workflow_content = git(old_repo, "cat-file", "blob", workflow_oid)
    candidate_lines = [index for index, line in enumerate(workflow_content.decode().splitlines(), 1) if "git clone https://github.com/flathub/shared-modules.git --depth=1" in line]
    if not candidate_lines:
        raise RuntimeError("Flathub candidate is not supported by recorded historical workflow")
    targets = []
    for object_id, introducing_commit, path in TARGETS:
        actual = git_text(old_repo, "ls-tree", introducing_commit, "--", path)
        if actual != f"160000 commit {object_id}\t{path}":
            raise RuntimeError("Original commit does not contain the specified gitlink")
        modules = full_gitmodules(old_repo, introducing_commit)
        declared_url = None
        if path == "libs/hbb_common":
            content = git(old_repo, "show", introducing_commit + ":.gitmodules")
            if content != b'[submodule "libs/hbb_common"]\n\tpath = libs/hbb_common\n\turl = https://github.com/rustdesk/hbb_common\n':
                raise RuntimeError("Original .gitmodules does not match the verified full declaration")
            declared_url = SOURCES["rustdesk-hbb-common"]
        successful = []
        target_attempts = [item for item in attempts if item["requested_commit"] == object_id]
        for attempt in target_attempts:
            if attempt["exit_code"] == 0:
                recovered = verify_recovered(BASE / (attempt["repository_key"] + ".git"), object_id)
                if not recovered:
                    raise RuntimeError("Successful fetch record lacks matching local commit object")
                successful.append({"fetched_from": attempt["url"], **recovered})
        targets.append({
            "gitlink_oid": object_id, "original_client_commit": introducing_commit,
            "original_gitlink_path": path, "original_gitlink_verified": True,
            "original_declared_url": declared_url,
            "original_url_attribution_verified": declared_url is not None,
            "full_original_gitmodules": modules,
            "parent_top_level_license_context": root_licenses(old_repo, introducing_commit),
            "parent_license_is_not_automatic_submodule_license_grant": True,
            "fetch_attempts": target_attempts, "recovered": successful,
            "status": "original_gitlink_object_recovered" if successful else "not_obtainable_from_attempted_documented_sources",
            "unavailability_scope": None if successful else "These exact-SHA requests failed; global nonexistence is not claimed.",
        })
    if file_sha256(original) != original_hash:
        raise RuntimeError("Original report changed during supplemental audit")
    output = ROOT / "docs/refactor/history-audit/gitlink-recovery-2026-10-13.json"
    report = {
        "schema_version": 1, "observed_date": "2026-10-13",
        "original_inventory": evidence_file(original), "original_inventory_modified": False,
        "script": evidence_file(Path(__file__)), "fetch_attempt_evidence": evidence_file(attempts_path),
        "scope": "Five original missing gitlinks; exact SHA retrieval into isolated bare stores, then read-only local object verification. No product source import.",
        "fetch_controls": {"public_https_only": True, "credential_helper_disabled": True, "global_and_system_git_config_disabled": True, "terminal_prompt_disabled": True, "no_checkout_no_tags_no_recursive_submodules": True, "request_ref_pattern": "<original gitlink SHA>:refs/tags/preserved/<same SHA>", "fetch_used_no_depth_or_filter": True},
        "candidate_source_evidence": {
            "21pages_hbb_common": {"url": SOURCES["21pages-hbb-common"], "declaration": candidate_declaration, "scope": "Exact historical .gitmodules elsewhere in Client history; not original URL for the three attempted targets"},
            "flathub_shared_modules": {"url": SOURCES["flathub-shared-modules"], "source_commit": workflow_commit, "source_path": workflow_path, "source_blob_oid": workflow_oid, "source_blob_sha256": sha256(workflow_content), "matching_line_numbers": candidate_lines, "matched_public_command": "git clone https://github.com/flathub/shared-modules.git --depth=1", "scope": "Later historical workflow is candidate evidence only; original gitlink commit has no .gitmodules"},
        },
        "targets": targets,
        "recovered_original_gitlink_count": sum(bool(item["recovered"]) for item in targets),
        "remaining_missing_gitlink_oids": [item["gitlink_oid"] for item in targets if not item["recovered"]],
        "limits": [
            "The shared-modules object matches the original gitlink hash and passes strict fsck, but original origin attribution remains unverified.",
            "The three unsuccessful hbb_common requests returned not our ref from the originally declared URL and a historically documented fork; no synthetic replacement commits were made.",
            "All recovered commit/tree/source/license bytes remain in isolated Git stores. No product reuse authorization is inferred, including when a submodule contains no standalone license file.",
            "Fetched Git object closures do not prove complete remote refs/Releases/assets, recover reflog-only history, or satisfy final repository-deletion prerequisites.",
            "Existing original inventory and its artifacts were not overwritten. Isolated ignored artifacts still need durable preservation before finalization.",
        ],
        "old_worktrees_modified": False, "product_history_imported": False, "remote_upload_or_deletion_performed": False, "new_product_reuse_approved": False, "finalization_ready": False,
    }
    write_json(output, report)
    print(json.dumps({"report": output.relative_to(ROOT).as_posix(), "recovered": report["recovered_original_gitlink_count"], "remaining": report["remaining_missing_gitlink_oids"]}, indent=2))


if __name__ == "__main__":
    main()
