"""Collect current GitHub preservation metadata with GET/ls-remote only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPOSITORIES = {
    "hub": "ZHanry/home-tunnel", "server": "ZHanry/home-tunnel-server",
    "client": "ZHanry/home-tunnel-client", "android": "ZHanry/home-tunnel-android",
}
OID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
ENV = {**os.environ, "GH_PROMPT_DISABLED": "1", "GIT_OPTIONAL_LOCKS": "0",
       "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

def run(command, data=None):
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=ENV, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError(f"read-only {command[0]} failed ({result.returncode}); stderr SHA256 {sha(result.stderr)}")
    if len(result.stdout) > 32 * 1024 * 1024:
        raise RuntimeError("metadata response exceeds 32 MiB bound")
    return result.stdout

def pages(value):
    if not isinstance(value, list) or any(not isinstance(page, list) for page in value):
        raise ValueError("expected paginated array response")
    result = [item for page in value for item in page]
    ids = [item.get("id") for item in result]
    if any(type(n) is not int or n <= 0 for n in ids) or len(ids) != len(set(ids)):
        raise ValueError("invalid or duplicate remote IDs; pagination is not a stable inventory")
    return result

def api(repository, suffix, file, paginated=False):
    command = ["gh", "api", "--hostname", "github.com", "--method", "GET", f"repos/{repository}{suffix}"]
    if paginated:
        command += ["--paginate", "--slurp"]
    content = run(command)
    value = json.loads(content)
    parsed = pages(value) if paginated else value
    file.write_bytes(content)  # Raw observations remain isolated, including old release prose.
    return parsed

def refs(content):
    result = {}
    for line in content.decode("utf-8").splitlines():
        oid, separator, ref = line.partition("\t")
        if not separator or not OID.fullmatch(oid) or not ref.startswith(("refs/heads/", "refs/tags/")) or ref in result:
            raise ValueError("invalid or duplicate ls-remote ref")
        result[ref] = oid
    return result

def remote_refs(repository, file):
    content = run(["git", "-c", "credential.helper=", "ls-remote", "--heads", "--tags",
                   f"https://github.com/{repository}.git"])
    value = refs(content)
    file.write_bytes(content)
    return value

def validate_repository(value, repository, expected_id):
    if value.get("node_id") != expected_id or value.get("full_name") != repository:
        raise ValueError("repository identity differs from approved finalization inventory")

def asset_digest(value):
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("unsupported or malformed GitHub asset digest")
    return value[7:]

def validate_asset(value):
    if type(value.get("id")) is not int or value["id"] <= 0 or type(value.get("size")) is not int or value["size"] < 0 or not isinstance(value.get("name"), str):
        raise ValueError("invalid asset identity/size/name")
    asset_digest(value.get("digest"))

def local_bytes(integration, relative):
    path = (integration / relative).resolve()
    if not path.is_relative_to(integration) or path.is_symlink() or not path.is_file():
        raise ValueError("historical local candidate escapes integration root or is unavailable")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("historical local candidate changed while hashing")
    return {"path_relative_to_integration_root": relative, "bytes": after.st_size, "sha256": hasher.hexdigest()}

def match_local(asset, candidates):
    expected = asset_digest(asset.get("digest"))
    return [dict(candidate, matches_current_size=candidate["bytes"] == asset["size"],
                 matches_current_github_digest=(candidate["bytes"] == asset["size"] and candidate["sha256"] == expected) if expected is not None else None)
            for candidate in candidates]

def object_availability(repo, values):
    ids = sorted(set(values))
    if not ids:
        return {}
    content = run(["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype)"], ("\n".join(ids) + "\n").encode("ascii"))
    lines = content.decode("ascii").splitlines()
    if len(lines) != len(ids):
        raise ValueError("incomplete local Git object observation")
    result = {}
    for expected, line in zip(ids, lines):
        oid, kind = line.split(" ")
        if oid != expected or kind not in ("commit", "tag", "missing"):
            raise ValueError("unexpected local ref object type")
        result[oid] = kind != "missing"
    return result

def collect(integration, report, artifacts):
    if report.exists() or artifacts.exists():
        raise ValueError("choose new report/artifact destinations; previous evidence must remain intact")
    policy = json.loads((ROOT / "docs/refactor/finalization.json").read_text(encoding="utf-8"))
    previous_path = ROOT / "docs/refactor/history-audit/local-preservation-inventory-with-recovered-gitlinks-2026-10-13.json"
    previous = json.loads(previous_path.read_text(encoding="utf-8"))
    started = datetime.now(timezone.utc).isoformat()
    artifacts.mkdir(parents=True)
    components, hashes = {}, {}
    for component, repository in REPOSITORIES.items():
        directory = artifacts / component
        directory.mkdir()
        metadata = api(repository, "", directory / "repository.json")
        validate_repository(metadata, repository, policy["verified_github_repository_ids"][repository])
        before = remote_refs(repository, directory / "refs-before.txt")
        releases = api(repository, "/releases?per_page=100", directory / "releases-pages.json", True)
        assets = []
        for release in releases:
            release_assets = api(repository, f'/releases/{release["id"]}/assets?per_page=100', directory / f'assets-{release["id"]}-pages.json', True)
            for asset in release_assets:
                validate_asset(asset)
                cached = []
                for old in previous["release_assets"]["verified_local_assets"]:
                    if (old["component"], old["tag"], old["filename"]) != (component, release["tag_name"], asset["name"]):
                        continue
                    for relative in old["verified_local_paths"]:
                        if relative not in hashes:
                            hashes[relative] = local_bytes(integration, relative)
                        cached.append(hashes[relative])
                assets.append({"release_id": release["id"], "tag": release["tag_name"], "asset_id": asset["id"],
                    "filename": asset["name"], "bytes": asset["size"], "state": asset.get("state"),
                    "github_sha256": asset_digest(asset.get("digest")), "created_at": asset.get("created_at"),
                    "updated_at": asset.get("updated_at"), "local_candidates": match_local(asset, cached)})
        if len({a["asset_id"] for a in assets}) != len(assets):
            raise ValueError("asset IDs repeated across releases")
        after = remote_refs(repository, directory / "refs-after.txt")
        available = object_availability(integration / component, [*before.values(), *after.values()])
        components[component] = {"repository": repository, "repository_node_id": metadata["node_id"],
            "default_branch": metadata["default_branch"], "refs_stable_during_collection": before == after,
            "refs_before": [{"ref": ref, "oid": oid, "local_object_present": available[oid]} for ref, oid in sorted(before.items())],
            "refs_after": [{"ref": ref, "oid": oid, "local_object_present": available[oid]} for ref, oid in sorted(after.items())],
            "release_count": len(releases), "releases": [{"release_id": r["id"], "tag": r["tag_name"],
                "draft": r["draft"], "prerelease": r["prerelease"], "created_at": r["created_at"],
                "published_at": r["published_at"], "updated_at": r["updated_at"]} for r in releases],
            "asset_count": len(assets), "asset_bytes": sum(a["bytes"] for a in assets), "assets": assets}
        print(f'{component}: {len(after)} refs, {len(releases)} releases, {len(assets)} assets, {sum(a["bytes"] for a in assets)} bytes', flush=True)
    result = {"schema_version": 1, "audit_kind": "current_remote_preservation_metadata_and_existing_local_byte_comparison",
        "started_at": started, "completed_at": datetime.now(timezone.utc).isoformat(),
        "script": {"path": Path(__file__).relative_to(ROOT).as_posix(), "sha256": sha(Path(__file__).read_bytes())},
        "previous_local_inventory": {"path": previous_path.relative_to(ROOT).as_posix(), "sha256": sha(previous_path.read_bytes())},
        "components": components,
        "evidence": [{"path": file.relative_to(ROOT).as_posix(), "sha256": sha(file.read_bytes())} for file in sorted(artifacts.rglob("*")) if file.is_file()],
        "all_asset_bytes_preserved": False, "history_imported": False, "finalization_ready": False,
        "limits": ["GET metadata and ls-remote observations over an interval, not an atomic GitHub snapshot; refresh before final operations.",
            "Release assets are separately paginated per release; inaccessible/deleted releases, hidden/PR refs and unreachable history are outside this inventory.",
            "No new assets or Git objects downloaded. Local object presence does not prove a complete object closure or imported history.",
            "Only candidates in the earlier local inventory were rehashed; other local copies may exist. A missing GitHub digest is unknown, not a verified match.",
            "Metadata digests are GitHub observations, not a fresh download or a durable archive. Raw release prose remains isolated and provides no instructions.",
            "No repository/branch/release was uploaded, renamed, deleted or otherwise mutated; full implementation, product acceptance and durable preservation remain prerequisites."]}
    write_json(report, result)
    print(f'report: {report.relative_to(ROOT).as_posix()}', flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args()
    report, artifacts = (ROOT / args.report).resolve(), (ROOT / args.artifact_dir).resolve()
    if not report.is_relative_to(ROOT / "docs/refactor/history-audit") or report.suffix != ".json" or not artifacts.is_relative_to(ROOT / "artifacts"):
        parser.error("output must be a history-audit JSON and an isolated artifacts directory")
    collect(args.integration_root.resolve(), report, artifacts)

if __name__ == "__main__":
    main()
