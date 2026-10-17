"""Preserve observed Release bytes locally; never publish or delete repositories."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = {"hub": ("ZHanry/home-tunnel", "R_kgDOTz-mRQ"),
    "server": ("ZHanry/home-tunnel-server", "R_kgDOUSDIiA"),
    "client": ("ZHanry/home-tunnel-client", "R_kgDOUSDI3Q"),
    "android": ("ZHanry/home-tunnel-android", "R_kgDOUSDJHw")}
ENV = {**os.environ, "GH_PROMPT_DISABLED": "1"}

def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()

def atomic_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".part")
    with temporary.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)

def asset_path(root, component, asset):
    if component not in IDENTITIES or type(asset.get("asset_id")) is not int or asset["asset_id"] <= 0 or type(asset.get("bytes")) is not int or asset["bytes"] < 0:
        raise ValueError("invalid archive component, asset ID or length")
    checksum = asset.get("github_sha256")
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("a current GitHub SHA256 is required before saving verified bytes")
    if asset.get("state") != "uploaded":
        raise ValueError("asset upload is incomplete")
    # Remote filenames are metadata only, never filesystem destinations.
    path = (root / component / "assets" / f'{asset["asset_id"]}-{checksum}.blob').resolve()
    if not path.is_relative_to(root):
        raise ValueError("archive target escapes the explicitly named root")
    return path

def verify_bytes(path, asset):
    if not path.is_file():
        raise ValueError("asset byte length or SHA256 differs from current inventory")
    before = path.stat()
    checksum = digest(path)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("asset changed during byte verification")
    if after.st_size != asset["bytes"] or checksum != asset["github_sha256"]:
        raise ValueError("asset byte length or SHA256 differs from current inventory")

def metadata(repository, asset):
    result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
        f'repos/{repository}/releases/assets/{asset["asset_id"]}'], env=ENV,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode:
        raise RuntimeError("asset metadata GET failed; stderr SHA256 " + hashlib.sha256(result.stderr).hexdigest())
    value = json.loads(result.stdout)
    if value.get("id") != asset["asset_id"] or value.get("size") != asset["bytes"] or value.get("digest") != "sha256:" + asset["github_sha256"] or value.get("state") != "uploaded":
        raise ValueError("asset identity/length/digest changed since inventory; refresh observations")
    return {key: value.get(key) for key in ("id", "name", "size", "digest", "state", "updated_at")}

def download(repository, asset, temporary):
    # Stream directly to an exclusive partial file; no binary is executed or extracted.
    with temporary.open("xb") as output:
        result = subprocess.run(["gh", "api", "--hostname", "github.com", "--method", "GET",
            "-H", "Accept: application/octet-stream",
            f'repos/{repository}/releases/assets/{asset["asset_id"]}'], env=ENV,
            stdout=output, stderr=subprocess.PIPE, timeout=max(60, min(1800, asset["bytes"] // (256 * 1024) + 30)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        output.flush()
        os.fsync(output.fileno())
    if result.returncode:
        raise RuntimeError("asset download failed; stderr SHA256 " + hashlib.sha256(result.stderr).hexdigest())

def local_copy(asset, integration, temporary):
    for candidate in asset.get("local_candidates", []):
        if candidate.get("matches_current_github_digest") is not True:
            continue
        source = (integration / candidate["path_relative_to_integration_root"]).resolve()
        if not source.is_relative_to(integration):
            raise ValueError("existing candidate escapes the integration root")
        verify_bytes(source, asset)
        with source.open("rb") as source_stream, temporary.open("xb") as destination:
            shutil.copyfileobj(source_stream, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        return candidate["path_relative_to_integration_root"]
    return None

def preserve(root, integration, component, asset):
    target = asset_path(root, component, asset)
    repository = IDENTITIES[component][0]
    record = {"component": component, "repository": repository, "release_id": asset["release_id"],
        "tag": asset["tag"], "asset_id": asset["asset_id"], "original_filename": asset["filename"],
        "bytes": asset["bytes"], "sha256": asset["github_sha256"], "verified": False}
    temporary = target.with_name(target.name + "." + uuid.uuid4().hex + ".part")
    try:
        record["metadata_before"] = metadata(repository, asset)
        if target.exists():
            verify_bytes(target, asset)
            record["method"] = "reverified_existing_archive"
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = local_copy(asset, integration, temporary)
            if copied is None:
                download(repository, asset, temporary)
                record["method"] = "fresh_github_asset_download"
            else:
                record["method"] = "independent_copy_of_reverified_local_bytes"
                record["existing_source"] = copied
            verify_bytes(temporary, asset)
            record["metadata_after"] = metadata(repository, asset)
            if target.exists():
                # Another writer must never cause an unchecked overwrite.
                raise ValueError("archive target appeared during preservation")
            # Atomic exclusive publication on Linux and Windows. An existence
            # check followed by rename can overwrite a competing Linux writer.
            os.link(temporary, target)
            temporary.unlink()
        verify_bytes(target, asset)
        record["metadata_after"] = metadata(repository, asset)
        record["archive_path"] = target.relative_to(root).as_posix()
        record["verified"] = True
    except Exception as error:
        record["error_type"] = type(error).__name__
        record["error"] = str(error) if not isinstance(error, OSError) else "filesystem operation failed; private path omitted"
        if temporary.exists():
            record["retained_partial_path"] = temporary.relative_to(root).as_posix()
    record["completed_at"] = datetime.now(timezone.utc).isoformat()
    return record

def inventory_assets(inventory):
    if set(inventory["components"]) != set(IDENTITIES):
        raise ValueError("inventory must cover the four approved repositories")
    result = []
    for component, (repository, node_id) in IDENTITIES.items():
        current = inventory["components"][component]
        if current["repository"] != repository or current["repository_node_id"] != node_id:
            raise ValueError("inventory repository identity differs from approved preservation scope")
        if current["asset_count"] != len(current["assets"]):
            raise ValueError("incomplete asset inventory")
        result.extend((component, asset) for asset in current["assets"])
    if len({a["asset_id"] for _, a in result}) != len(result):
        raise ValueError("duplicate asset identities")
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--integration-root", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4, choices=range(1, 5))
    parser.add_argument("--asset-id", type=int, action="append", help="Explicit smoke-test subset; never marks the complete inventory preserved.")
    args = parser.parse_args()
    inventory_file = args.inventory.resolve()
    inventory_bytes = inventory_file.read_bytes()
    inventory = json.loads(inventory_bytes)
    all_assets = inventory_assets(inventory)
    selected = [(c, a) for c, a in all_assets if args.asset_id is None or a["asset_id"] in args.asset_id]
    if args.asset_id is not None and {a["asset_id"] for _, a in selected} != set(args.asset_id):
        parser.error("requested asset ID is absent from the approved inventory")
    root, integration = args.archive_root.resolve(), args.integration_root.resolve()
    for component, asset in selected:
        asset_path(root, component, asset)
    needed = sum(a["bytes"] for c, a in selected if not asset_path(root, c, a).exists())
    if shutil.disk_usage(root if root.exists() else root.parent).free < needed + 2 * 1024**3:
        parser.error("insufficient space for the selected bytes plus a 2 GiB reserve")
    root.mkdir(parents=True, exist_ok=True)
    inventory_hash = hashlib.sha256(inventory_bytes).hexdigest()
    snapshot = root / f'inventory-{inventory_hash}.json'
    if not snapshot.resolve().is_relative_to(root):
        raise ValueError("inventory snapshot escapes archive root")
    if snapshot.exists():
        if digest(snapshot) != inventory_hash:
            raise ValueError("saved inventory snapshot changed")
    else:
        with snapshot.open("xb") as output:
            output.write(inventory_bytes)
            output.flush()
            os.fsync(output.fileno())
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    report_file = root / f'archive-{run_id}.json'
    report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
        "source_inventory_sha256": inventory_hash, "inventory_asset_count": len(all_assets),
        "selected_asset_count": len(selected), "source_script_sha256": digest(Path(__file__)),
        "archive_root": str(root), "assets": [], "all_inventory_bytes_verified": False,
        "durable_remote_archive_uploaded": False, "finalization_ready": False}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(preserve, root, integration, component, asset) for component, asset in selected]
        for future in as_completed(futures):
            report["assets"].append(future.result())
            report["verified_assets"] = sum(a["verified"] for a in report["assets"])
            report["verified_bytes"] = sum(a["bytes"] for a in report["assets"] if a["verified"])
            atomic_json(report_file, report)
            if len(report["assets"]) % 20 == 0 or not report["assets"][-1]["verified"]:
                print(f'{len(report["assets"])}/{len(selected)} observed, {report["verified_assets"]} verified', flush=True)
    report["completed_at"] = datetime.now(timezone.utc).isoformat()
    report["all_inventory_bytes_verified"] = len(selected) == len(all_assets) == report.get("verified_assets", 0)
    atomic_json(report_file, report)
    print(f'report: {report_file}', flush=True)
    raise SystemExit(0 if all(a["verified"] for a in report["assets"]) else 1)

if __name__ == "__main__":
    main()
