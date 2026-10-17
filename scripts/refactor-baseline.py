"""Record committed v14 product entrypoints without importing runtime source."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

EXPECTED = {
    "hub": "da66975153385f9d92643daa4b7d9f1efbaa7a7d",
    "server": "10d3f5be070b4caf4d8feb11defb86ad0e68e5d4",
    "client": "181519880a5971f0618adfc81a55281a09d613a8",
    "android": "fc3690289d7bda0b0f0aec122e9379b2fa93f16c",
}
ENTRYPOINTS = {
    "hub": ["distribution.json", "LICENSE", "contracts/openapi.v2.json"],
    "server": ["compose.yaml", ".github/workflows/ci.yml", "control-center/package.json", "traffic-gateway/package.json", "LICENSE", "contracts/openapi.v2.json"],
    "client": ["client/Cargo.toml", "client/flutter/pubspec.yaml", "build/ci/build-client.py", "scripts/package-homedesk-windows.py", "brand/brand.json", "LICENSE", "LICENSE-RUSTDESK", "contracts/openapi.v2.json"],
    "android": ["homedesk-core.lock.json", "docs/BUILDING.md", ".github/workflows/ci.yml", "LICENSE", "contracts/openapi.v2.json"],
}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def snapshot(integration_root):
    components = {}
    contracts = {}
    for name, revision in EXPECTED.items():
        repo = integration_root / "work-14.1.0" / name
        git(repo, "cat-file", "-e", revision + "^{commit}")
        files = {}
        for filename in ENTRYPOINTS[name]:
            data = git(repo, "show", revision + ":" + filename)
            files[filename] = {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
            if filename.endswith("openapi.v2.json"):
                contract = json.loads(data)
                contracts[name] = sorted(
                    f"{method.upper()} {path}"
                    for path, item in contract.get("paths", {}).items()
                    for method in item
                    if method in {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
                )
        status = git(repo, "status", "--porcelain").decode("utf-8").splitlines()
        components[name] = {
            "repository": "ZHanry/home-tunnel" + ("" if name == "hub" else "-" + name),
            "baseline_revision": revision,
            "observed_head": git(repo, "rev-parse", "HEAD").decode().strip(),
            "uncommitted_entry_count": len(status),
            "build_and_license_files": files,
            "api_v2_operations": contracts[name],
        }
    hub_ops = set(contracts["hub"])
    differences = {
        name: {"missing_from_hub": sorted(set(operations) - hub_ops), "missing_from_component": sorted(hub_ops - set(operations))}
        for name, operations in contracts.items() if name != "hub"
    }
    return {
        "schema_version": 1,
        "recorded_date": "2026-10-12",
        "basis": "committed source; dirty 14.1.0 changes are counted, never imported",
        "components": components,
        "legacy_api_operation_differences": differences,
        "legacy_contracts_copied_into_v15": False,
        "distribution_checks": "existing v14 disclosure remains authoritative; no new runtime acceptance inferred",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--integration-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = snapshot(args.integration_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"components": len(result["components"]), "output": str(args.output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
