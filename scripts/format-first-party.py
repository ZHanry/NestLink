"""Format only the formal first-party Cargo workspace members on hosted Actions.

Do not use cargo fmt --all: it also follows local path dependencies whose
upstream source bytes, licenses and minimal patches must remain unchanged.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    receipt = {"commands": [], "packages": [], "return_code": 1, "error": None}
    try:
        if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
            raise RuntimeError("first-party formatting runs only on GitHub-hosted Actions")
        command = ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"]
        print(json.dumps({"command": command}), flush=True)
        metadata_result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, check=False)
        receipt["commands"].append({"command": command, "return_code": metadata_result.returncode})
        if metadata_result.returncode:
            receipt["return_code"] = metadata_result.returncode
            raise RuntimeError("workspace metadata failed; formatter was not started")
        metadata = json.loads(metadata_result.stdout)
        if Path(metadata["workspace_root"]).resolve() != root:
            raise RuntimeError("Cargo metadata workspace root does not match this checkout")
        packages = {package["id"]: package for package in metadata["packages"]}
        names = []
        for member in metadata["workspace_members"]:
            package = packages[member]
            if package["name"] == "fast-socks5":
                continue
            manifest = Path(package["manifest_path"]).resolve()
            relative = manifest.relative_to(root)
            if package["source"] is not None or relative.parts[0] not in {"crates", "apps", "xtask"}:
                raise RuntimeError("workspace selection contains a non-first-party package")
            names.append(package["name"])
            receipt["packages"].append({"name": package["name"], "manifest": relative.as_posix()})
        if not names or len(names) != len(set(names)):
            raise RuntimeError("workspace package selection is empty or ambiguous")
        command = ["cargo", "fmt"] + [value for name in sorted(names) for value in ("--package", name)]
        if args.check:
            command += ["--", "--check"]
        print(json.dumps({"command": command}), flush=True)
        result = subprocess.run(command, cwd=root, check=False)
        receipt["commands"].append({"command": command, "return_code": result.returncode})
        receipt["return_code"] = result.returncode
    except (KeyError, OSError, ValueError, RuntimeError) as error:
        receipt["error"] = str(error)
        print(str(error), file=sys.stderr, flush=True)
    finally:
        print(json.dumps(receipt, sort_keys=True), flush=True)
        if args.receipt:
            args.receipt.parent.mkdir(parents=True, exist_ok=True)
            args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return receipt["return_code"]


if __name__ == "__main__":
    raise SystemExit(main())
