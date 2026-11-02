"""Derive current product-version locks only on GitHub-hosted Actions.

Cargo updates the local workspace graph. Every previously reviewed external
package, checksum and dependency edge is then retained verbatim and verified
with Cargo's locked resolver. This never compiles or qualifies the product.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tomllib


MANIFESTS = {
    "product": "Cargo.toml",
    "browser-native-fixture": "scripts/fixtures/browser-native-host/Cargo.toml",
    "security-fuzz": "tests/security/fuzz/Cargo.toml",
}


def blocks(raw):
    header, *parts = raw.decode("utf-8").split("[[package]]")
    result = []
    for part in parts:
        package = tomllib.loads("[[package]]" + part)["package"][0]
        result.append(((package["name"], package["version"], package.get("source", "")), package, part))
    keys = [key for key, _, _ in result]
    if len(keys) != len(set(keys)):
        raise ValueError("Duplicate locked package identity")
    return header, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=MANIFESTS, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "ZHanry/NestLink"):
        raise ValueError("Version lock derivation requires the original GitHub-hosted repository")
    root = Path(__file__).resolve().parents[1]
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    if source != args.source or source != os.environ["GITHUB_SHA"]:
        raise ValueError("Requested version source differs from the workflow checkout")
    if subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root):
        raise ValueError("Version derivation requires the exact clean source")
    args.output.mkdir(parents=True, exist_ok=False)
    manifest = root / MANIFESTS[args.scope]
    lock = manifest.with_name("Cargo.lock")
    before = lock.read_bytes()
    (args.output / "before.lock").write_bytes(before)
    version = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]["package"]["version"]
    if version != "0.8.0-rc.1":
        raise ValueError("This derivation is restricted to the requested 0.8.0RC")
    receipt = {"schema_version": 1, "purpose": "same-component-product-version-lock-derivation",
               "repository": os.environ["GITHUB_REPOSITORY"], "source_revision": source,
               "workflow": os.environ["GITHUB_WORKFLOW_REF"], "workflow_revision": os.environ["GITHUB_WORKFLOW_SHA"],
               "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
               "runner_environment": os.environ["RUNNER_ENVIRONMENT"], "scope": args.scope,
               "manifest": MANIFESTS[args.scope], "version": version,
               "before_lock_sha256": hashlib.sha256(before).hexdigest(), "commands": [],
               "external_packages_and_edges_unchanged": False, "passed": False,
               "product_compilation_performed": False, "quality_or_acceptance_claimed": False}

    def execute(name, command):
        with (args.output / (name + ".log")).open("wb") as stream:
            result = subprocess.run(command, cwd=root, stdout=stream, stderr=subprocess.STDOUT,
                                    timeout=600, check=False)
        receipt["commands"].append({"name": name, "argv": command, "return_code": result.returncode})
        if result.returncode:
            raise ValueError("Version lock command failed: " + name)

    try:
        execute("cargo-local-workspace-update", ["cargo", "update", "--workspace", "--manifest-path", str(manifest)])
        shutil.copyfile(lock, args.output / "cargo-generated.lock")
        _, original = blocks(before)
        header, generated = blocks(lock.read_bytes())
        old_external = {key: (package, raw) for key, package, raw in original if key[2]}
        new_external = {key: package for key, package, _ in generated if key[2]}
        if set(old_external) != set(new_external):
            raise ValueError("Product version update changed the reviewed external package identities")
        # Cargo can reselect a compatible edge during --workspace. Restore its
        # original exact block; --locked below rejects an incompatible graph.
        lock.write_text(header + "".join("[[package]]" + (old_external[key][1] if key[2] else raw)
                                        for key, _, raw in generated), encoding="utf-8", newline="\n")
        execute("locked-resolver-readback", ["cargo", "metadata", "--locked", "--format-version", "1",
                                            "--manifest-path", str(manifest)])
        _, final = blocks(lock.read_bytes())
        if {key: package for key, package, _ in final if key[2]} != {key: package for key, (package, _) in old_external.items()}:
            raise ValueError("External dependency checksum or edge changed")
        harness = {"browser-native-fixture": "nestlink-browser-native-host-fixture",
                   "security-fuzz": "nestlink-network-security-fuzz"}.get(args.scope)
        if harness:
            if [package["version"] for key, package, _ in final if not key[2] and package["name"] == harness] != ["0.0.0"]:
                raise ValueError("The unpublished verification harness must retain its original 0.0.0 identity")
        product_packages = [package for key, package, _ in final
                            if not key[2] and package["name"].startswith("nestlink-")
                            and package["name"] != harness]
        if not product_packages or any(package["version"] != version for package in product_packages):
            raise ValueError("First-party product versions are not unified")
        receipt["product_packages"] = [package["name"] for package in product_packages]
        receipt["external_packages_and_edges_unchanged"] = True
        receipt["passed"] = True
    except BaseException as error:
        receipt["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        shutil.copyfile(lock, args.output / "Cargo.lock")
        (args.output / "version-lock.patch").write_bytes(subprocess.check_output(
            ["git", "diff", "--binary", "--no-ext-diff", "--", str(lock)], cwd=root))
        receipt["files"] = [{"path": path.name, "bytes": path.stat().st_size,
                             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                            for path in sorted(args.output.iterdir()) if path.is_file()]
        (args.output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
