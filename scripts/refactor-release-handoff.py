#!/usr/bin/env python3
"""Verify fixed release custody inputs and write an offline upload plan.

This tool never signs, uploads, creates a tag/release, or changes repositories.
Its signed handoff is a release owner's decision bound to exact evidence bytes;
schema validation cannot replace installed-product or physical-device testing.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging/native"))
import release_verify as verify

REPOSITORY_ID = "R_kgDOTz-mRQ"
REPOSITORIES = {
    "hub": ("ZHanry/home-tunnel", REPOSITORY_ID),
    "server": ("ZHanry/home-tunnel-server", "R_kgDOUSDIiA"),
    "client": ("ZHanry/home-tunnel-client", "R_kgDOUSDI3Q"),
    "android": ("ZHanry/home-tunnel-android", "R_kgDOUSDJHw"),
}
CURRENT_ROLES = frozenset((
    "windows-x64-setup", "windows-x64-privileged-setup",
    "linux-x64-server", "linux-arm64-server",
    "web-static", "oci-x64", "oci-arm64", "source", "sbom", "licenses",
    "materials", "acceptance", "native-payload-manifest", "native-packages-manifest",
))
PRESERVATION_ROLES = frozenset((
    "legacy-source-bundle", "legacy-source-report", "dirty-worktree-backups", "legacy-release-inventory",
))
REQUIRED_CASES = frozenset((
    "windows-10-installed", "windows-11-installed", "windows-privileged-input",
    "linux-x64-server-installed", "linux-arm64-server-installed",
    "chrome-current", "edge-current", "firefox-current",
    "company-to-home", "mobile-to-home", "72-hour-soak", "turn-capacity-and-revoke",
    "signature-windows", "signature-linux-update", "signature-oci",
    "install-upgrade-rollback-uninstall", "reinstall-new-identity-retained-data",
    "schema-migration-and-interruption-recovery", "license-and-source-audit",
))


class Blocked(ValueError):
    """A required final release identity or acceptance input is absent."""


def bounded_json(path, maximum=32 * 1024 * 1024):
    verify.regular(path)
    before = verify.sha256(path)
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("handoff metadata exceeds its budget")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate metadata field")
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique)
    if verify.sha256(path) != before:
        raise ValueError("handoff metadata changed during parsing")
    return result


def checksum(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def object_keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("metadata has missing or unknown fields")


def validate(plan):
    object_keys(plan, ("schema_version", "product", "purpose", "version", "source_revision",
                       "repository_node_id", "update_certificate_sha256", "completion", "artifacts", "acceptance_cases", "legacy_assets"))
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1 or plan["product"] != "NestLink-v15" or plan["purpose"] != "release-handoff" or plan["version"] != "15.0.0" or plan["repository_node_id"] != REPOSITORY_ID:
        raise ValueError("handoff identity differs from the approved first release")
    if plan["source_revision"] is None or plan["update_certificate_sha256"] is None:
        raise Blocked("final source and independent update identity are not enrolled")
    if not isinstance(plan["source_revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", plan["source_revision"]) or not checksum(plan["update_certificate_sha256"]):
        raise ValueError("invalid fixed source or update certificate identity")
    object_keys(plan["completion"], ("implementation", "installed_product_acceptance", "release_bytes_frozen", "legacy_preservation_review"))
    if any(value != "passed" for value in plan["completion"].values()):
        raise Blocked("implementation, installed-product acceptance and preservation review must be complete")
    validate_contents(plan)


def validate_contents(plan, *, allowed_case_statuses=frozenset(("passed",)), current_roles=CURRENT_ROLES, preservation_roles=PRESERVATION_ROLES, required_cases=REQUIRED_CASES):
    """Validate fixed custody records; formal release callers require passed cases."""
    if not isinstance(plan["artifacts"], list) or len(plan["artifacts"]) != len(current_roles | preservation_roles):
        raise ValueError("one fixed artifact for every required role is mandatory")
    roles, ids, paths = set(), set(), set()
    for item in plan["artifacts"]:
        object_keys(item, ("id", "role", "path", "bytes", "sha256", "source_revision"))
        if not isinstance(item["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item["id"]) or item["id"] in ids or item["role"] not in current_roles | preservation_roles or item["role"] in roles:
            raise ValueError("duplicate or invalid artifact ID/role")
        relative = verify.relative(item["path"]).as_posix()
        if relative.casefold() in paths:
            raise ValueError("artifact paths collide across supported platforms")
        if type(item["bytes"]) is not int or item["bytes"] <= 0 or not checksum(item["sha256"]):
            raise ValueError("final artifact length/hash is missing")
        if item["source_revision"] != (plan["source_revision"] if item["role"] in current_roles else None):
            raise ValueError("new products must share one source; historical material must not claim it was built from that source")
        ids.add(item["id"]); roles.add(item["role"]); paths.add(relative.casefold())
    if roles != current_roles | preservation_roles:
        raise ValueError("required artifact cohort is incomplete")
    cases = plan["acceptance_cases"]
    if not isinstance(cases, list) or len(cases) != len(required_cases):
        raise Blocked("the complete agreed platform and installed-product matrix is required")
    seen = set()
    evidence_ids = {item["id"] for item in plan["artifacts"] if item["role"] in ("acceptance", "materials")}
    for case in cases:
        object_keys(case, ("id", "status", "evidence_artifact_id"))
        if case["id"] not in required_cases or case["id"] in seen or case["evidence_artifact_id"] not in evidence_ids:
            raise ValueError("invalid or duplicate acceptance evidence reference")
        if case["status"] not in allowed_case_statuses:
            raise Blocked("the final installed-product matrix contains a pending/failed case")
        seen.add(case["id"])
    if not isinstance(plan["legacy_assets"], list) or len(plan["legacy_assets"]) > 10000:
        raise ValueError("invalid preserved release asset inventory")
    legacy_ids = set()
    for item in plan["legacy_assets"]:
        object_keys(item, ("component", "release_id", "asset_id", "path", "bytes", "sha256"))
        if item["component"] not in REPOSITORIES or type(item["release_id"]) is not int or item["release_id"] <= 0 or type(item["asset_id"]) is not int or item["asset_id"] <= 0 or item["asset_id"] in legacy_ids or type(item["bytes"]) is not int or item["bytes"] < 0 or not checksum(item["sha256"]):
            raise ValueError("invalid historical release asset identity")
        relative = verify.relative(item["path"]).as_posix()
        if relative.casefold() in paths:
            raise ValueError("historical asset paths collide")
        legacy_ids.add(item["asset_id"]); paths.add(relative.casefold())


def fixed_file(bundle, item):
    path = verify.artifact_path(bundle, item["path"])
    before = path.stat()
    if before.st_size != item["bytes"] or verify.sha256(path) != item["sha256"]:
        raise ValueError("fixed handoff bytes differ from the signed statement")
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("handoff file changed during hashing")
    return path


def verify_preservation(plan, bundle):
    roles = {item["role"]: item for item in plan["artifacts"]}
    inventory_file = fixed_file(bundle, roles["legacy-release-inventory"])
    inventory = bounded_json(inventory_file)
    if verify.sha256(inventory_file) != roles["legacy-release-inventory"]["sha256"]:
        raise ValueError("historical inventory changed before parsing")
    if set(inventory.get("components", {})) != set(REPOSITORIES):
        raise ValueError("historical inventory must include all four approved repositories")
    expected = {}
    for component, identity in REPOSITORIES.items():
        current = inventory["components"][component]
        if (current.get("repository"), current.get("repository_node_id")) != identity or current.get("asset_count") != len(current.get("assets", [])):
            raise ValueError("historical repository identity or asset count differs")
        for asset in current["assets"]:
            key = (component, asset["release_id"], asset["asset_id"])
            if key in expected or asset.get("state") != "uploaded":
                raise ValueError("duplicate or incomplete source asset")
            expected[key] = (asset["bytes"], asset["github_sha256"])
    actual = {(item["component"], item["release_id"], item["asset_id"]): (item["bytes"], item["sha256"]) for item in plan["legacy_assets"]}
    if actual != expected:
        raise Blocked("the signed upload handoff does not preserve every observed historical Release byte")
    report_file = fixed_file(bundle, roles["legacy-source-report"])
    report = bounded_json(report_file)
    if verify.sha256(report_file) != roles["legacy-source-report"]["sha256"]:
        raise ValueError("historical preservation report changed before parsing")
    if not all(report.get(key) is True for key in ("bundle_standalone_verified", "restored_ref_map_verified", "strict_fsck_passed")):
        raise Blocked("standalone source bundle restore/fsck evidence is missing")
    source_bundle = roles["legacy-source-bundle"]
    if (report.get("bundle", {}).get("sha256"), report.get("bundle", {}).get("bytes")) != (source_bundle["sha256"], source_bundle["bytes"]):
        raise ValueError("source preservation report does not bind the actual bundle")
    return report.get("unavailable_gitlinks", [])


def prepare(args):
    before = verify.sha256(args.plan)
    plan = bounded_json(args.plan)
    validate(plan)
    if not checksum(args.certificate_sha256):
        raise Blocked("the independently enrolled public update certificate pin is required")
    if args.certificate_sha256 != plan["update_certificate_sha256"]:
        raise ValueError("handoff may not choose its own trust anchor")
    verify.verify_cms(args.plan, args.signature, args.certificate, args.certificate_sha256, openssl=args.openssl)
    if verify.sha256(args.plan) != before:
        raise ValueError("signed handoff changed between parsing and signature verification")
    revision = verify.command(["git", "-C", ROOT, "rev-parse", "HEAD"]).decode().strip()
    if revision != plan["source_revision"] or verify.command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=all"]).strip():
        raise ValueError("handoff requires the exact clean source commit")
    if args.expected_source and args.expected_source != revision:
        raise ValueError("CI dispatch/build source differs from the signed cohort")
    for item in plan["artifacts"] + plan["legacy_assets"]:
        fixed_file(args.bundle, item)
    unavailable = verify_preservation(plan, args.bundle)
    uploads = [{"asset_name": item["id"] + "--" + Path(item["path"]).name, "local_path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"], "role": item["role"]} for item in plan["artifacts"]]
    uploads += [{"asset_name": "legacy-" + item["component"] + "-" + str(item["release_id"]) + "-" + str(item["asset_id"]) + ".blob", "local_path": item["path"], "bytes": item["bytes"], "sha256": item["sha256"], "role": "legacy-release-asset"} for item in plan["legacy_assets"]]
    for item in uploads:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", item["asset_name"]):
            raise ValueError("upload asset name must be an unambiguous safe basename")
    if len({item["asset_name"].casefold() for item in uploads}) != len(uploads):
        raise ValueError("upload names collide")
    output = {"schema_version": 1, "purpose": "offline-reviewed-release-upload-plan", "version": "15.0.0", "source_revision": revision, "repository_node_id": REPOSITORY_ID, "allowed_repository_names": ["ZHanry/home-tunnel", "ZHanry/NestLink"], "tag": "v15.0.0", "handoff_sha256": verify.sha256(args.plan), "uploads": uploads, "unavailable_historical_gitlinks": unavailable, "remote_upload_performed": False, "durable_remote_preservation_verified": False, "repository_finalization_ready": False, "next_required": "Review the signed decision and final evidence; upload unchanged bytes only after full acceptance; re-download/verify durable copies and refresh remote inventory before any repository deletion/rename/branch cleanup."}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(output, stream, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--certificate-sha256", required=True)
    parser.add_argument("--expected-source")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    try:
        result = prepare(args)
    except Blocked as error:
        print("Release handoff blocked: " + str(error), file=sys.stderr); return 2
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print("Release handoff refused: " + str(error), file=sys.stderr); return 1
    print(json.dumps({"upload_plan": str(args.output), "assets": len(result["uploads"]), "remote_upload_performed": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
