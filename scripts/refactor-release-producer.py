#!/usr/bin/env python3
"""Produce a fixed v15 release cohort from one clean final commit.

This command is used by the manual release workflow. It never substitutes a
development key, changes source versions, or marks installed-product acceptance
passed. Final signed bytes can subsequently be promoted without rebuilding.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.parse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ID = "R_kgDOTz-mRQ"
NATIVE = {
    "windows-x64": ("x86_64-pc-windows-msvc", "windows-x86_64", ("desktop", "daemon", "privileged")),
    "linux-x64": ("x86_64-unknown-linux-gnu", "linux-x86_64", ("server",)),
    "linux-arm64": ("aarch64-unknown-linux-gnu", "linux-aarch64", ("server",)),
}
PARTS = frozenset(NATIVE) | {"web"}
PACKAGE_PATHS = {
    "windows-x64-setup": "NestLink-windows-x64.exe",
    "windows-x64-privileged-setup": "NestLink-windows-x64-privileged.exe",
    "linux-x64-server": "NestLink-server-linux-x64.deb",
    "linux-arm64-server": "NestLink-server-linux-arm64.deb",
}
FINAL_ROLES = frozenset(PACKAGE_PATHS) | {"web-static", "oci-x64", "oci-arm64", "source", "sbom", "licenses", "materials", "native-payload-manifest", "native-packages-manifest"}
SECRETS = {
    "windows": ("NESTLINK_WINDOWS_PFX_BASE64", "NESTLINK_WINDOWS_PFX_PASSWORD"),
    "update": ("NESTLINK_UPDATE_CERTIFICATE_BASE64", "NESTLINK_UPDATE_PRIVATE_KEY_BASE64", "NESTLINK_UPDATE_KEY_PASSWORD"),
}


class Blocked(ValueError):
    pass


def require(value, message):
    if not value:
        raise ValueError(message)


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def hash_value(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def regular(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400), "Expected a regular, non-reparse release file")
    return info


def directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400), "Expected a real, non-reparse directory")


def relative(value):
    require(isinstance(value, str) and 0 < len(value) <= 512 and "\\" not in value, "Expected a portable release path")
    parts = value.split("/")
    for part in parts:
        require(part not in ("", ".", "..") and not part.endswith((" ", ".")), "Unsafe release path component")
        require(not any(ord(ch) < 32 or ch in ':<>"|?*' for ch in part), "Nonportable release path")
        require(not re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part), "Reserved path component")
    return PurePosixPath(value)


def artifact(root, value):
    parts = relative(value).parts
    directory(root)
    current = root
    for component in parts[:-1]:
        current /= component
        directory(current)
    current /= parts[-1]
    regular(current)
    return current


def json_read(path, maximum=16 * 1024 * 1024):
    regular(path)
    require(path.stat().st_size <= maximum, "Release metadata exceeds its budget")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate release metadata field")
            result[key] = value
        return result
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def create_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run(command, *, cwd=ROOT, env=None, timeout=300, capture=True):
    # Never echo command arguments/environment: signing tool arguments can be
    # sensitive. Child failure output is bounded and not automatically replayed.
    result = subprocess.run([str(item) for item in command], cwd=cwd, env=env, timeout=timeout,
                            stdout=subprocess.PIPE if capture else None, stderr=subprocess.PIPE)
    require(result.returncode == 0, "Release subprocess failed: " + Path(str(command[0])).name)
    return result.stdout if capture else b""


def clean_source(revision, version):
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "Full lowercase source commit is required")
    require(run(["git", "rev-parse", "HEAD"]).decode().strip() == revision, "Checked-out source differs from the cohort")
    require(not run(["git", "status", "--porcelain", "--untracked-files=all"]).strip(), "Release requires clean source including untracked files")
    data = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    require(data["workspace"]["package"]["version"] == version == "15.0.0", "Commit the unified final 15.0.0 version before release dispatch")
    require(all(value.get("version") == "=" + version for key, value in data["workspace"]["dependencies"].items()
                if key.startswith("nestlink-") and isinstance(value, dict) and "path" in value), "First-party dependency versions differ")
    for path in ("compatibility.json", "protocol-spec/contract.json", "protocol-spec/openapi.json"):
        value = json_read(ROOT / path)
        actual = value["info"]["version"] if path.endswith("openapi.json") else value["product_version"] if path.endswith("contract.json") else value["version"]
        require(actual == version, "Committed protocol/version metadata is inconsistent")


def configuration(path):
    value = json_read(path, maximum=64 * 1024)
    require(set(value) == {"schema_version", "product", "repository_node_id", "version", "native_state_compatibility",
                           "update_certificate_sha256", "windows_certificate_sha256",
                           "windows_timestamp_url", "debian_maintainer", "oci_base"}, "Unknown or missing producer configuration")
    require(value["schema_version"] == 1 and value["product"] == "NestLink-v15" and value["repository_node_id"] == REPOSITORY_ID and value["version"] == "15.0.0", "Producer identity differs from the approved release")
    require(isinstance(value["native_state_compatibility"], str) and re.fullmatch(r"v15-native-state[1-9][0-9]*", value["native_state_compatibility"]), "Missing reviewed native state compatibility")
    missing = [key for key in ("update_certificate_sha256", "windows_certificate_sha256") if value[key] is None]
    missing += [key for key in ("windows_timestamp_url", "debian_maintainer", "oci_base") if value[key] is None]
    if missing:
        raise Blocked("Public release settings are not enrolled: " + ", ".join(missing))
    require(all(hash_value(value[key]) for key in ("update_certificate_sha256", "windows_certificate_sha256")), "Invalid public signing certificate pin")
    require(value["update_certificate_sha256"] != value["windows_certificate_sha256"], "Update signing identity must be independent of platform signing")
    require(isinstance(value["windows_timestamp_url"], str) and re.fullmatch(r"https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9._/-]*)?", value["windows_timestamp_url"]), "Enroll a fixed HTTPS RFC3161 timestamp endpoint")
    require(isinstance(value["debian_maintainer"], str) and re.fullmatch(r"[^\r\n<>]{1,100} <[^\s<>@]+@[^\s<>@]+>", value["debian_maintainer"]), "Enroll the actual Debian maintainer")
    require(isinstance(value["oci_base"], str) and re.fullmatch(r"ubuntu:24\.04@sha256:[0-9a-f]{64}", value["oci_base"]), "Enroll the Ubuntu 24.04 multi-architecture OCI index digest")
    return value


def validate_cohort(value):
    require(value.get("schema_version") == 1 and value.get("kind") == "nestlink-release-cohort" and value.get("repository_node_id") == REPOSITORY_ID, "Unsupported release cohort")
    require(value.get("version") == "15.0.0" and isinstance(value.get("source_revision"), str) and re.fullmatch(r"[0-9a-f]{40}", value["source_revision"]), "Cohort source/version is not fixed")
    require(type(value.get("release_sequence")) is int and 1 <= value["release_sequence"] <= 999, "Invalid release sequence")
    require(type(value.get("run_id")) is int and value["run_id"] > 0 and type(value.get("run_attempt")) is int and value["run_attempt"] > 0, "Missing CI execution identity")
    require(hash_value(value.get("configuration_sha256")) and type(value.get("source_epoch")) is int and value["source_epoch"] > 0, "Missing immutable configuration/epoch")


def load_cohort(path, *, source=True):
    value = json_read(path)
    validate_cohort(value)
    config_path = ROOT / "config/release-producer.json"
    config = configuration(config_path)
    require(digest(config_path) == value["configuration_sha256"], "Cohort configuration is not the committed public policy")
    require(value.get("identities") == {key: config[key] for key in ("update_certificate_sha256", "windows_certificate_sha256")}, "Cohort signing identities differ")
    require(value.get("native_state_compatibility") == config["native_state_compatibility"], "Cohort native state compatibility differs")
    schema = re.findall(r"(?m)^pub const SCHEMA_VERSION: i32 = ([0-9]+);$", (ROOT / "crates/storage/src/lib.rs").read_text(encoding="utf-8"))
    require(len(schema) == 1 and value.get("control_state_compatibility") == "v15-control-schema" + schema[0] + "-epoch1", "Cohort control schema differs from its source")
    for key, variable in (("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT")):
        if os.environ.get(variable):
            require(str(value[key]) == os.environ[variable], "Cohort belongs to another CI execution")
    if source:
        clean_source(value["source_revision"], value["version"])
    return value, config


def outside_source(path):
    require(not path.resolve().is_relative_to(ROOT.resolve()), "Build outputs and secrets must stay outside the clean source checkout")


def preflight(args):
    outside_source(args.output)
    report = {"schema_version": 1, "kind": "nestlink-release-readiness", "status": "blocked", "missing": []}
    try:
        config = configuration(args.config)
    except Blocked as error:
        report["missing"].append(str(error))
        create_json(args.output / "readiness.json", report)
        raise
    missing = [name for group in SECRETS.values() for name in group if not os.environ.get(name)]
    if missing:
        report["missing"] = missing
        create_json(args.output / "readiness.json", report)
        raise Blocked("Required fixed signing secrets are not configured: " + ", ".join(missing))
    clean_source(args.source, config["version"])
    require(args.config.resolve() == (ROOT / "config/release-producer.json").resolve(), "Release policy must be committed at its fixed path")
    schema_text = (ROOT / "crates/storage/src/lib.rs").read_text(encoding="utf-8")
    schema = re.findall(r"(?m)^pub const SCHEMA_VERSION: i32 = ([0-9]+);$", schema_text)
    require(len(schema) == 1 and int(schema[0]) >= 4, "Control schema must be a single committed authority")
    cohort = {"schema_version": 1, "kind": "nestlink-release-cohort", "repository_node_id": REPOSITORY_ID,
              "version": config["version"], "source_revision": args.source, "release_sequence": args.sequence,
              "run_id": args.run_id, "run_attempt": args.run_attempt,
              "configuration_sha256": digest(args.config),
              "source_epoch": int(run(["git", "show", "-s", "--format=%ct", args.source]).decode().strip()),
              "native_state_compatibility": config["native_state_compatibility"],
              "control_state_compatibility": "v15-control-schema" + schema[0] + "-epoch1",
              "identities": {key: config[key] for key in ("update_certificate_sha256", "windows_certificate_sha256")}}
    validate_cohort(cohort)
    create_json(args.output / "cohort.json", cohort)
    report.update(status="ready", cohort_sha256=digest(args.output / "cohort.json"), source_revision=args.source)
    create_json(args.output / "readiness.json", report)
    print(json.dumps({"readiness": "ready", "source_revision": args.source, "cohort_sha256": report["cohort_sha256"]}))


def materialize(args):
    outside_source(args.output)
    require(not args.output.exists(), "Secret directory must be new")
    args.output.mkdir(mode=0o700, parents=True)
    variables = {"windows": {"NESTLINK_WINDOWS_PFX_BASE64": "windows.pfx"},
                 "update": {"NESTLINK_UPDATE_CERTIFICATE_BASE64": "update.crt", "NESTLINK_UPDATE_PRIVATE_KEY_BASE64": "update.key"}}[args.group]
    require(all(os.environ.get(key) for key in SECRETS[args.group]), "Required fixed signing secret is missing")
    for key, name in variables.items():
        value = base64.b64decode(os.environ[key], validate=True)
        require(0 < len(value) <= 4 * 1024 * 1024, "Signing input exceeds its budget")
        path = args.output / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    # No certificate is generated and no private value/path is printed.


def file_record(root, path, role):
    regular(path)
    before = path.stat()
    result = {"path": relative(path.relative_to(root).as_posix()).as_posix(), "role": role,
              "bytes": before.st_size, "sha256": digest(path)}
    after = path.stat()
    require(result["bytes"] > 0 and (before.st_ino, before.st_size, before.st_mtime_ns) == (after.st_ino, after.st_size, after.st_mtime_ns), "Artifact changed while recording fixed bytes")
    return result


def copy_fixed(source, destination):
    regular(source)
    before = digest(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    require(digest(destination) == before == digest(source), "Artifact changed while copying fixed bytes")


def receipt(args, part, files, evidence):
    create_json(args.output / "parts" / (part + ".json"), {
        "schema_version": 1, "kind": "nestlink-release-part", "part": part,
        "cohort_sha256": digest(args.cohort), "artifacts": files, "evidence": evidence,
    })


def tool_facts(commands):
    result = []
    for command in commands:
        executable = shutil.which(str(command[0]))
        require(executable, "Required release tool is missing")
        record = {"tool": Path(str(command[0])).name, "version": run(command).decode("utf-8", "replace").strip()[:8000], "executable_sha256": digest(Path(executable))}
        result.append(record)
    return result


def elf(path, machine):
    regular(path)
    with path.open("rb") as stream:
        header = stream.read(64)
    require(len(header) == 64 and header[:6] == b"\x7fELF\x02\x01" and int.from_bytes(header[18:20], "little") == machine, "Release executable ELF architecture mismatch")


def pe_x64(path):
    regular(path)
    with path.open("rb") as stream:
        header = stream.read(64)
        require(header[:2] == b"MZ" and len(header) == 64, "Release executable is not a PE")
        offset = int.from_bytes(header[60:64], "little")
        require(64 <= offset <= 1024 * 1024, "Invalid PE header offset")
        stream.seek(offset)
        pe = stream.read(6)
    require(pe[:4] == b"PE\0\0" and int.from_bytes(pe[4:6], "little") == 0x8664, "Release PE architecture is not x64")


def collect_native(args):
    cohort, config = load_cohort(args.cohort)
    target, folder, roles = NATIVE[args.target]
    outside_source(args.output)
    supplier = module("release_codec_supplier", "scripts/refactor-native-codecs.py")
    supplier.verify_receipt(args.codec_prefix, target, ROOT / "docs/refactor/native-codecs.lock.json")
    files, evidence = [], []
    for role in roles:
        name = "nestlink-" + role + (".exe" if args.target == "windows-x64" else "")
        source = args.input / name
        if args.target == "windows-x64":
            pe_x64(source)
            signing = module("release_signatures", "scripts/refactor-signatures.py")
            result = signing.windows_signature(source, config["windows_certificate_sha256"], args.powershell)
            create_json(args.output / "evidence" / (folder + "-" + role + "-signature.json"), result)
        else:
            elf(source, 183 if args.target == "linux-arm64" else 62)
        destination = args.output / folder / name
        copy_fixed(source, destination)
        files.append(file_record(args.output, destination, "native-" + args.target + "-" + role))
    codec = args.output / "evidence" / (folder + "-codecs.json")
    copy_fixed(args.codec_prefix / supplier.RECEIPT, codec)
    evidence.append(file_record(args.output, codec, "native-codec-receipt"))
    for path in sorted((args.output / "evidence").glob(folder + "-*-signature.json")):
        evidence.append(file_record(args.output, path, "authenticode-verification"))
    tools = args.output / "evidence" / (folder + "-build-tools.json")
    create_json(tools, tool_facts((("rustc", "--version", "--verbose"), ("cargo", "--version"))))
    evidence.append(file_record(args.output, tools, "native-rust-toolchain"))
    receipt(args, args.target, files, evidence)




def tree_files(root, maximum=100000, bytes_limit=2 * 1024**3):
    directory(root)
    pending, result, seen, total = [root], [], set(), 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            name = relative(path.relative_to(root).as_posix()).as_posix()
            require(name.casefold() not in seen, "Case-colliding archive path")
            seen.add(name.casefold())
            require(len(seen) <= maximum, "Archive member budget exceeded")
            info = path.lstat()
            require(not (getattr(info, "st_file_attributes", 0) & 0x400), "Reparse archive member")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
            else:
                regular(path)
                total += info.st_size
                require(total <= bytes_limit, "Archive byte budget exceeded")
                result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def pack_tree(root, output, epoch):
    files = tree_files(root)
    expected = {}
    with output.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for path in files:
                    name = path.relative_to(root).as_posix()
                    payload = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size, info.mtime, info.mode = len(payload), epoch, 0o644
                    archive.addfile(info, io.BytesIO(payload))
                    expected[name] = hashlib.sha256(payload).hexdigest()
        raw.flush()
        os.fsync(raw.fileno())
    with tarfile.open(output, "r:gz") as archive:
        actual = {}
        for item in archive:
            require(item.isfile() and item.name not in actual, "Generated archive did not read back as regular unique files")
            relative(item.name)
            actual[item.name] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
    require(actual == expected, "Generated archive failed byte-for-byte readback")
    return expected


def collect_web(args):
    cohort, _ = load_cohort(args.cohort)
    outside_source(args.output)
    files = tree_files(args.input, maximum=20000, bytes_limit=512 * 1024**2)
    index = artifact(args.input, "index.html").read_text(encoding="utf-8")
    require(len(files) >= 3 and "<script" in index and "nestlink.css" in index and any(path.suffix == ".wasm" and path.stat().st_size > 0 for path in files), "Web release is missing its built HTML/CSS/script/WASM")
    args.output.mkdir(parents=True, exist_ok=True)
    destination = args.output / "NestLink-web-static.tar.gz"
    contents = pack_tree(args.input, destination, cohort["source_epoch"])
    proof = args.output / "evidence/web-files.json"
    create_json(proof, contents)
    tools = args.output / "evidence/web-build-tools.json"
    create_json(tools, tool_facts((("rustc", "--version", "--verbose"), ("cargo", "--version"), ("trunk", "--version"), ("wasm-bindgen", "--version"), ("wasm-opt", "--version"))))
    receipt(args, "web", [file_record(args.output, destination, "web-static")], [file_record(args.output, proof, "web-static-readback"), file_record(args.output, tools, "web-build-tools")])


def verify_record(root, item):
    require(set(item) == {"path", "role", "bytes", "sha256"} and type(item["bytes"]) is int and item["bytes"] > 0 and hash_value(item["sha256"]), "Invalid fixed artifact record")
    path = artifact(root, item["path"])
    require(file_record(root, path, item["role"]) == item, "Artifact differs from its producing job's fixed bytes")
    return path


def verify_parts(cohort_path, bundle):
    result, paths = {}, set()
    for part in sorted(PARTS):
        record = json_read(artifact(bundle, "parts/" + part + ".json"))
        require(set(record) == {"schema_version", "kind", "part", "cohort_sha256", "artifacts", "evidence"} and record["schema_version"] == 1 and record["kind"] == "nestlink-release-part" and record["part"] == part and record["cohort_sha256"] == digest(cohort_path), "Mixed source/run/configuration release cohort")
        require(isinstance(record["artifacts"], list) and isinstance(record["evidence"], list) and 0 < len(record["artifacts"]) <= 8 and len(record["evidence"]) <= 16, "Invalid release part inventory")
        for item in record["artifacts"] + record["evidence"]:
            require(item["path"].casefold() not in paths, "Release parts overlap")
            paths.add(item["path"].casefold())
            verify_record(bundle, item)
        expected = {"native-" + part + "-" + role for role in NATIVE[part][2]} if part in NATIVE else {"web-static"}
        require({item["role"] for item in record["artifacts"]} == expected and len(record["artifacts"]) == len(expected), "Missing or duplicate product role")
        if part in NATIVE:
            _, folder, roles = NATIVE[part]
            expected_paths = {folder + "/nestlink-" + role + (".exe" if part == "windows-x64" else "") for role in roles}
            require({item["path"] for item in record["artifacts"]} == expected_paths, "Native part paths differ from packaging inputs")
        result[part] = record
    actual_parts = {path.stem for path in (bundle / "parts").glob("*.json")}
    require(PARTS <= actual_parts <= PARTS | {"metadata", "oci-x64", "oci-arm64"}, "Unknown release part supplied")
    return result


def sign_metadata(path, signature, certificate, key, pin, openssl="openssl"):
    regular(path)
    regular(certificate)
    regular(key)
    require(not signature.exists(), "Refusing to overwrite a detached release signature")
    require(os.environ.get("NESTLINK_UPDATE_KEY_PASSWORD"), "Fixed update key password is not configured")
    verify = module("release_verify", "packaging/native/release_verify.py")
    # Verify the independently committed public certificate before using a key.
    der = run([openssl, "x509", "-in", certificate, "-outform", "DER"])
    require(hashlib.sha256(der).hexdigest() == pin, "Update certificate differs from its independently enrolled pin")
    run([openssl, "cms", "-sign", "-binary", "-in", path, "-signer", certificate,
         "-inkey", key, "-passin", "env:NESTLINK_UPDATE_KEY_PASSWORD", "-md", "sha256", "-outform", "DER", "-out", signature])
    verify.verify_cms(path, signature, certificate, pin, openssl=openssl)


def payload_manifest(args):
    cohort, config = load_cohort(args.cohort)
    verify_parts(args.cohort, args.bundle)
    value = json_read(ROOT / "config/native-payload.template.json")
    value.update(version=cohort["version"], source_revision=cohort["source_revision"], release_sequence=cohort["release_sequence"])
    for item in value["artifacts"]:
        item["state_compatibility"] = cohort["control_state_compatibility"] if item["role"] == "server" else cohort["native_state_compatibility"]
        if item["platform"] == "windows":
            item["windows_certificate_sha256"] = config["windows_certificate_sha256"]
    plan = args.output / "native-payload.plan.json"
    create_json(plan, value)
    packaging = module("release_packaging", "scripts/refactor-native-packaging.py")
    packaging.freeze(argparse.Namespace(plan=plan, bundle=args.bundle, output=args.output / "native-payload.json"))
    sign_metadata(args.output / "native-payload.json", args.output / "native-payload.p7s", args.certificate, args.key, config["update_certificate_sha256"], args.openssl)
    copy_fixed(args.certificate, args.output / "update.crt")


def package_manifest(args):
    cohort, config = load_cohort(args.cohort)
    packaging = module("release_packaging", "scripts/refactor-native-packaging.py")
    packaging.payload(argparse.Namespace(bundle=args.bundle, manifest=args.payload / "native-payload.json", signature=args.payload / "native-payload.p7s", certificate=args.payload / "update.crt", certificate_sha256=config["update_certificate_sha256"], openssl=args.openssl))
    value = json_read(ROOT / "config/native-packages.template.json")
    value.update(version=cohort["version"], source_revision=cohort["source_revision"], release_sequence=cohort["release_sequence"])
    for item in value["artifacts"]:
        item["payload_manifest_sha256"] = digest(args.payload / "native-payload.json")
        item["state_compatibility"] = cohort["control_state_compatibility"] if item["role"] == "server" else cohort["native_state_compatibility"]
        if item["platform"] == "windows":
            item["windows_certificate_sha256"] = config["windows_certificate_sha256"]
    plan = args.output / "native-packages.plan.json"
    create_json(plan, value)
    packaging.freeze(argparse.Namespace(plan=plan, bundle=args.bundle, output=args.output / "native-packages.json"))
    sign_metadata(args.output / "native-packages.json", args.output / "native-packages.p7s", args.certificate, args.key, config["update_certificate_sha256"], args.openssl)


def unpack_web(source, output):
    # Web is produced locally by pack_tree, but a substituted CI artifact must
    # still not gain extraction primitives in the OCI context owner.
    with tarfile.open(source, "r:gz") as archive:
        seen, total, members = set(), 0, []
        for item in archive:
            require(item.isfile() and len(members) < 20000 and 0 <= item.size <= 128 * 1024**2, "Unsafe archive member")
            relative(item.name)
            require(item.name.casefold() not in seen, "Duplicate Web archive member")
            seen.add(item.name.casefold())
            total += item.size
            require(total <= 512 * 1024**2, "Web archive exceeds byte budget")
            members.append(item)
        for item in members:
            path = output / item.name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                shutil.copyfileobj(archive.extractfile(item), stream)


def oci_context(args):
    cohort, config = load_cohort(args.cohort)
    parts = verify_parts(args.cohort, args.bundle)
    require(args.target in ("linux-x64", "linux-arm64"), "OCI requires a native Linux target")
    require(not args.output.exists(), "OCI build context must be fresh")
    outside_source(args.output)
    args.output.mkdir(parents=True)
    native = next(item for item in parts[args.target]["artifacts"] if item["role"].endswith("-server"))
    copy_fixed(verify_record(args.bundle, native), args.output / "nestlink-server")
    web = parts["web"]["artifacts"][0]
    unpack_web(verify_record(args.bundle, web), args.output / "web")
    for path in tree_files(ROOT / "packaging/notices"):
        copy_fixed(path, args.output / "notices" / path.relative_to(ROOT / "packaging/notices"))
    copy_fixed(ROOT / "packaging/oci/Dockerfile.v15", args.output / "Dockerfile")
    create_json(args.output / "build-policy.json", {"base": config["oci_base"], "source_revision": cohort["source_revision"], "version": cohort["version"], "architecture": "arm64" if args.target == "linux-arm64" else "amd64"})


def oci_expected_files(parts, target, bundle):
    native = next(item for item in parts[target]["artifacts"] if item["role"].endswith("-server"))
    expected = {"usr/local/bin/nestlink-server": native["sha256"]}
    web = verify_record(bundle, parts["web"]["artifacts"][0])
    with tarfile.open(web, "r:gz") as archive:
        for item in archive:
            require(item.isfile() and item.size <= 128 * 1024**2, "Invalid fixed Web archive member")
            relative(item.name)
            name = "usr/share/nestlink/web/" + item.name
            require(name not in expected, "Duplicate fixed Web archive member")
            expected[name] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
    return expected


def inspect_oci(path, architecture, cohort, expected_files=None):
    regular(path)
    # Validate OCI index -> manifest -> config -> layers by digest, then check
    # the actual declared architecture/source/version. Never trust a filename.
    with tarfile.open(path, "r:*") as archive:
        members, total = {}, 0
        for item in archive:
            name = item.name.removeprefix("./").rstrip("/")
            if name in ("", ".") and item.isdir():
                continue
            relative(name)
            require(item.isfile() or item.isdir(), "OCI archive links/special members are forbidden")
            require(name not in members and len(members) < 10000, "Duplicate or oversized OCI member inventory")
            require(item.size <= 1024**3, "OCI member exceeds byte budget")
            total += item.size
            require(total <= 2 * 1024**3, "OCI archive exceeds byte budget")
            members[name] = item
        def read(name, maximum=16 * 1024**2):
            require(name in members and members[name].isfile() and members[name].size <= maximum, "OCI descriptor is absent/unbounded")
            return archive.extractfile(members[name]).read()
        def descriptor(item):
            require(isinstance(item, dict) and re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", "")) and type(item.get("size")) is int and item["size"] > 0, "Invalid OCI descriptor")
            raw = read("blobs/sha256/" + item["digest"][7:], maximum=1024**3)
            require(len(raw) == item["size"] and "sha256:" + hashlib.sha256(raw).hexdigest() == item["digest"], "OCI descriptor digest/size mismatch")
            return raw
        require(json.loads(read("oci-layout")) == {"imageLayoutVersion": "1.0.0"}, "Unsupported OCI layout")
        index = json.loads(read("index.json"))
        require(index.get("schemaVersion") == 2 and len(index.get("manifests", [])) == 1, "One OCI architecture image is required")
        manifest = json.loads(descriptor(index["manifests"][0]))
        require(manifest.get("schemaVersion") == 2 and manifest.get("mediaType") == "application/vnd.oci.image.manifest.v1+json", "Unsupported OCI image manifest")
        config = json.loads(descriptor(manifest["config"]))
        require(config.get("architecture") == architecture and config.get("os") == "linux", "OCI runtime architecture differs")
        labels = config.get("config", {}).get("Labels", {})
        require(labels.get("org.opencontainers.image.revision") == cohort["source_revision"] and labels.get("org.opencontainers.image.version") == cohort["version"], "OCI image source/version differs from the cohort")
        require(config.get("config", {}).get("User") == "65532:65532", "OCI runtime must use the non-root product user")
        require(0 < len(manifest.get("layers", [])) <= 64, "OCI layer budget exceeded")
        require(config.get("config", {}).get("Entrypoint") == ["/usr/local/bin/nestlink-server"], "OCI entry point differs from the fixed product")
        actual_files, rootfs_entries, system_files, system_links = {}, 0, {}, {}
        for layer in manifest["layers"]:
            raw = descriptor(layer)
            if expected_files is None:
                continue
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as filesystem:
                for item in filesystem:
                    rootfs_entries += 1
                    require(rootfs_entries <= 200000 and item.size <= 512 * 1024**2, "OCI expanded layer exceeds its budget")
                    name = item.name.removeprefix("./").rstrip("/")
                    if name in ("", ".") and item.isdir():
                        continue
                    # These are paths in a Linux rootfs, never host extraction
                    # destinations. Base-image symlinks are permitted, while
                    # any link touching our expected product files is rejected.
                    require(name and not name.startswith("/") and ".." not in name.split("/"), "Unsafe OCI rootfs path")
                    parent, _, leaf = name.rpartition("/")
                    if leaf.startswith(".wh."):
                        affected = (parent + "/" if parent else "") if leaf == ".wh..wh..opq" else (parent + "/" if parent else "") + leaf[4:]
                        for previous in list(actual_files):
                            if not affected or previous == affected or previous.startswith(affected.rstrip("/") + "/"):
                                del actual_files[previous]
                        for collection in (system_files, system_links):
                            for previous in list(collection):
                                if not affected or previous == affected or previous.startswith(affected.rstrip("/") + "/"):
                                    del collection[previous]
                        continue
                    product_paths = set(expected_files) | {"var/lib/dpkg/status"}
                    touches_product = name in product_paths or any(key.startswith(name + "/") for key in product_paths)
                    if touches_product:
                        require(item.isfile() if name in product_paths else item.isdir(), "OCI layer replaced a product path with a link/special file")
                    if name in expected_files or name.startswith("usr/share/nestlink/web/"):
                        if item.isdir():
                            continue
                        require(item.isfile(), "OCI Web/product file is not regular")
                        value = hashlib.sha256()
                        stream = filesystem.extractfile(item)
                        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                            value.update(chunk)
                        actual_files[name] = value.hexdigest()
                    if name == "var/lib/dpkg/status" or name.startswith(("usr/share/doc/", "usr/share/common-licenses/")):
                        if item.isfile():
                            require(item.size <= 16 * 1024**2, "OCI system package/notice file exceeds its budget")
                            system_files[name] = filesystem.extractfile(item).read()
                            system_links.pop(name, None)
                        elif item.issym() or item.islnk():
                            target = item.linkname.lstrip("/") if item.linkname.startswith("/") else posixpath.normpath(posixpath.join(posixpath.dirname(name), item.linkname)) if item.issym() else item.linkname.removeprefix("./")
                            require(target.startswith(("usr/share/doc/", "usr/share/common-licenses/")) and ".." not in target.split("/"), "OCI notice link escapes its documentation namespace")
                            system_links[name] = target
                            system_files.pop(name, None)
                        else:
                            require(item.isdir(), "OCI documentation contains a special file")
                        require(sum(map(len, system_files.values())) <= 64 * 1024**2, "OCI system notice inventory exceeds its byte budget")
        if expected_files is not None:
            require(actual_files == expected_files, "OCI product/Web bytes differ from the native and Web producing jobs")
            require("var/lib/dpkg/status" in system_files, "Pinned Ubuntu OCI image lacks its actual package inventory")
            status = system_files["var/lib/dpkg/status"].decode("utf-8")
            packages = debian_packages(status)
            require(packages and any(name.endswith("/copyright") for name in system_files), "OCI system packages or copyright notices are missing")
        else:
            packages = []
        return {"manifest_digest": index["manifests"][0]["digest"], "architecture": architecture, "os": "linux", "layers": len(manifest["layers"]), "product_bytes_verified": expected_files is not None,
                "os_packages": packages, "system_files": system_files, "system_notice_links": system_links}


def debian_packages(status):
    packages = []
    for paragraph in re.split(r"\n\s*\n", status):
        fields = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ":" in line:
                key, value = line.split(":", 1)
                require(key not in fields, "Duplicate Debian package inventory field")
                fields[key] = value.strip()
        if fields.get("Status") != "install ok installed":
            continue
        require(all(fields.get(key) for key in ("Package", "Version", "Architecture")), "Incomplete installed OCI package record")
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", fields["Package"]) and fields["Architecture"] in ("amd64", "arm64", "all"), "Unsupported OCI OS package identity")
        packages.append({"name": fields["Package"], "version": fields["Version"], "architecture": fields["Architecture"], "source": fields.get("Source", fields["Package"]), "homepage": fields.get("Homepage")})
    require(len(packages) <= 2000 and len({(item["name"], item["architecture"]) for item in packages}) == len(packages), "OCI OS package inventory is duplicated or unbounded")
    return sorted(packages, key=lambda item: (item["name"], item["architecture"]))


def collect_oci(args):
    cohort, _ = load_cohort(args.cohort)
    outside_source(args.output)
    architecture = "arm64" if args.target == "linux-arm64" else "amd64"
    parts = verify_parts(args.cohort, args.bundle)
    result = inspect_oci(args.input, architecture, cohort, oci_expected_files(parts, args.target, args.bundle))
    system_files = result.pop("system_files")
    role = "oci-arm64" if architecture == "arm64" else "oci-x64"
    destination = args.output / ("NestLink-" + role + ".tar")
    copy_fixed(args.input, destination)
    evidence = args.output / "evidence" / (role + ".json")
    create_json(evidence, {**result, "cohort_sha256": digest(args.cohort), "base": configuration(ROOT / "config/release-producer.json")["oci_base"]})
    with tempfile.TemporaryDirectory(prefix="nestlink-system-notices-") as scratch:
        notices = Path(scratch)
        for name, raw in system_files.items():
            relative(name)
            path = notices / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        create_json(notices / "notice-link-index.json", result["system_notice_links"])
        notice_archive = args.output / "evidence" / (role + "-system-notices.tar.gz")
        pack_tree(notices, notice_archive, cohort["source_epoch"])
    tools = args.output / "evidence" / (role + "-build-tools.json")
    create_json(tools, tool_facts((("buildah", "--version"),)))
    receipt(args, role, [file_record(args.output, destination, role)], [file_record(args.output, evidence, "oci-descriptor-readback"), file_record(args.output, notice_archive, "oci-system-notices"), file_record(args.output, tools, "oci-build-tools")])


def cargo_license_expression(value):
    if not value:
        return "NOASSERTION"
    if "/" not in value:
        return value
    # Cargo historically used slash for OR. SPDX 2.3 expressions do not.
    # Review new spellings explicitly instead of changing arbitrary strings.
    legacy = {("MIT", "Apache-2.0"): "MIT OR Apache-2.0",
              ("Apache-2.0", "MIT"): "Apache-2.0 OR MIT",
              ("Unlicense", "MIT"): "Unlicense OR MIT"}
    parts = tuple(part.strip() for part in value.split("/"))
    require(parts in legacy, "Unreviewed legacy Cargo license expression")
    return legacy[parts]


def metadata(args):
    cohort, _ = load_cohort(args.cohort)
    outside_source(args.output)
    args.output.mkdir(parents=True, exist_ok=True)
    # git archive is exact committed source. It never includes ignored build
    # caches, secret directories, or dirty historical working trees.
    source = args.output / "NestLink-source.tar"
    run(["git", "archive", "--format=tar", "--prefix=NestLink-" + cohort["version"] + "/", "--output=" + str(source.resolve()), cohort["source_revision"]])
    regular(source)
    cargo = json.loads(run(["cargo", "metadata", "--format-version", "1", "--all-features", "--locked"], timeout=600))
    lock_packages = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))["package"]
    checksums = {(item["name"], item["version"], item.get("source")): item.get("checksum") for item in lock_packages}
    packages = []
    for index, item in enumerate(cargo["packages"]):
        checksum = checksums.get((item["name"], item["version"], item.get("source")))
        entry = {"SPDXID": "SPDXRef-Cargo-" + str(index), "name": item["name"], "versionInfo": item["version"],
                 "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                 "licenseDeclared": cargo_license_expression(item.get("license")),
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:cargo/" + item["name"] + "@" + item["version"]}]}
        if item.get("license") and entry["licenseDeclared"] != item["license"]:
            entry["sourceInfo"] = "Original Cargo manifest license declaration: " + item["license"] + "; legacy Cargo slash syntax normalized to SPDX OR. Original declaration retained in the Cargo notice index and manifest."
        if checksum and hash_value(checksum):
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        packages.append(entry)
    native_lock = json_read(ROOT / "docs/refactor/native-codecs.lock.json")
    for item in native_lock["sources"]:
        packages.append({"SPDXID": "SPDXRef-Native-" + item["name"], "name": item["name"], "versionInfo": item["version"],
                         "downloadLocation": item["url"], "filesAnalyzed": False, "licenseConcluded": "NOASSERTION",
                         "licenseDeclared": "BSD-3-Clause", "checksums": [{"algorithm": "SHA256", "checksumValue": item["archive_sha256"]}],
                         "sourceInfo": "Pinned source commit " + item["commit"] + "; complete upstream license/patent notices are in the license archive."})
    # OS packages and image-bound system notices are added by the final cohort
    # owner, after both real architecture OCI images are available.
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "NestLink-" + cohort["version"], "documentNamespace": "https://github.com/ZHanry/NestLink/sbom/" + cohort["source_revision"] + "/" + str(cohort["run_id"]) + "-" + str(cohort["run_attempt"]),
            "creationInfo": {"created": __import__("datetime").datetime.fromtimestamp(cohort["source_epoch"], __import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"), "creators": ["Tool: nestlink-release-producer-v1"]},
            "packages": packages, "comment": "Cargo/native exact dependency inventory. OCI system packages are added by the final owner. NOASSERTION records never assert a missing license review passed."}
    create_json(args.output / "NestLink-build-sbom.spdx.json", sbom)
    with tempfile.TemporaryDirectory(prefix="nestlink-notices-", dir=args.output) as scratch:
        notices = Path(scratch)
        for relative_name in ("LICENSE", "docs/refactor/source-ledger.json", "docs/refactor/native-codecs.lock.json"):
            copy_fixed(ROOT / relative_name, notices / relative_name)
        for path in tree_files(ROOT / "packaging/notices"):
            copy_fixed(path, notices / "notices" / path.relative_to(ROOT / "packaging/notices"))
        for path in (ROOT / "docs/refactor").glob("*review*"):
            if path.is_file():
                copy_fixed(path, notices / "reviews" / path.name)
        cargo_notices = module("release_cargo_notices", "scripts/refactor-cargo-notices.py")
        try:
            cargo_notice_index = cargo_notices.collect(ROOT, cargo, notices / "cargo")
        except cargo_notices.MissingNotices as error:
            create_json(args.output / "evidence/cargo-notice-index.json", error.index)
            raise
        create_json(args.output / "evidence/cargo-notice-index.json", cargo_notice_index)
        pack_tree(notices, args.output / "NestLink-build-licenses.tar.gz", cohort["source_epoch"])
    proof = {"cohort_sha256": digest(args.cohort), "source_revision": cohort["source_revision"], "input_files": {}, "tools": {}}
    for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "docs/refactor/native-codecs.lock.json", "docs/refactor/source-ledger.json", "docs/refactor/cargo-notice-supplements.json", "scripts/refactor-cargo-notices.py", "config/release-producer.json", "config/product-scope.json"):
        proof["input_files"][name] = digest(ROOT / name)
    for command in (("rustc", "--version", "--verbose"), ("cargo", "--version"), (sys.executable, "--version")):
        proof["tools"][Path(command[0]).name] = run(command).decode("utf-8", "replace").strip()
    create_json(args.output / "evidence/source-build-inputs.json", proof)
    receipt(args, "metadata", [file_record(args.output, args.output / name, role) for name, role in (("NestLink-source.tar", "source"), ("NestLink-build-sbom.spdx.json", "sbom-input"), ("NestLink-build-licenses.tar.gz", "licenses-input"))], [file_record(args.output, args.output / "evidence/source-build-inputs.json", "source-and-toolchain-inputs"), file_record(args.output, args.output / "evidence/cargo-notice-index.json", "cargo-notice-index")])


def finalize(args):
    cohort, config = load_cohort(args.cohort)
    parts = verify_parts(args.cohort, args.bundle)
    verify = module("release_verify", "packaging/native/release_verify.py")
    require(not (args.output / "release-cohort.json").exists(), "Final release cohort already exists")
    payload = verify.verify_bundle(args.bundle, args.bundle / "native-payload.json", args.bundle / "native-payload.p7s", args.certificate, config["update_certificate_sha256"], openssl=args.openssl)
    packages = verify.verify_bundle(args.bundle, args.bundle / "native-packages.json", args.bundle / "native-packages.p7s", args.certificate, config["update_certificate_sha256"], openssl=args.openssl)
    require(payload["purpose"] == "native-payload" and packages["purpose"] == "native-packages", "Final native manifests have the wrong purpose")
    require(all(value["source_revision"] == cohort["source_revision"] and value["version"] == cohort["version"] and value["release_sequence"] == cohort["release_sequence"] for value in (payload, packages)), "Native final cohort differs")
    require(all(item.get("payload_manifest_sha256") == digest(args.bundle / "native-payload.json") for item in packages["artifacts"]), "Final packages do not bind the signed payload")
    artifacts = [item for part in ("web",) for item in parts[part]["artifacts"]]
    for role, name in PACKAGE_PATHS.items():
        artifacts.append(file_record(args.bundle, artifact(args.bundle, name), role))
    extra_parts = {}
    oci_proofs = {}
    oci_system_files = {}
    for part in ("metadata", "oci-x64", "oci-arm64"):
        path = artifact(args.bundle, "parts/" + part + ".json")
        value = json_read(path)
        require(value.get("kind") == "nestlink-release-part" and value.get("part") == part and value.get("cohort_sha256") == digest(args.cohort), "Mixed metadata/OCI cohort")
        expected = {"source", "sbom-input", "licenses-input"} if part == "metadata" else {part}
        require({item["role"] for item in value["artifacts"]} == expected and len(value["artifacts"]) == len(expected), "Final metadata/OCI part incomplete")
        for item in value["artifacts"] + value["evidence"]:
            verify_record(args.bundle, item)
        extra_parts[part] = value
        artifacts += [item for item in value["artifacts"] if item["role"] not in {"sbom-input", "licenses-input"}]
        if part.startswith("oci-"):
            target = "linux-arm64" if part.endswith("arm64") else "linux-x64"
            proof = inspect_oci(verify_record(args.bundle, value["artifacts"][0]), "arm64" if part.endswith("arm64") else "amd64", cohort, oci_expected_files(parts, target, args.bundle))
            oci_system_files[part] = proof.pop("system_files")
            recorded = [item for item in value["evidence"] if item["role"] == "oci-descriptor-readback"]
            require(len(recorded) == 1 and json_read(verify_record(args.bundle, recorded[0])) == {**proof, "cohort_sha256": digest(args.cohort), "base": config["oci_base"]}, "OCI package/notice evidence differs from the actual final image")
            oci_proofs[part] = proof
    meta = {item["role"]: verify_record(args.bundle, item) for item in extra_parts["metadata"]["artifacts"]}
    sbom = json_read(meta["sbom-input"])
    for part, proof in sorted(oci_proofs.items()):
        require(all(item["architecture"] in {proof["architecture"], "all"} for item in proof["os_packages"]), "OCI OS package architecture differs from its image")
        for index, item in enumerate(proof["os_packages"]):
            sbom["packages"].append({"SPDXID": "SPDXRef-" + part + "-OS-" + str(index), "name": item["name"], "versionInfo": item["version"],
                "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:deb/ubuntu/" + urllib.parse.quote(item["name"], safe=".") + "@" + urllib.parse.quote(item["version"], safe=".") + "?arch=" + item["architecture"] + "&distro=ubuntu-24.04"}],
                "sourceInfo": item["source"], "comment": "Read from var/lib/dpkg/status in exact signed OCI archive " + proof["manifest_digest"] + "; system documentation/copyright files are retained in the license archive."})
    sbom["comment"] = "Exact Cargo, pinned native sources and actual x64/ARM64 OCI OS packages. Full system notices are archived. NOASSERTION records require the independent license/source acceptance review."
    create_json(args.output / "NestLink-sbom.spdx.json", sbom)
    artifacts.append(file_record(args.output, args.output / "NestLink-sbom.spdx.json", "sbom"))
    with tempfile.TemporaryDirectory(prefix="nestlink-final-notices-", dir=args.output) as scratch:
        notices = Path(scratch)
        unpack_web(meta["licenses-input"], notices / "product")
        for part in ("oci-x64", "oci-arm64"):
            candidates = [item for item in extra_parts[part]["evidence"] if item["role"] == "oci-system-notices"]
            require(len(candidates) == 1, "OCI system notices are missing")
            os_notices = notices / part
            unpack_web(verify_record(args.bundle, candidates[0]), os_notices)
            require(json_read(os_notices / "notice-link-index.json") == oci_proofs[part]["system_notice_links"], "OCI notice link index differs from the actual image")
            actual_names = {path.relative_to(os_notices).as_posix() for path in tree_files(os_notices)} - {"notice-link-index.json"}
            require(actual_names == set(oci_system_files[part]), "OCI system notice archive has missing/extra files")
            require(all(digest(artifact(os_notices, name)) == hashlib.sha256(raw).hexdigest() for name, raw in oci_system_files[part].items()), "OCI license archive bytes differ from its image")
        pack_tree(notices, args.output / "NestLink-licenses.tar.gz", cohort["source_epoch"])
    artifacts.append(file_record(args.output, args.output / "NestLink-licenses.tar.gz", "licenses"))
    for name, role in (("native-payload.json", "native-payload-manifest"), ("native-packages.json", "native-packages-manifest")):
        artifacts.append(file_record(args.bundle, artifact(args.bundle, name), role))
    # Detached CMS signatures independently authenticate exact OCI archive bytes.
    for item in artifacts:
        if item["role"].startswith("oci-"):
            path = verify_record(args.bundle, item)
            sign_metadata(path, args.output / (path.name + ".p7s"), args.certificate, args.key, config["update_certificate_sha256"], args.openssl)
    with tempfile.TemporaryDirectory(prefix="nestlink-materials-", dir=args.output) as scratch:
        materials = Path(scratch)
        copy_fixed(args.cohort, materials / "build-cohort.json")
        copy_fixed(args.certificate, materials / "update.crt")
        for name in ("native-payload.json", "native-payload.p7s", "native-packages.json", "native-packages.p7s"):
            copy_fixed(artifact(args.bundle, name), materials / name)
        for name in ("parts", "evidence"):
            for path in tree_files(args.bundle / name):
                copy_fixed(path, materials / name / path.relative_to(args.bundle / name))
        for path in sorted(args.output.glob("NestLink-oci-*.tar.p7s")):
            copy_fixed(path, materials / path.name)
        pack_tree(materials, args.output / "NestLink-materials.tar.gz", cohort["source_epoch"])
    artifacts.append(file_record(args.output, args.output / "NestLink-materials.tar.gz", "materials"))
    require({item["role"] for item in artifacts} == FINAL_ROLES and len(artifacts) == len(FINAL_ROLES), "Final cohort role matrix is incomplete")
    statement = {"schema_version": 1, "kind": "nestlink-fixed-release", "cohort_sha256": digest(args.cohort),
                 "version": cohort["version"], "source_revision": cohort["source_revision"], "release_sequence": cohort["release_sequence"],
                 "repository_node_id": REPOSITORY_ID, "artifacts": sorted(artifacts, key=lambda item: item["role"]),
                 "installed_product_acceptance": "pending", "promotion": "requires-signed-handoff-and-complete-acceptance"}
    create_json(args.output / "release-cohort.json", statement)
    sign_metadata(args.output / "release-cohort.json", args.output / "release-cohort.p7s", args.certificate, args.key, config["update_certificate_sha256"], args.openssl)
    print(json.dumps({"candidate": "fixed-and-signed", "source_revision": cohort["source_revision"], "installed_product_acceptance": "pending", "artifacts": len(artifacts)}))


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="action", required=True)
    pre = sub.add_parser("preflight")
    pre.add_argument("--config", type=Path, default=ROOT / "config/release-producer.json")
    pre.add_argument("--source", required=True)
    pre.add_argument("--sequence", type=int, required=True)
    pre.add_argument("--run-id", type=int, required=True)
    pre.add_argument("--run-attempt", type=int, required=True)
    pre.add_argument("--output", type=Path, required=True)
    secret = sub.add_parser("materialize-secrets")
    secret.add_argument("--group", choices=SECRETS, required=True)
    secret.add_argument("--output", type=Path, required=True)
    for action in ("collect-native", "collect-web", "payload-manifest", "package-manifest", "oci-context", "collect-oci", "metadata", "finalize"):
        command = sub.add_parser(action)
        command.add_argument("--cohort", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if action in ("collect-native", "collect-web", "collect-oci"):
            command.add_argument("--input", type=Path, required=True)
        if action in ("payload-manifest", "package-manifest", "oci-context", "collect-oci", "finalize"):
            command.add_argument("--bundle", type=Path, required=True)
        if action == "package-manifest":
            command.add_argument("--payload", type=Path, required=True)
        if action in ("payload-manifest", "package-manifest", "finalize"):
            command.add_argument("--certificate", type=Path, required=True)
            command.add_argument("--key", type=Path, required=True)
            command.add_argument("--openssl", default="openssl")
        if action in ("collect-native", "oci-context", "collect-oci"):
            command.add_argument("--target", choices=NATIVE if action == "collect-native" else ("linux-x64", "linux-arm64"), required=True)
        if action == "collect-native":
            command.add_argument("--codec-prefix", type=Path, required=True)
            command.add_argument("--powershell", default="powershell.exe")
    return value


def main():
    args = parser().parse_args()
    try:
        {"preflight": preflight, "materialize-secrets": materialize, "collect-native": collect_native,
         "collect-web": collect_web, "payload-manifest": payload_manifest,
         "package-manifest": package_manifest, "oci-context": oci_context, "collect-oci": collect_oci,
         "metadata": metadata, "finalize": finalize}[args.action](args)
    except Blocked as error:
        print("Release producer blocked: " + str(error), file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("Release producer refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
