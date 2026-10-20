#!/usr/bin/env python3
"""Build and freeze a development-only user acceptance cohort.

This entry point never invokes formal release preflight, imports production
signing secrets, weakens a production verifier, uploads, or changes repositories.
All required platforms and artifact roles must be present before freezing.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


# Reuse read-only architecture, archive, provenance and codec helpers. Formal
# configuration(), load_cohort(), signing and packaging entry points are never
# called or monkeypatched by this separate producer.
TOOLS = module("candidate_release_utilities", "scripts/refactor-release-producer.py")
NATIVE = TOOLS.NATIVE
VERSION = "0.7.0-rc.1"
REPOSITORY = "ZHanry/NestLink"
REPOSITORY_ID = "R_kgDOVNHMvg"
CURRENT_ROLES = frozenset((
    "windows-x64-setup", "windows-x64-privileged-setup", "linux-x64-desktop", "linux-arm64-desktop",
    "linux-x64-server", "linux-arm64-server", "android-arm64", "android-x86_64",
    "web-static", "oci-x64", "oci-arm64", "source", "sbom", "licenses",
    "materials", "acceptance", "native-payload-manifest", "native-packages-manifest",
))
REQUIRED_CASES = frozenset((
    "windows-10-installed", "windows-11-installed", "windows-privileged-input", "linux-x64-x11-installed",
    "linux-arm64-x11-installed", "gnome-wayland-authorized", "kde-wayland-authorized",
    "android-arm64-physical", "chrome-current", "edge-current", "firefox-current",
    "company-to-home", "mobile-to-home", "90-minute-soak", "turn-capacity-and-revoke",
    "signature-windows", "signature-android", "signature-linux-update", "signature-oci",
    "install-upgrade-rollback-uninstall", "reinstall-new-identity-retained-data",
    "schema-migration-and-interruption-recovery", "license-and-source-audit",
) + tuple("android-api-" + str(api) for api in range(30, 37)))
EXPECTED = {
    "windows-x64": {"windows-x64-setup", "windows-x64-privileged-setup"},
    "linux-x64": {"linux-x64-desktop", "linux-x64-server"},
    "linux-arm64": {"linux-arm64-desktop", "linux-arm64-server"},
    "android": {"android-arm64", "android-x86_64"},
    "web": {"web-static"},
    "metadata": {"source", "sbom-input", "licenses-input"},
    "oci-x64": {"oci-x64"},
    "oci-arm64": {"oci-arm64"},
}
EVIDENCE = {
    **{name: {name + "-codecs.json", name + "-tools.json", name + "-signing.json"} for name in NATIVE},
    "android": {"android-arm64-development-signature.json", "android-x86_64-development-signature.json",
                "aarch64-linux-android-codecs.json", "x86_64-linux-android-codecs.json", "android-tools.json"},
    "web": {"web-readback.json", "web-tools.json"},
    "metadata": {"cargo-notice-index.json", "candidate-source-inputs.json"},
    **{name: {name + "-readback.json", name + "-system-notices.tar.gz", name + "-tools.json"}
       for name in ("oci-x64", "oci-arm64")},
}
SIGNING = {"windows": "not-configured", "android": "development-only",
           "linux_update": "not-configured", "oci": "not-configured"}
ANDROID_GRAPHICS_PATH_AAR_SHA256 = "8ca4032b6d79b351f0b59ad4b580eddbb9423e1652f7c958830687f1eee2ec03"
# Raw JNI entries from the checksum-verified graphics-path-1.0.1.aar. AGP
# packages these already-stripped entries unchanged; no alternate bytes or
# additional dependency libraries are allowed by this candidate policy.
ANDROID_GRAPHICS_PATH_LIBRARIES = {
    "arm64-v8a": {"bytes": 10096, "sha256": "41e9a793c43a0f4fddb19e33f346bace464f30f888ba7b9eaf96294ea115bfb6"},
    "x86_64": {"bytes": 10760, "sha256": "4e56c996f13670e70082658de7880c4020eabf4f25e43387f88ed78a713fc9f0"},
}
require = TOOLS.require
digest = TOOLS.digest
read_json = TOOLS.json_read
write_json = TOOLS.create_json
copy_fixed = TOOLS.copy_fixed


def configuration():
    value = read_json(ROOT / "config/candidate-producer.json")
    require(value == {"schema_version": 1, "product": "NestLink", "version": VERSION,
                      "release_tag": "v" + VERSION, "repository": REPOSITORY, "repository_node_id": REPOSITORY_ID,
                      "android_application_id": "com.zhanry.nestlink.candidate",
                      "minimum_android_api": 30, "maximum_android_api": 36},
            "Candidate policy must bind the new RC repository and Android 11–16 matrix")
    return value


def clean_source(revision, version):
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "Full lowercase source commit is required")
    require(TOOLS.run(["git", "rev-parse", "HEAD"]).decode().strip() == revision, "Checked-out source differs from the RC cohort")
    require(not TOOLS.run(["git", "status", "--porcelain", "--untracked-files=all"]).strip(), "RC requires clean source including untracked files")
    data = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    require(data["workspace"]["package"]["version"] == version == VERSION, "Commit the unified RC product version before dispatch")
    require(all(value.get("version") == "=" + version for key, value in data["workspace"]["dependencies"].items()
                if key.startswith("nestlink-") and isinstance(value, dict) and "path" in value), "First-party dependency versions differ")
    for path in ("compatibility.json", "protocol-spec/contract.json", "protocol-spec/openapi.json"):
        value = read_json(ROOT / path)
        actual = value["info"]["version"] if path.endswith("openapi.json") else value["product_version"] if path.endswith("contract.json") else value["version"]
        require(actual == version, "Committed public RC version metadata is inconsistent")


def execute(command, *, cwd=ROOT, env=None, timeout=5400):
    """Bound each build command and stop its descendants on timeout."""
    command = [str(value) for value in command]
    process = subprocess.Popen(command, cwd=cwd, env=env,
                               start_new_session=os.name != "nt")
    try:
        code = process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            import signal
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise
    require(code == 0, "Candidate build command failed: " + Path(command[0]).name)


def outside(path):
    TOOLS.outside_source(path)
    require(not ROOT.resolve().is_relative_to(path.resolve()), "Candidate output cannot contain the source checkout")
    require(not path.exists() and not path.is_symlink(), "Candidate output must be a new directory")
    for parent in path.parents:
        if parent.exists():
            TOOLS.directory(parent)


def oci_index(path, base):
    require(digest(path) == base.rsplit(":", 1)[1], "OCI base index digest differs")
    value = read_json(path, maximum=256 * 1024)
    require(value.get("schemaVersion") == 2 and value.get("mediaType") in (
        "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"),
        "Candidate base must be an actual multi-architecture index")
    manifests = value.get("manifests")
    require(isinstance(manifests, list) and 2 <= len(manifests) <= 64
            and all(isinstance(item, dict) and isinstance(item.get("platform"), dict)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", item.get("digest", ""))
                    and type(item.get("size")) is int and item["size"] > 0 for item in manifests),
            "OCI base index has invalid platform descriptors")
    platforms = {item.get("platform", {}).get("architecture") for item in manifests
                 if item.get("platform", {}).get("os") == "linux"}
    require({"amd64", "arm64"} <= platforms, "OCI base index must contain both required Linux architectures")


def cohort(path):
    policy = configuration()
    value = read_json(path)
    require(value.get("schema_version") == 1 and value.get("kind") == "nestlink-development-candidate"
            and value.get("repository_node_id") == policy["repository_node_id"]
            and value.get("repository") == policy["repository"] and value.get("product") == "NestLink"
            and value.get("configuration_sha256") == digest(ROOT / "config/candidate-producer.json")
            and value.get("version") == VERSION, "Unexpected candidate cohort")
    require(value.get("signing") == SIGNING and value.get("production_update_eligible") is False,
            "Candidate cannot claim production signing or update eligibility")
    require(type(value.get("sequence")) is int and 1 <= value["sequence"] <= 999
            and value.get("android_version_code") == 700000 + value["sequence"],
            "Invalid candidate version allocation")
    require(type(value.get("source_epoch")) is int and value["source_epoch"] > 0,
            "Candidate source epoch is missing")
    require(re.fullmatch(r"ubuntu:24\.04@sha256:[0-9a-f]{64}", value.get("oci_base", "")),
            "Candidate OCI base must be fixed by index digest")
    require(value.get("android_application_id") == "com.zhanry.nestlink.candidate"
            and value.get("android_version_name") == VERSION
            and value.get("android_api_range") == [30, 36]
            and value.get("final_user_acceptance") == "pending"
            and value.get("required_parts") == sorted(EXPECTED)
            and value.get("required_roles") == sorted(CURRENT_ROLES),
            "Candidate platform, identity or pending acceptance declaration differs")
    oci_index(path.parent / "oci-base-index.json", value["oci_base"])
    for key, variable in (("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT")):
        require(type(value.get(key)) is int and value[key] > 0, "Missing candidate execution identity")
        require(not os.environ.get(variable) or str(value[key]) == os.environ[variable],
                "Candidate belongs to another CI execution")
    clean_source(value.get("source_revision"), value["version"])
    return value


def preflight(args):
    outside(args.output)
    policy = configuration()
    clean_source(args.source, policy["version"])
    require(1 <= args.sequence <= 999 and args.run_id > 0 and args.run_attempt > 0,
            "Candidate sequence or execution identity is invalid")
    require(re.fullmatch(r"ubuntu:24\.04@sha256:[0-9a-f]{64}", args.oci_base),
            "Resolve and fix the Ubuntu 24.04 multi-architecture index first")
    oci_index(args.oci_index, args.oci_base)
    require((policy["minimum_android_api"], policy["maximum_android_api"]) == (30, 36),
            "The full agreed Android 11–16 range must remain available")
    value = {"schema_version": 1, "kind": "nestlink-development-candidate",
             "product": "NestLink", "repository": policy["repository"],
             "repository_node_id": policy["repository_node_id"], "version": policy["version"],
             "configuration_sha256": digest(ROOT / "config/candidate-producer.json"),
             "source_revision": args.source, "sequence": args.sequence,
             "run_id": args.run_id, "run_attempt": args.run_attempt,
             "source_epoch": int(TOOLS.run(["git", "show", "-s", "--format=%ct", args.source]).decode().strip()),
             "android_version_code": 700000 + args.sequence,
             "android_application_id": "com.zhanry.nestlink.candidate",
             "android_version_name": policy["version"],
             "android_api_range": [30, 36], "oci_base": args.oci_base,
             "signing": SIGNING, "production_update_eligible": False,
             "final_user_acceptance": "pending", "required_parts": sorted(EXPECTED),
             "required_roles": sorted(CURRENT_ROLES)}
    write_json(args.output / "candidate-cohort.json", value)
    copy_fixed(args.oci_index, args.output / "oci-base-index.json")
    print(json.dumps({"candidate": "development-only", "source_revision": args.source,
                      "formal_signing": "not-configured", "required_roles": len(CURRENT_ROLES)}))


def record(root, path, role, revision):
    return {"id": role, **TOOLS.file_record(root, path, role), "source_revision": revision}


def verify_record(root, item, revision):
    require(isinstance(item, dict) and set(item) == {"id", "role", "path", "bytes", "sha256", "source_revision"}
            and item["id"] == item["role"] and item["source_revision"] == revision,
            "Candidate artifact identity/source differs")
    require(type(item["bytes"]) is int and item["bytes"] > 0 and TOOLS.hash_value(item["sha256"]),
            "Candidate artifact has no fixed size/hash")
    path = TOOLS.artifact(root, item["path"])
    require(path.stat().st_size == item["bytes"] and digest(path) == item["sha256"],
            "Candidate artifact bytes changed")
    return path


def part_receipt(args, name, artifacts, payload=()):
    value = cohort(args.cohort)
    evidence = [record(args.output, path, "evidence-" + path.name.replace(".", "-"), value["source_revision"])
                for path in TOOLS.tree_files(args.output / "evidence")]
    require({item["role"] for item in artifacts} == EXPECTED[name]
            and len(artifacts) == len(EXPECTED[name]), "Candidate part is incomplete")
    write_json(args.output / "parts" / (name + ".json"), {
        "schema_version": 1, "kind": "nestlink-development-candidate-part", "part": name,
        "cohort_sha256": digest(args.cohort), "source_revision": value["source_revision"],
        "artifacts": artifacts, "payload": list(payload), "evidence": evidence})


def zip_tree(root, destination, epoch):
    expected = {}
    timestamp = datetime.fromtimestamp(max(epoch, 315532800), timezone.utc)
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for path in TOOLS.tree_files(root):
            name = path.relative_to(root).as_posix()
            entry = zipfile.ZipInfo(name, timestamp.timetuple()[:6])
            entry.create_system = 3
            entry.external_attr = (stat.S_IFREG | (0o755 if path.stat().st_mode & 0o111 else 0o644)) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            raw = path.read_bytes()
            archive.writestr(entry, raw)
            expected[name] = hashlib.sha256(raw).hexdigest()
    with zipfile.ZipFile(destination) as archive:
        require(len(archive.namelist()) == len(set(archive.namelist())), "Duplicate candidate ZIP member")
        require({name: hashlib.sha256(archive.read(name)).hexdigest() for name in archive.namelist()} == expected,
                "Candidate ZIP readback differs")


def inno6_bootstrap_x86(path):
    """Check the pinned Inno 6 loader, separately from its x64 product payload.

    Inno 6 produces an x86 PE32 bootstrap even in x64 install mode. Native
    64-bit setup executables and SetupArchitecture were introduced in Inno 7:
    https://jrsoftware.org/ishelp/topic_64bit.htm
    """
    TOOLS.regular(path)
    with path.open("rb") as stream:
        header = stream.read(64)
        require(len(header) == 64 and header[:2] == b"MZ", "Candidate Inno 6 bootstrap is not a PE")
        offset = int.from_bytes(header[60:64], "little")
        require(64 <= offset <= 1024 * 1024, "Invalid candidate Inno 6 bootstrap PE offset")
        stream.seek(offset)
        pe = stream.read(24 + 224)
    require(len(pe) == 24 + 224 and pe[:4] == b"PE\0\0"
            and int.from_bytes(pe[4:6], "little") == 0x014c
            and int.from_bytes(pe[20:22], "little") == 224
            and int.from_bytes(pe[24:26], "little") == 0x010b,
            "Candidate Inno 6 bootstrap must be x86 PE32")
    characteristics = int.from_bytes(pe[22:24], "little")
    require(characteristics & 0x0002 and not characteristics & 0x2000
            and int.from_bytes(pe[24 + 68:24 + 70], "little") == 2,
            "Candidate Inno 6 bootstrap must be a Windows GUI executable")


def setup_candidate(input_directory, output, role, version, iscc):
    template = ROOT / "packaging/candidate/windows.iss"
    execute([iscc, "/Qp", "/DVersion=" + version, "/DPrivileged=" + ("1" if role == "privileged" else "0"),
             "/DPayloadDir=" + str(input_directory.resolve()), "/DOutputDir=" + str(output.parent.resolve()),
             "/DOutputBase=" + output.stem, template])
    inno6_bootstrap_x86(output)


def deb_candidate(input_directory, output, role, architecture, value):
    require(architecture in ("amd64", "arm64") and role in ("desktop", "server"), "Unknown candidate DEB")
    with tempfile.TemporaryDirectory(prefix="candidate-deb-") as scratch:
        staging = Path(scratch)
        prefix = staging / "opt/nestlink-rc" / role
        prefix.mkdir(parents=True)
        names = ("desktop", "daemon") if role == "desktop" else ("server",)
        for name in names:
            copy_fixed(input_directory / ("nestlink-" + name), prefix / ("nestlink-" + name))
            (prefix / ("nestlink-" + name)).chmod(0o755)
        control = staging / "DEBIAN"
        control.mkdir()
        depends = "libc6 (>= 2.39), libgcc-s1, libstdc++6"
        if role == "desktop":
            depends += ", libasound2t64, libpipewire-0.3-0t64, libwayland-client0, libxkbcommon0, libx11-6, libxcursor1, libxi6, libxrandr2, libgl1, xdg-desktop-portal, libsecret-tools"
        deb_version = value["version"].replace("-rc.", "~rc.")
        text = (f"Package: nestlink-rc-{role}\nVersion: {deb_version}\n"
                f"Architecture: {architecture}\nMaintainer: NestLink candidate build <candidate@invalid.example>\n"
                f"Depends: {depends}\nSection: net\nPriority: optional\n"
                "Description: NestLink development-only acceptance candidate\n"
                " Unsigned isolated candidate; production update and installation acceptance pending.\n")
        (control / "control").write_text(text, encoding="utf-8")
        if role == "desktop":
            launcher = staging / "usr/bin/nestlink-rc"
            launcher.parent.mkdir(parents=True)
            launcher.write_text('#!/bin/sh\nset -eu\nexec /opt/nestlink-rc/desktop/nestlink-desktop --state-dir "${XDG_STATE_HOME:-$HOME/.local/state}/NestLink-RC" "$@"\n', encoding="utf-8")
            launcher.chmod(0o755)
            desktop = staging / "usr/share/applications/nestlink-rc.desktop"
            desktop.parent.mkdir(parents=True)
            desktop.write_text("[Desktop Entry]\nType=Application\nName=NestLink RC\nName[zh_CN]=NestLink 远程桌面\nIcon=nestlink-rc\nExec=nestlink-rc\nTerminal=false\nCategories=Network;RemoteAccess;\n", encoding="utf-8")
        if role == "desktop":
            icon = staging / "usr/share/icons/hicolor/scalable/apps/nestlink-rc.svg"
            icon.parent.mkdir(parents=True)
            copy_fixed(ROOT / "brand/icon.svg", icon)
        notices = staging / "usr/share/doc" / ("nestlink-rc-" + role)
        notices.mkdir(parents=True)
        copy_fixed(ROOT / "LICENSE", notices / "copyright")
        (notices / "README.candidate").write_text(candidate_readme(value), encoding="utf-8")
        for path in staging.rglob("*"):
            if path.is_dir():
                path.chmod(0o755)
            elif not path.stat().st_mode & 0o111:
                path.chmod(0o644)
        execute(["dpkg-deb", "--build", "--root-owner-group", staging, output])
    actual = TOOLS.run(["dpkg-deb", "--field", output, "Architecture"]).decode().strip()
    require(actual == architecture, "Candidate DEB architecture differs")


def candidate_readme(value):
    return ("NestLink RC 开发预览版 / Development candidate\n"
            "登录后自动登记此电脑；浏览器访问获准后，请选择并批准共享屏幕。\n"
            "本预览版尚未配置 Windows 发行签名，卸载时保留用户数据。\n\n"
            f"Source: {value['source_revision']}\nVersion: {value['version']} candidate {value['sequence']}\n"
            "Windows Authenticode, fixed Android Release signing and update/OCI signatures are not configured.\n"
            "Android uses its recorded development certificate and an isolated .candidate applicationId.\n"
            "Candidate installers use separate paths and retain user data on uninstall.\n"
            "The optional Windows broker bytes are included; signed privileged activation remains pending.\n"
            "Formal installer lifecycle, signed upgrade/rollback, devices and cross-network acceptance remain pending.\n"
            "These packages must not be promoted into the production update channel.\n"
            "Linux server binary: /opt/nestlink-rc/server/nestlink-server --help\n"
            "Server deployment initialization is an explicit operator action.\n")


def collect_native(args):
    value = cohort(args.cohort)
    outside(args.output)
    target, folder, roles = NATIVE[args.target]
    supplier = module("candidate_codec_supplier", "scripts/refactor-native-codecs.py")
    supplier.verify_receipt(args.codec_prefix, target, ROOT / "docs/refactor/native-codecs.lock.json")
    destination = args.output / "native" / folder
    destination.mkdir(parents=True)
    payload = []
    for role in roles:
        name = "nestlink-" + role + (".exe" if args.target == "windows-x64" else "")
        source = args.input / name
        if args.target == "windows-x64":
            TOOLS.pe_x64(source)
        else:
            TOOLS.elf(source, 183 if args.target == "linux-arm64" else 62)
        copy_fixed(source, destination / name)
        if args.target != "windows-x64":
            (destination / name).chmod(0o755)
        payload.append(record(args.output, destination / name, "native-" + args.target + "-" + role, value["source_revision"]))
    files = args.output / "files"
    files.mkdir()
    (destination / "README.candidate.txt").write_text(candidate_readme(value), encoding="utf-8")
    artifacts = []
    for role in ("desktop", "privileged") if args.target == "windows-x64" else ("desktop", "server"):
        suffix = "windows-x64" + ("-privileged" if role == "privileged" else "") if args.target == "windows-x64" else args.target + ("-server" if role == "server" else "")
        path = files / ("NestLink-candidate-" + suffix + (".exe" if args.target == "windows-x64" else ".deb"))
        if args.target == "windows-x64":
            setup_candidate(destination, path, role, value["version"], args.iscc)
            artifact_role = "windows-x64-privileged-setup" if role == "privileged" else "windows-x64-setup"
        else:
            deb_candidate(destination, path, role, "arm64" if args.target == "linux-arm64" else "amd64", value)
            artifact_role = args.target + "-" + role
        artifacts.append(record(args.output, path, artifact_role, value["source_revision"]))
    evidence = args.output / "evidence"
    evidence.mkdir()
    copy_fixed(args.codec_prefix / supplier.RECEIPT, evidence / (args.target + "-codecs.json"))
    write_json(evidence / (args.target + "-tools.json"), TOOLS.tool_facts((("rustc", "--version", "--verbose"), ("cargo", "--version"))))
    write_json(evidence / (args.target + "-signing.json"), {"source_revision": value["source_revision"], "status": "not-configured", "production_update_eligible": False, "note": "Candidate installers are isolated and unsigned; formal installer and signed update verification remain mandatory for formal release."})
    # The explanatory file is part of the material inventory, not an executable.
    payload.append(record(args.output, destination / "README.candidate.txt", "native-" + args.target + "-readme", value["source_revision"]))
    part_receipt(args, args.target, artifacts, payload)


def android_graphics_dependency():
    """Keep the one allowed Compose native dependency bound to Gradle's pins."""
    lock = TOOLS.artifact(ROOT, "apps/android/app/gradle.lockfile").read_text(encoding="utf-8")
    entries = re.findall(r"^androidx\.graphics:graphics-path:([^=\s]+)=([^\r\n]+)$", lock, re.M)
    require(len(entries) == 1 and entries[0][0] == "1.0.1"
            and "debugRuntimeClasspath" in entries[0][1].split(","), "Candidate graphics-path dependency lock differs")
    metadata = TOOLS.artifact(ROOT, "apps/android/gradle/verification-metadata.xml")
    require(metadata.stat().st_size <= 2 * 1024**2, "Android dependency verification metadata exceeds its budget")
    namespace = "{https://schema.gradle.org/dependency-verification}"
    document = ET.fromstring(metadata.read_bytes())
    components = [item for item in document.findall(namespace + "components/" + namespace + "component")
                  if item.get("group") == "androidx.graphics" and item.get("name") == "graphics-path"]
    require(len(components) == 1 and components[0].get("version") == "1.0.1", "Candidate graphics-path component differs")
    artifacts = [item for item in components[0].findall(namespace + "artifact")
                 if item.get("name") == "graphics-path-1.0.1.aar"]
    require(len(artifacts) == 1 and [item.get("value") for item in artifacts[0].findall(namespace + "sha256")]
            == [ANDROID_GRAPHICS_PATH_AAR_SHA256], "Candidate graphics-path AAR verification pin differs")
    return {"coordinate": "androidx.graphics:graphics-path:1.0.1", "artifact": "graphics-path-1.0.1.aar",
            "aar_sha256": ANDROID_GRAPHICS_PATH_AAR_SHA256}


def android_native_libraries(archive, abi):
    names = archive.namelist()
    require(len(names) == len(set(names)) and len(names) <= 20000, "Candidate APK member inventory is invalid")
    native = [name for name in names if name.endswith(".so")]
    expected = {"lib/" + abi + "/" + name for name in ("libnestlink_android.so", "libandroidx.graphics.path.so")}
    require(set(native) == expected, "Candidate APK JNI set differs")
    facts = []
    with tempfile.TemporaryDirectory(prefix="candidate-jni-") as scratch:
        for name in sorted(native):
            info = archive.getinfo(name)
            require(0 < info.file_size <= 128 * 1024**2, "Candidate JNI exceeds its byte budget")
            require(info.compress_type == zipfile.ZIP_STORED, "Candidate JNI must use uncompressed direct loading")
            archive.fp.seek(info.header_offset)
            header = archive.fp.read(30)
            require(len(header) == 30 and header[:4] == b"PK\x03\x04", "Candidate JNI local ZIP header is invalid")
            data_offset = info.header_offset + 30 + int.from_bytes(header[26:28], "little") + int.from_bytes(header[28:30], "little")
            require(data_offset % 16384 == 0, "Candidate JNI ZIP data is not 16 KiB aligned")
            raw = archive.read(name)
            checksum = hashlib.sha256(raw).hexdigest()
            item = {"path": name, "bytes": len(raw), "sha256": checksum, "abi": abi,
                    "zip_data_offset": data_offset, "page_size_bytes": 16384}
            if name.endswith("/libandroidx.graphics.path.so"):
                require({"bytes": len(raw), "sha256": checksum} == ANDROID_GRAPHICS_PATH_LIBRARIES[abi],
                        "Candidate graphics-path JNI differs from the fixed AAR bytes")
                item["dependency"] = "androidx.graphics:graphics-path:1.0.1"
                item["aar_sha256"] = ANDROID_GRAPHICS_PATH_AAR_SHA256
            library = Path(scratch) / Path(name).name
            library.write_bytes(raw)
            # Apply the same existing ELF64 ABI and 16 KiB LOAD verification
            # to the application JNI and the one fixed Compose dependency.
            execute([sys.executable, ROOT / "scripts/verify-android-binary.py", "--library", library, "--abi", abi], timeout=60)
            item["elf_16k_verification"] = "passed"
            facts.append(item)
    return facts


def collect_android(args):
    value = cohort(args.cohort)
    outside(args.output)
    android_graphics_dependency()
    apks = sorted(args.input.glob("*.apk"))
    require(len(apks) == 2, "Candidate requires both Android ABI APKs")
    signatures = module("candidate_android_signatures", "scripts/refactor-signatures.py")
    files, seen, certificates = [], set(), set()
    evidence = args.output / "evidence"
    evidence.mkdir(parents=True)
    for path in apks:
        signer = [args.java, "-jar", args.apksigner] if Path(args.apksigner).suffix.lower() == ".jar" else [args.apksigner]
        output = TOOLS.run(signer + ["verify", "--verbose", "--print-certs", path]).decode("utf-8")
        pins = re.findall(r"^Signer #\d+ certificate SHA-256 digest:\s*([0-9a-fA-F]{64})\s*$", output, re.M)
        require(len(pins) == 1, "Candidate APK must have one recorded development signer")
        pin = pins[0].lower()
        certificates.add(pin)
        badging = TOOLS.run([args.aapt2, "dump", "badging", path]).decode("utf-8")
        match = re.search(r"^native-code:\s*'([^']+)'\s*$", badging, re.M)
        require(match and match[1] in ("arm64-v8a", "x86_64") and match[1] not in seen,
                "Candidate APK ABI is missing, duplicated or unexpected")
        abi = match[1]
        seen.add(abi)
        identity = signatures.android_signature(path, pin, value["android_application_id"], value["android_version_name"], [abi], args.apksigner, args.aapt2, args.java)
        require(int(identity["version_code"]) == value["android_version_code"], "Candidate Android version code differs")
        TOOLS.run([args.zipalign, "-c", "-P", "16", "-v", "4", path])
        with zipfile.ZipFile(path) as archive:
            native = android_native_libraries(archive, abi)
        role = "android-arm64" if abi == "arm64-v8a" else "android-x86_64"
        target = args.output / "files" / ("NestLink-candidate-" + role + ".apk")
        copy_fixed(path, target)
        files.append(record(args.output, target, role, value["source_revision"]))
        write_json(evidence / (role + "-development-signature.json"), {**identity, "status": "development-only", "fixed_release_identity_configured": False, "debuggable": "application-debuggable" in badging, "native_libraries": native})
    require(seen == {"arm64-v8a", "x86_64"} and len(certificates) == 1, "Android ABI cohort or development signer differs")
    supplier = module("candidate_android_codecs", "scripts/refactor-native-codecs.py")
    for target, prefix in (("aarch64-linux-android", args.codec_arm64), ("x86_64-linux-android", args.codec_x64)):
        supplier.verify_receipt(prefix, target, ROOT / "docs/refactor/native-codecs.lock.json")
        copy_fixed(prefix / supplier.RECEIPT, evidence / (target + "-codecs.json"))
    write_json(evidence / "android-tools.json", TOOLS.tool_facts(((args.java, "--version"), (args.aapt2, "version"), ("cargo", "--version"))))
    part_receipt(args, "android", files)


def collect_web(args):
    value = cohort(args.cohort)
    outside(args.output)
    files = TOOLS.tree_files(args.input, maximum=20000, bytes_limit=512 * 1024**2)
    class Entry(HTMLParser):
        styles, scripts = None, False
        def __init__(self):
            super().__init__()
            self.styles = []
        def handle_starttag(self, tag, attributes):
            attributes = dict(attributes)
            if tag == "script":
                self.scripts = True
            if tag == "link" and attributes.get("rel") == "stylesheet":
                self.styles.append(attributes.get("href", "").removeprefix("/"))
    entry = Entry()
    entry.feed(TOOLS.artifact(args.input, "index.html").read_text(encoding="utf-8"))
    require(files and entry.scripts and entry.styles
            and all(TOOLS.artifact(args.input, name).suffix == ".css" for name in entry.styles)
            and any(path.suffix == ".js" and path.stat().st_size > 0 for path in files)
            and any(path.suffix == ".wasm" and path.stat().st_size > 0 for path in files),
            "Candidate Web output is missing HTML/CSS/script/WASM")
    target = args.output / "files/NestLink-candidate-web.tar.gz"
    target.parent.mkdir(parents=True)
    inventory = TOOLS.pack_tree(args.input, target, value["source_epoch"])
    write_json(args.output / "evidence/web-readback.json", inventory)
    write_json(args.output / "evidence/web-tools.json", TOOLS.tool_facts((("rustc", "--version", "--verbose"), ("trunk", "--version"), ("wasm-bindgen", "--version"), ("wasm-opt", "--version"))))
    part_receipt(args, "web", [record(args.output, target, "web-static", value["source_revision"])])


def metadata(args):
    value = cohort(args.cohort)
    outside(args.output)
    files = args.output / "files"
    files.mkdir(parents=True)
    source = files / "NestLink-candidate-source.tar"
    TOOLS.run(["git", "archive", "--format=tar", "--prefix=NestLink-" + value["version"] + "/", "--output=" + str(source.resolve()), value["source_revision"]])
    cargo = json.loads(TOOLS.run(["cargo", "metadata", "--format-version", "1", "--all-features", "--locked"], timeout=600))
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    checksums = {(item["name"], item["version"], item.get("source")): item.get("checksum") for item in lock["package"]}
    packages = []
    for index, item in enumerate(cargo["packages"]):
        package = {"SPDXID": "SPDXRef-Cargo-" + str(index), "name": item["name"], "versionInfo": item["version"], "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": TOOLS.cargo_license_expression(item.get("license"))}
        checksum = checksums.get((item["name"], item["version"], item.get("source")))
        if checksum:
            package["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        packages.append(package)
    codec_lock = read_json(ROOT / "docs/refactor/native-codecs.lock.json")
    for item in codec_lock["sources"]:
        packages.append({"SPDXID": "SPDXRef-Native-" + item["name"], "name": item["name"], "versionInfo": item["version"], "downloadLocation": item["url"], "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "BSD-3-Clause", "checksums": [{"algorithm": "SHA256", "checksumValue": item["archive_sha256"]}], "sourceInfo": "Pinned source commit " + item["commit"]})
    dependencies = set()
    locks = sorted((ROOT / "apps/android").rglob("*.lockfile"))
    for path in locks:
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.fullmatch(r"([^#:=\s]+):([^:=\s]+):([^=\s]+)=(.*)", line)
            if match:
                dependencies.add((match[1], match[2], match[3]))
    require(dependencies, "Android dependency locks are missing")
    for index, (group, name, version) in enumerate(sorted(dependencies)):
        packages.append({"SPDXID": "SPDXRef-Maven-" + str(index), "name": group + ":" + name, "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION"})
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "NestLink-development-candidate", "documentNamespace": "https://github.com/ZHanry/NestLink/candidate-sbom/" + value["source_revision"] + "/" + str(value["run_id"]) + "-" + str(value["run_attempt"]), "creationInfo": {"created": datetime.fromtimestamp(value["source_epoch"], timezone.utc).isoformat().replace("+00:00", "Z"), "creators": ["Tool: nestlink-development-candidate-v1"]}, "packages": packages, "comment": "Dependency inventory, not an assertion of formal license or platform acceptance. OCI OS inventory is appended at freeze."}
    sbom_path = files / "NestLink-candidate-sbom-input.spdx.json"
    write_json(sbom_path, sbom)
    with tempfile.TemporaryDirectory(prefix="candidate-notices-") as scratch:
        notices = Path(scratch)
        for name in ("LICENSE", "docs/refactor/source-ledger.json", "docs/refactor/native-codecs.lock.json"):
            copy_fixed(ROOT / name, notices / name)
        for path in TOOLS.tree_files(ROOT / "packaging/notices"):
            copy_fixed(path, notices / "notices" / path.relative_to(ROOT / "packaging/notices"))
        for path in (ROOT / "docs/refactor").glob("*review*"):
            if path.is_file():
                copy_fixed(path, notices / "reviews" / path.name)
        collector = module("candidate_cargo_notices", "scripts/refactor-cargo-notices.py")
        index = collector.collect(ROOT, cargo, notices / "cargo")
        write_json(args.output / "evidence/cargo-notice-index.json", index)
        licenses = files / "NestLink-candidate-license-input.tar.gz"
        TOOLS.pack_tree(notices, licenses, value["source_epoch"])
    inputs = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "docs/refactor/native-codecs.lock.json", "scripts/refactor-candidate-producer.py", "config/candidate-producer.json", "apps/android/gradle/verification-metadata.xml", *[path.relative_to(ROOT).as_posix() for path in locks]]
    write_json(args.output / "evidence/candidate-source-inputs.json", {"source_revision": value["source_revision"], "cohort_sha256": digest(args.cohort), "files": {name: digest(ROOT / name) for name in inputs}, "tools": TOOLS.tool_facts((("rustc", "--version", "--verbose"), ("cargo", "--version"), (sys.executable, "--version")))})
    part_receipt(args, "metadata", [record(args.output, path, role, value["source_revision"]) for path, role in ((source, "source"), (sbom_path, "sbom-input"), (licenses, "licenses-input"))])


def read_parts(cohort_path, bundle, names=None):
    value = cohort(cohort_path)
    selected = set(EXPECTED if names is None else names)
    require(selected <= EXPECTED.keys(), "Unknown candidate build part")
    result, paths = {}, set()
    for name in sorted(selected):
        receipt = read_json(TOOLS.artifact(bundle, "parts/" + name + ".json"))
        require(receipt.get("schema_version") == 1 and receipt.get("kind") == "nestlink-development-candidate-part"
                and receipt.get("part") == name and receipt.get("cohort_sha256") == digest(cohort_path)
                and receipt.get("source_revision") == value["source_revision"], "Candidate receipt source/cohort differs")
        require(isinstance(receipt.get("artifacts"), list) and all(isinstance(item, dict) for item in receipt["artifacts"])
                and len(receipt["artifacts"]) == len(EXPECTED[name])
                and {item.get("role") for item in receipt["artifacts"]} == EXPECTED[name], "Required candidate platform/ABI role is absent")
        require(isinstance(receipt.get("payload"), list) and isinstance(receipt.get("evidence"), list) and receipt["evidence"], "Candidate provenance is missing")
        require(len(receipt["payload"]) <= 16 and len(receipt["evidence"]) <= 32,
                "Candidate part inventory exceeds its budget")
        for item in receipt["artifacts"] + receipt["payload"] + receipt["evidence"]:
            verify_record(bundle, item, value["source_revision"])
            path = item["path"].casefold()
            require(path not in paths, "Candidate parts reuse/collide artifact paths")
            paths.add(path)
        require({"evidence/" + filename for filename in EVIDENCE[name]} <= {item["path"] for item in receipt["evidence"]},
                "Required candidate build provenance is missing")
        if name in NATIVE:
            raw = {item["role"] for item in receipt["payload"] if not item["role"].endswith("-readme")}
            require(raw == {"native-" + name + "-" + role for role in NATIVE[name][2]}, "Candidate native executable matrix is incomplete")
        result[name] = receipt
    return value, result


def oci_context(args):
    value, parts = read_parts(args.cohort, args.bundle, {args.target, "web"})
    outside(args.output)
    require(not args.output.exists(), "Candidate OCI context must be fresh")
    native = next(item for item in parts[args.target]["payload"] if item["role"].endswith("-server"))
    copy_fixed(verify_record(args.bundle, native, value["source_revision"]), args.output / "nestlink-server")
    web = parts["web"]["artifacts"][0]
    TOOLS.unpack_web(verify_record(args.bundle, web, value["source_revision"]), args.output / "web")
    for path in TOOLS.tree_files(ROOT / "packaging/notices"):
        copy_fixed(path, args.output / "notices" / path.relative_to(ROOT / "packaging/notices"))
    copy_fixed(ROOT / "packaging/candidate/Dockerfile", args.output / "Dockerfile")
    write_json(args.output / "build-policy.json", {"base": value["oci_base"], "source_revision": value["source_revision"], "version": value["version"], "architecture": "arm64" if args.target == "linux-arm64" else "amd64", "signing": "not-configured", "production_update_eligible": False})


def oci_expected(parts, target, bundle, value):
    native = next(item for item in parts[target]["payload"] if item["role"].endswith("-server"))
    expected = {"usr/local/bin/nestlink-server": native["sha256"]}
    web = verify_record(bundle, parts["web"]["artifacts"][0], value["source_revision"])
    with tarfile.open(web, "r:gz") as archive:
        for item in archive:
            require(item.isfile(), "Candidate Web archive contains a special member")
            TOOLS.relative(item.name)
            expected["usr/share/nestlink/web/" + item.name] = hashlib.sha256(archive.extractfile(item).read()).hexdigest()
    return expected


def collect_oci(args):
    value, parts = read_parts(args.cohort, args.bundle, {args.target, "web"})
    outside(args.output)
    architecture = "arm64" if args.target == "linux-arm64" else "amd64"
    result = TOOLS.inspect_oci(args.input, architecture, value, oci_expected(parts, args.target, args.bundle, value))
    system_files = result.pop("system_files")
    role = "oci-arm64" if architecture == "arm64" else "oci-x64"
    path = args.output / "files" / ("NestLink-candidate-" + role + ".tar")
    copy_fixed(args.input, path)
    write_json(args.output / "evidence" / (role + "-readback.json"), {**result, "base": value["oci_base"], "signing": "not-configured"})
    with tempfile.TemporaryDirectory(prefix="candidate-oci-notices-") as scratch:
        notices = Path(scratch)
        for name, raw in system_files.items():
            TOOLS.relative(name)
            target = notices / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        write_json(notices / "notice-link-index.json", result["system_notice_links"])
        TOOLS.pack_tree(notices, args.output / "evidence" / (role + "-system-notices.tar.gz"), value["source_epoch"])
    write_json(args.output / "evidence" / (role + "-tools.json"), TOOLS.tool_facts((("buildah", "--version"),)))
    part_receipt(args, role, [record(args.output, path, role, value["source_revision"])])


def freeze(args):
    value, parts = read_parts(args.cohort, args.bundle)
    outside(args.output)
    require(not args.output.exists() and not args.output.resolve().is_relative_to(args.bundle.resolve()),
            "Candidate freeze destination must be new and separate from producing inputs")
    args.output.mkdir(parents=True)
    artifacts = []
    for part in parts.values():
        for item in part["artifacts"]:
            if item["role"].endswith("-input"):
                continue
            target = args.output / item["path"]
            copy_fixed(verify_record(args.bundle, item, value["source_revision"]), target)
            artifacts.append(record(args.output, target, item["role"], value["source_revision"]))
    files = args.output / "files"
    metadata_files = {item["role"]: item for item in parts["metadata"]["artifacts"]}
    sbom = read_json(verify_record(args.bundle, metadata_files["sbom-input"], value["source_revision"]))
    for role in ("oci-x64", "oci-arm64"):
        info = read_json(TOOLS.artifact(args.bundle, "evidence/" + role + "-readback.json"))
        for index, item in enumerate(info["os_packages"]):
            sbom["packages"].append({"SPDXID": "SPDXRef-" + role + "-OS-" + str(index), "name": item["name"], "versionInfo": item["version"], "downloadLocation": item.get("homepage") or "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "sourceInfo": item["source"], "comment": "Read from exact OCI image " + info["manifest_digest"] + "; system notices retained in license archive."})
    write_json(files / "NestLink-candidate-sbom.spdx.json", sbom)
    artifacts.append(record(args.output, files / "NestLink-candidate-sbom.spdx.json", "sbom", value["source_revision"]))
    with tempfile.TemporaryDirectory(prefix="candidate-licenses-") as scratch:
        notices = Path(scratch)
        copy_fixed(verify_record(args.bundle, metadata_files["licenses-input"], value["source_revision"]), notices / "build-notices.tar.gz")
        for role in ("oci-x64", "oci-arm64"):
            copy_fixed(TOOLS.artifact(args.bundle, "evidence/" + role + "-system-notices.tar.gz"), notices / (role + "-system-notices.tar.gz"))
        TOOLS.pack_tree(notices, files / "NestLink-candidate-licenses.tar.gz", value["source_epoch"])
    artifacts.append(record(args.output, files / "NestLink-candidate-licenses.tar.gz", "licenses", value["source_revision"]))
    native = [item for name in NATIVE for item in parts[name]["payload"] if not item["role"].endswith("-readme")]
    payload = {"schema_version": 1, "product": "NestLink", "purpose": "development-candidate-native-payload", "source_revision": value["source_revision"], "version": value["version"], "signing": SIGNING, "production_update_eligible": False, "container_artifact_id": "materials", "artifacts": native}
    write_json(files / "NestLink-candidate-native-payload.json", payload)
    packages = [item for item in artifacts if item["role"] in set().union(*(EXPECTED[name] for name in NATIVE))]
    write_json(files / "NestLink-candidate-native-packages.json", {"schema_version": 1, "product": "NestLink", "purpose": "development-candidate-native-packages", "source_revision": value["source_revision"], "version": value["version"], "signing": SIGNING, "production_update_eligible": False, "artifacts": packages})
    for role, name in (("native-payload-manifest", "NestLink-candidate-native-payload.json"), ("native-packages-manifest", "NestLink-candidate-native-packages.json")):
        artifacts.append(record(args.output, files / name, role, value["source_revision"]))
    with tempfile.TemporaryDirectory(prefix="candidate-materials-") as scratch:
        materials = Path(scratch)
        copy_fixed(args.cohort, materials / "candidate-cohort.json")
        copy_fixed(args.cohort.parent / "oci-base-index.json", materials / "oci-base-index.json")
        for name, part in parts.items():
            copy_fixed(args.bundle / "parts" / (name + ".json"), materials / "parts" / (name + ".json"))
            for item in part["evidence"] + part["payload"]:
                target = materials / item["path"]
                copy_fixed(verify_record(args.bundle, item, value["source_revision"]), target)
                if name in NATIVE and item["role"].startswith("native-") and not item["role"].endswith("-readme") and name != "windows-x64":
                    target.chmod(0o755)
        for name in ("scripts/refactor-candidate-producer.py", ".github/workflows/v15-candidate-build.yml", "config/candidate-producer.json", "packaging/candidate/windows.iss", "packaging/candidate/android.init.gradle", "packaging/candidate/Dockerfile"):
            copy_fixed(ROOT / name, materials / "build-sources" / name)
        zip_tree(materials, files / "NestLink-candidate-materials.zip", value["source_epoch"])
    artifacts.append(record(args.output, files / "NestLink-candidate-materials.zip", "materials", value["source_revision"]))
    cases = [{"id": name, "status": "pending", "evidence_artifact_id": "acceptance"} for name in sorted(REQUIRED_CASES)]
    with tempfile.TemporaryDirectory(prefix="candidate-acceptance-") as scratch:
        evidence = Path(scratch)
        write_json(evidence / "user-acceptance.json", {"source_revision": value["source_revision"], "status": "pending", "signing": SIGNING, "cases": cases})
        (evidence / "README.candidate.txt").write_text(candidate_readme(value), encoding="utf-8")
        for path in (ROOT / "docs/refactor").glob("current-verification-*.json"):
            copy_fixed(path, evidence / "prior-development-evidence" / path.name)
        for name, part in parts.items():
            copy_fixed(args.bundle / "parts" / (name + ".json"), evidence / "candidate-build-checks" / (name + ".json"))
            for item in part["evidence"]:
                if item["path"].endswith(".json"):
                    copy_fixed(verify_record(args.bundle, item, value["source_revision"]), evidence / "candidate-build-checks" / item["path"])
        if args.acceptance_evidence:
            for path in TOOLS.tree_files(args.acceptance_evidence):
                copy_fixed(path, evidence / "executed-development-checks" / path.relative_to(args.acceptance_evidence))
        zip_tree(evidence, files / "NestLink-candidate-development-evidence.zip", value["source_epoch"])
    artifacts.append(record(args.output, files / "NestLink-candidate-development-evidence.zip", "acceptance", value["source_revision"]))
    require(len(artifacts) == len(CURRENT_ROLES) and {item["role"] for item in artifacts} == CURRENT_ROLES,
            "Cannot freeze a candidate with a missing platform, ABI or deliverable")
    require(len({item["path"].casefold() for item in artifacts}) == len(artifacts), "Candidate filenames collide")
    for item in artifacts:
        verify_record(args.output, item, value["source_revision"])
    write_json(args.output / "candidate-build-manifest.json", {"schema_version": 1, "kind": "nestlink-development-candidate-build", "product": "NestLink", "repository": value["repository"], "repository_node_id": value["repository_node_id"], "source_revision": value["source_revision"], "cohort_sha256": digest(args.cohort), "version": value["version"], "signing": SIGNING, "production_update_eligible": False, "user_full_functional_acceptance": "pending", "acceptance_cases": cases, "artifacts": sorted(artifacts, key=lambda item: item["role"])})
    cohort(args.cohort)
    print(json.dumps({"candidate": "frozen-development-only", "version": value["version"], "source_revision": value["source_revision"], "roles": len(artifacts), "final_user_acceptance": "pending", "publication": "new-repository-prerelease-only"}))


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="action", required=True)
    first = commands.add_parser("preflight")
    first.add_argument("--source", required=True)
    first.add_argument("--sequence", type=int, required=True)
    first.add_argument("--run-id", type=int, required=True)
    first.add_argument("--run-attempt", type=int, required=True)
    first.add_argument("--oci-base", required=True)
    first.add_argument("--oci-index", type=Path, required=True)
    first.add_argument("--output", type=Path, required=True)
    for name in ("collect-native", "collect-android", "collect-web", "metadata", "oci-context", "collect-oci", "freeze"):
        command = commands.add_parser(name)
        command.add_argument("--cohort", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        if name in ("collect-native", "collect-android", "collect-web", "collect-oci"):
            command.add_argument("--input", type=Path, required=True)
        if name in ("oci-context", "collect-oci", "freeze"):
            command.add_argument("--bundle", type=Path, required=True)
        if name == "collect-native":
            command.add_argument("--target", choices=NATIVE, required=True)
            command.add_argument("--codec-prefix", type=Path, required=True)
            command.add_argument("--iscc", default="ISCC.exe")
        if name in ("oci-context", "collect-oci"):
            command.add_argument("--target", choices=("linux-x64", "linux-arm64"), required=True)
        if name == "collect-android":
            command.add_argument("--codec-arm64", type=Path, required=True)
            command.add_argument("--codec-x64", type=Path, required=True)
            command.add_argument("--apksigner", required=True)
            command.add_argument("--aapt2", required=True)
            command.add_argument("--zipalign", required=True)
            command.add_argument("--java", default="java")
        if name == "freeze":
            command.add_argument("--acceptance-evidence", type=Path)
    return result


def main():
    args = parser().parse_args()
    try:
        globals()[args.action.replace("-", "_")](args)
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as error:
        print("Candidate production failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
