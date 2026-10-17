#!/usr/bin/env python3
"""Freeze payload/package manifests and build signed-input native installers.

Builds consume a final, clean source commit and an independently CMS-signed
payload manifest. They never sign with a generated development identity.
The resulting final packages need a second signed native-packages manifest
and installation acceptance of those exact final bytes before publication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging/native"))
import release_verify as verify


def source_matches(manifest):
    revision = verify.command(["git", "-C", ROOT, "rev-parse", "HEAD"]).decode().strip()
    status = verify.command(["git", "-C", ROOT, "status", "--porcelain", "--untracked-files=all"])
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    if revision != manifest["source_revision"] or status.strip() or cargo["workspace"]["package"]["version"] != manifest["version"]:
        raise ValueError("packaging requires the exact clean final source commit and final Cargo version")


def freeze(args):
    plan = verify.bounded_json(args.plan)
    for item in plan.get("artifacts", []):
        path = verify.artifact_path(args.bundle, item.get("path"))
        item["bytes"], item["sha256"] = path.stat().st_size, verify.sha256(path)
    verify.validate_manifest(plan)
    source_matches(plan)
    with args.output.open("xb") as stream:
        stream.write(json.dumps(plan, sort_keys=True, indent=2).encode("utf-8") + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def payload(args):
    data = verify.verify_bundle(args.bundle, args.manifest, args.signature, args.certificate, args.certificate_sha256, openssl=args.openssl)
    if data["purpose"] != "native-payload":
        raise ValueError("build requires a signed native-payload manifest")
    source_matches(data)
    return data


def executable_items(data, platform_name, architecture, role):
    roles = {"server": ("server",), "desktop": ("desktop", "daemon"), "privileged": ("desktop", "daemon", "privileged")}.get(role)
    if roles is None or (role == "privileged" and (platform_name, architecture) != ("windows", "x86_64")):
        raise ValueError("unsupported native installation role")
    required = {"nestlink-" + value for value in roles}
    if platform_name == "windows":
        required = {name + ".exe" for name in required}
    chosen = [item for item in data["artifacts"] if item["platform"] == platform_name and item["architecture"] == architecture and item["format"] == "executable" and item["role"] in roles]
    if {Path(item["path"]).name for item in chosen} != required or len(chosen) != len(required) or len({item["state_compatibility"] for item in chosen}) != 1:
        raise ValueError("exact native executable set/state compatibility is missing or duplicated")
    if any(Path(item["path"]).name != "nestlink-" + item["role"] + (".exe" if platform_name == "windows" else "") for item in chosen):
        raise ValueError("executable basename differs from its signed role")
    return chosen


def broker_policy(data, chosen, payload_hash, update_pin):
    """Derive only fixed public facts from the already authenticated payload."""
    verify.validate_manifest(data)
    verify.fixed_hash(payload_hash)
    verify.fixed_hash(update_pin)
    if chosen != executable_items(data, "windows", "x86_64", "privileged"):
        raise ValueError("broker policy requires the complete protected Windows cohort")
    pins = {item["windows_certificate_sha256"] for item in chosen}
    if len(pins) != 1 or update_pin in pins:
        raise ValueError("broker policy requires distinct fixed update and Windows signers")
    by_role = {item["role"]: item for item in chosen}
    return {"schema_version": 1, "version": data["version"], "release_sequence": data["release_sequence"],
            "source_revision": data["source_revision"], "payload_manifest_sha256": payload_hash,
            "update_certificate_sha256": update_pin, "windows_certificate_sha256": next(iter(pins)),
            **{role + "_sha256": by_role[role]["sha256"] for role in ("desktop", "daemon", "privileged")}}


def copy_file(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
    destination.chmod(mode)


def elf_architecture(path, architecture):
    with path.open("rb") as stream:
        header = stream.read(64)
    if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != {"x86_64": 62, "aarch64": 183}[architecture]:
        raise ValueError("payload ELF architecture differs from signed manifest")


def build_deb(args):
    if sys.platform != "linux":
        raise ValueError("DEB build requires the Ubuntu packaging toolchain")
    if "\n" in args.maintainer or "\r" in args.maintainer or "<" not in args.maintainer or ">" not in args.maintainer:
        raise ValueError("supply the actual Debian maintainer Name <email>")
    data = payload(args)
    chosen = executable_items(data, "linux", args.architecture, args.role)
    package = "nestlink-v15-" + args.role
    deb_arch = {"x86_64": "amd64", "aarch64": "arm64"}[args.architecture]
    version = data["version"] + "-" + str(data["release_sequence"])
    if args.output.exists():
        raise ValueError("refusing to overwrite fixed package bytes")
    with tempfile.TemporaryDirectory(prefix="nestlink-v15-deb-", dir=args.output.parent) as scratch:
        stage = Path(scratch) / "root"
        directory = stage / "usr/lib/nestlink-v15" / args.role / "versions" / (data["version"] + "-r" + str(data["release_sequence"]))
        for item in chosen:
            source = verify.artifact_path(args.bundle, item["path"])
            elf_architecture(source, args.architecture)
            copy_file(source, directory / source.name, 0o755)
            if verify.sha256(directory / source.name) != item["sha256"]:
                raise ValueError("ELF changed while copying to the packaging owner")
        for source, name in ((args.manifest, "payload.json"), (args.signature, "payload.p7s"), (args.certificate, "update.crt")):
            copy_file(source, directory / name)
        tools = stage / "usr/lib/nestlink-v15-tools" / args.role
        for source in (ROOT / "packaging/linux/lifecycle.py", ROOT / "packaging/native/release_verify.py"):
            copy_file(source, tools / source.name, 0o755 if source.suffix == ".py" else 0o644)
        if args.role == "desktop":
            copy_file(ROOT / "packaging/systemd/nestlink-v15-daemon.service", stage / "usr/lib/systemd/user/nestlink-v15-daemon.service")
            copy_file(ROOT / "packaging/linux/nestlink-v15.desktop", stage / "usr/share/applications/nestlink-v15.desktop")
            copy_file(ROOT / "brand/icon.svg", stage / "usr/share/icons/hicolor/scalable/apps/nestlink-v15.svg")
            dependencies = "libc6 (>= 2.39), libgcc-s1, python3 (>= 3.12), openssl, libx11-6, libxrandr2, libxi6, libxfixes3, libxinerama1, libxcursor1, libxkbcommon0, libgl1, libegl1, libwayland-client0, libpipewire-0.3-0, libdbus-1-3, libasound2t64"
        else:
            copy_file(ROOT / "packaging/systemd/nestlink-v15-control.service", stage / "usr/lib/systemd/system/nestlink-v15-control.service")
            dependencies = "libc6 (>= 2.39), libgcc-s1, python3 (>= 3.12), openssl"
        for notice in sorted((ROOT / "packaging/notices").iterdir()):
            if notice.is_file():
                copy_file(notice, stage / "usr/share/doc" / package / "notices" / notice.name)
        copy_file(ROOT / "LICENSE", stage / "usr/share/doc" / package / "copyright")
        control = stage / "DEBIAN"
        control.mkdir()
        (control / "control").write_text(f"Package: {package}\nVersion: {version}\nSection: net\nPriority: optional\nArchitecture: {deb_arch}\nMaintainer: {args.maintainer}\nDepends: {dependencies}\nDescription: NestLink v15 isolated {args.role}\n Independent v15 namespace. Installation is activated only by its verified lifecycle owner.\n", encoding="utf-8")
        hook = (ROOT / "packaging/debian/maintainer-owner.py").read_text(encoding="utf-8")
        for phase in ("prerm", "postinst", "postrm"):
            # Inline the exact reviewed Python hook; no interpreter or shell
            # command is fetched or selected from manifest fields.
            body = hook.replace("    role, phase, action = sys.argv[1:4]", f"    role, phase, action = {args.role!r}, {phase!r}, sys.argv[1]")
            (control / phase).write_text(body, encoding="utf-8")
            (control / phase).chmod(0o755)
        verify.command([args.dpkg_deb, "--build", "--root-owner-group", stage, args.output], timeout=120)
    # The output is not signed here. Freeze it in native-packages, sign that
    # manifest with the independently enrolled update key, then accept bytes.
    print(json.dumps({"path": str(args.output), "bytes": args.output.stat().st_size, "sha256": verify.sha256(args.output), "source_revision": data["source_revision"], "acceptance": "not_run"}))


def build_windows(args):
    if sys.platform != "win32":
        raise ValueError("Authenticode/Inno packaging requires Windows")
    data = payload(args)
    role = args.role
    chosen = executable_items(data, "windows", "x86_64", role)
    pins = {item["windows_certificate_sha256"] for item in chosen}
    if len(pins) != 1 or args.certificate_sha256 in pins:
        raise ValueError("use one fixed Authenticode identity distinct from the update signing certificate")
    if args.output.exists():
        raise ValueError("refusing to overwrite fixed installer bytes")
    # Existing verifier checks system trust, fixed DER signer SHA256, code EKU
    # and timestamp for every input PE; Sigstore is not substituted for it.
    import importlib.util
    spec = importlib.util.spec_from_file_location("signature_acceptance", ROOT / "scripts/refactor-signatures.py")
    signing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signing)
    for item in chosen:
        signing.windows_signature(verify.artifact_path(args.bundle, item["path"]), item["windows_certificate_sha256"], args.powershell)
    with tempfile.TemporaryDirectory(prefix="nestlink-v15-inno-", dir=args.output.parent) as scratch:
        directory = Path(scratch)
        for item in chosen:
            source = verify.artifact_path(args.bundle, item["path"])
            copy_file(source, directory / source.name)
            if verify.sha256(directory / source.name) != item["sha256"]:
                raise ValueError("PE changed while copying to the packaging owner")
        for source, name in ((args.manifest, "payload.json"), (args.signature, "payload.p7s"), (args.certificate, "update.crt")):
            copy_file(source, directory / name)
        helper = "Manage-NestLinkPrivileged.ps1" if role == "privileged" else "Manage-NestLink.ps1"
        script = "nestlink-v15-privileged.iss" if role == "privileged" else "nestlink-v15.iss"
        copy_file(ROOT / "packaging/windows" / helper, directory / helper)
        if role == "privileged":
            with (directory / "broker-package.json").open("xb") as stream:
                stream.write(json.dumps(broker_policy(data, chosen, verify.sha256(args.manifest), args.certificate_sha256), sort_keys=True, indent=2).encode("utf-8") + b"\n")
        arguments = [args.iscc, "/Qp", "/DVersion=" + data["version"], "/DReleaseSequence=" + str(data["release_sequence"]),
                     "/DPayloadDir=" + str(directory), "/DUpdateCertificateSha256=" + args.certificate_sha256,
                     "/DWindowsCertificateSha256=" + next(iter(pins)), "/DPayloadManifestSha256=" + verify.sha256(args.manifest),
                     "/DMaintenanceHelperSha256=" + verify.sha256(directory / helper),
                     "/DOutputDir=" + str(args.output.parent.resolve()), "/DOutputBase=" + args.output.stem,
                     "/SNestLinkSigning=" + args.inno_sign_command, ROOT / "packaging/windows" / script]
        # Inno's required SignTool signs both final setup and uninstaller. The
        # signing command is user-supplied build configuration, never a shell
        # string from a downloaded manifest; it is intentionally never logged.
        verify.command(arguments, timeout=300)
        signed_uninstallers = []
        for candidate in (directory / "signed-uninstaller").rglob("*"):
            if candidate.is_file():
                with candidate.open("rb") as stream:
                    is_pe = stream.read(2) == b"MZ"
                if is_pe:
                    signing.windows_signature(candidate, next(iter(pins)), args.powershell)
                    signed_uninstallers.append(verify.sha256(candidate))
        if not signed_uninstallers:
            raise ValueError("Inno did not retain a verifiable signed uninstaller")
    signing.windows_signature(args.output, next(iter(pins)), args.powershell)
    print(json.dumps({"path": str(args.output), "bytes": args.output.stat().st_size, "sha256": verify.sha256(args.output), "source_revision": data["source_revision"], "acceptance": "not_run"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    frozen = sub.add_parser("freeze")
    frozen.add_argument("--plan", type=Path, required=True)
    frozen.add_argument("--bundle", type=Path, required=True)
    frozen.add_argument("--output", type=Path, required=True)
    for name in ("build-deb", "build-windows"):
        build = sub.add_parser(name)
        for field in ("bundle", "manifest", "signature", "certificate", "output"):
            build.add_argument("--" + field, type=Path, required=True)
        build.add_argument("--certificate-sha256", required=True)
        build.add_argument("--openssl", default="openssl")
        if name == "build-deb":
            build.add_argument("--architecture", choices=("x86_64", "aarch64"), required=True)
            build.add_argument("--role", choices=("desktop", "server"), required=True)
            build.add_argument("--dpkg-deb", default="dpkg-deb")
            build.add_argument("--maintainer", required=True)
        else:
            build.add_argument("--role", choices=("desktop", "privileged"), default="desktop")
            build.add_argument("--iscc", required=True)
            build.add_argument("--powershell", default="powershell.exe")
            build.add_argument("--inno-sign-command", required=True)
    args = parser.parse_args()
    {"freeze": freeze, "build-deb": build_deb, "build-windows": build_windows}[args.action](args)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("NestLink package preparation refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
