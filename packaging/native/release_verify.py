"""Fixed bytes and independently pinned CMS update signatures; stdlib only.

The public certificate is enrolled out of band. CMS `-noverify` deliberately
does not trust an arbitrary certificate chain: `-nointern` and the independently
pinned, single certificate force the signature to that exact update key.
Authenticode remains a separate Windows platform check.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

MAX_MANIFEST = 256 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
VERSION = re.compile(r"15\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
FORMATS = {"executable", "asset", "deb", "inno"}


def exact_keys(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ValueError("unknown or missing manifest fields")


def fixed_hash(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise ValueError("expected a fixed lowercase SHA-256")
    return value


def relative(value):
    if not isinstance(value, str) or not value or any(char in value for char in "\\\0:\r\n\t"):
        raise ValueError("artifact path must be a portable relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("artifact path escapes its fixed bundle")
    if any(part.endswith((".", " ")) or re.fullmatch(r"(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", part) for part in path.parts):
        raise ValueError("reserved Windows artifact path")
    return path


def regular(path: Path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
        raise ValueError("artifact must be a regular file, without a link/reparse point")
    return value


def artifact_path(root: Path, value):
    rel = relative(value)
    root = root.resolve(strict=True)
    current = root
    for index, part in enumerate(rel.parts):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("links/reparse points are forbidden inside the fixed bundle")
        if index < len(rel.parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise ValueError("artifact parent is not a directory")
    regular(current)
    return current


def sha256(path: Path):
    digest = hashlib.sha256()
    before = regular(path)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            raise ValueError("artifact identity changed before reading")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
    final = regular(path)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns):
        raise ValueError("artifact changed while hashing")
    return digest.hexdigest()


def bounded_json(path: Path):
    regular(path)
    with path.open("rb") as stream:
        data = stream.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise ValueError("manifest exceeds budget")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate manifest field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def validate_manifest(data):
    exact_keys(data, ("schema_version", "product", "purpose", "version", "release_sequence", "source_revision", "artifacts"))
    if data["schema_version"] != 1 or data["product"] != "NestLink-v15" or data["purpose"] not in ("native-payload", "native-packages"):
        raise ValueError("unsupported v15 manifest purpose/namespace")
    if not isinstance(data["version"], str) or not VERSION.fullmatch(data["version"]):
        raise ValueError("expected a final v15 semantic version")
    if type(data["release_sequence"]) is not int or not 1 <= data["release_sequence"] <= 2**53 - 1 or not isinstance(data["source_revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", data["source_revision"]):
        raise ValueError("release sequence/source commit not fixed")
    artifacts = data["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 128:
        raise ValueError("manifest must contain 1-128 artifacts")
    seen = set()
    ids = set()
    for item in artifacts:
        exact_keys(item, ("id", "platform", "architecture", "role", "format", "path", "bytes", "sha256", "state_compatibility"), ("windows_certificate_sha256", "payload_manifest_sha256"))
        if not isinstance(item["id"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", item["id"]) or item["id"] in ids:
            raise ValueError("invalid/duplicate artifact id")
        ids.add(item["id"])
        relative(item["path"])
        folded = item["path"].casefold()
        if folded in seen:
            raise ValueError("duplicate/case-colliding artifact path")
        seen.add(folded)
        if item["platform"] not in ("windows", "linux") or item["architecture"] not in ("x86_64", "aarch64") or item["role"] not in ("desktop", "daemon", "server", "privileged") or item["format"] not in FORMATS:
            raise ValueError("unsupported native artifact target")
        if item["platform"] == "windows" and item["architecture"] != "x86_64":
            raise ValueError("Windows release supports x64 only")
        if item["role"] == "privileged" and (item["platform"] != "windows" or item["architecture"] != "x86_64" or item["format"] != ("executable" if data["purpose"] == "native-payload" else "inno")):
            raise ValueError("privileged input is an optional Windows x64 executable/installer only")
        if (data["purpose"] == "native-payload") != (item["format"] in ("executable", "asset")):
            raise ValueError("payload and final package manifests are separate signed statements")
        if type(item["bytes"]) is not int or not 1 <= item["bytes"] <= 8 * 1024**3:
            raise ValueError("invalid artifact size")
        fixed_hash(item["sha256"])
        if not isinstance(item["state_compatibility"], str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", item["state_compatibility"]):
            raise ValueError("state compatibility must be explicit")
        if item["platform"] == "windows":
            fixed_hash(item.get("windows_certificate_sha256"))
        if data["purpose"] == "native-packages":
            fixed_hash(item.get("payload_manifest_sha256"))
    return data


def command(args, *, timeout=60):
    result = subprocess.run([str(arg) for arg in args], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if len(result.stdout) + len(result.stderr) > 2 * 1024 * 1024:
        raise ValueError("verification tool output exceeds budget")
    if result.returncode:
        raise ValueError("verification/build tool failed: " + str(args[0]))
    return result.stdout


def verify_cms(manifest: Path, signature: Path, certificate: Path, expected: str, *, openssl="openssl"):
    fixed_hash(expected)
    regular(manifest)
    regular(signature)
    regular(certificate)
    pem = certificate.read_bytes()
    if not 1 <= len(pem) <= 32 * 1024 or pem.count(b"-----BEGIN CERTIFICATE-----") != 1 or pem.count(b"-----END CERTIFICATE-----") != 1 or b"PRIVATE KEY" in pem:
        raise ValueError("supply exactly one public update signing certificate")
    der = command([openssl, "x509", "-in", certificate, "-outform", "DER"])
    if hashlib.sha256(der).hexdigest() != expected:
        raise ValueError("update certificate differs from the independently enrolled pin")
    before = sha256(manifest), sha256(signature), sha256(certificate)
    command([openssl, "cms", "-verify", "-binary", "-inform", "DER", "-in", signature,
             "-content", manifest, "-certfile", certificate, "-nointern", "-noverify", "-out", os.devnull])
    if before != (sha256(manifest), sha256(signature), sha256(certificate)):
        raise ValueError("signed input changed during verification")


def verify_bundle(root, manifest, signature, certificate, certificate_sha256, *, openssl="openssl"):
    verify_cms(manifest, signature, certificate, certificate_sha256, openssl=openssl)
    data = validate_manifest(bounded_json(manifest))
    for item in data["artifacts"]:
        path = artifact_path(root, item["path"])
        if regular(path).st_size != item["bytes"] or sha256(path) != item["sha256"]:
            raise ValueError("fixed artifact size/hash mismatch: " + item["id"])
    return data


def verify_selected(root, manifest, signature, certificate, certificate_sha256, artifact_id, *, openssl="openssl"):
    verify_cms(manifest, signature, certificate, certificate_sha256, openssl=openssl)
    data = validate_manifest(bounded_json(manifest))
    selected = [item for item in data["artifacts"] if item["id"] == artifact_id]
    if len(selected) != 1:
        raise ValueError("fixed artifact id is absent")
    item = selected[0]
    path = artifact_path(root, item["path"])
    if regular(path).st_size != item["bytes"] or sha256(path) != item["sha256"]:
        raise ValueError("fixed artifact size/hash mismatch")
    return data, item, path
