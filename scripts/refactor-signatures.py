"""Verify fixed v15 signed package bytes and public certificate identities.

Read-only verification: no signing, key import, password, upload or repository
operation. Copy config/release-signatures.template.json to an artifacts plan
after fixing the source commit, final package hashes and public identities.
This check is one part of product acceptance, not its replacement.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys
from datetime import datetime, timezone


class Blocked(Exception):
    pass


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fixed_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def artifact_path(root, value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise ValueError("artifact path must be a relative POSIX path")
    relative = Path(value)
    if relative.is_absolute() or PureWindowsPath(value).drive or ".." in relative.parts:
        raise ValueError("artifact path escapes the workspace")
    resolved = (root / relative).resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError("artifact link escapes the workspace")
    return resolved


def run(command, *, env=None):
    try:
        result = subprocess.run(command, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=30, check=False)
    except (FileNotFoundError, PermissionError) as error:
        raise Blocked("verification tool unavailable") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError("verification tool exceeded 30 seconds") from error
    # Tool output is diagnostic data. Commands and arguments never come from it.
    stdout = result.stdout.decode("utf-8-sig", errors="replace")
    if len(result.stdout) + len(result.stderr) > 256 * 1024:
        raise ValueError("verification output exceeds budget")
    return result.returncode, stdout


WINDOWS_CHECK = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
# Load only modules shipped with this shell. An inherited PowerShell 7 module
# path otherwise breaks Windows PowerShell 5.1 autoloading (or shadows it).
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$item = Get-AuthenticodeSignature -LiteralPath $env:NESTLINK_VERIFY_FILE
function CertificateDigest($certificate) {
    if ($null -eq $certificate) { return $null }
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($digest.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $digest.Dispose() }
}
$result = [ordered]@{
    status = [string]$item.Status
    certificate_sha256 = CertificateDigest $item.SignerCertificate
    timestamp_certificate_sha256 = CertificateDigest $item.TimeStamperCertificate
    code_signing_eku = $false
}
if ($null -ne $item.SignerCertificate) {
    foreach ($extension in $item.SignerCertificate.Extensions) {
        if ($extension.Oid.Value -eq '2.5.29.37') {
            $usage = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($extension, $extension.Critical)
            $result.code_signing_eku = @($usage.EnhancedKeyUsages | Where-Object { $_.Value -eq '1.3.6.1.5.5.7.3.3' }).Count -gt 0
        }
    }
}
$result | ConvertTo-Json -Compress
"""


def windows_signature(path, expected, powershell):
    if sys.platform != "win32":
        raise Blocked("Authenticode verification requires Windows")
    env = dict(os.environ, NESTLINK_VERIFY_FILE=str(path))
    code, output = run([powershell, "-NoProfile", "-NonInteractive", "-Command", WINDOWS_CHECK], env=env)
    if code:
        raise ValueError("Authenticode verifier failed")
    result = json.loads(output)
    if result.get("status") != "Valid" or result.get("certificate_sha256") != expected:
        raise ValueError("Authenticode trust or fixed signer mismatch")
    if not result.get("code_signing_eku") or not fixed_digest(result.get("timestamp_certificate_sha256")):
        raise ValueError("code-signing EKU or trusted timestamp missing")
    return result




def verify_source(root, revision):
    code, current = run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"])
    if code or current.strip() != revision:
        raise ValueError("fixed source revision differs from the checked-out commit")
    code, status = run(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=no"])
    if code or status.strip():
        raise ValueError("tracked source tree is dirty or cannot be checked")


def check_plan(plan, root, tools):
    if not isinstance(plan, dict) or plan.get("schema_version") != 1 or plan.get("release_version") != "15.0.0":
        raise ValueError("unsupported release signature plan")
    artifacts = plan.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 64:
        raise ValueError("plan must contain 1–64 final artifacts")
    if any(not isinstance(item, dict) for item in artifacts):
        raise ValueError("invalid artifact entry")
    paths = [artifact_path(root, item.get("path")) for item in artifacts]
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate final artifact")
    identities = plan.get("identities")
    if not isinstance(identities, dict):
        raise ValueError("missing public identity declarations")
    revision = plan.get("source_revision")
    revision_fixed = isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) is not None
    checks = []
    for item, path in zip(artifacts, paths):
        check = {"path": item["path"], "platform": item.get("platform"), "status": "blocked"}
        try:
            platform = item.get("platform")
            if platform != "windows":
                raise ValueError("unsupported signing platform")
            if not revision_fixed or not fixed_digest(item.get("sha256")):
                raise Blocked("source revision and final artifact hash are not fixed")
            verify_source(root, revision)
            expected = identities.get(platform + "_certificate_sha256")
            if not fixed_digest(expected):
                raise Blocked("public signing certificate identity not configured")
            if not path.is_file():
                raise Blocked("final signed artifact not available")
            before = sha256(path)
            check["actual_sha256"] = before
            if before != item["sha256"]:
                raise ValueError("final artifact hash mismatch")
            if path.suffix.lower() not in (".exe", ".msi", ".msix"):
                raise ValueError("unsupported Windows package extension")
            identity = windows_signature(path, expected, tools["powershell"])
            if sha256(path) != before:
                raise ValueError("artifact changed during signature verification")
            check.update(status="passed", identity=identity)
        except Blocked as error:
            check["reason"] = str(error)
        except (ValueError, OSError) as error:
            check.update(status="failed", reason=str(error))
        checks.append(check)
    return {"schema_version": 1, "scope": "fixed package signatures only; not full product acceptance",
            "product_acceptance": False, "source_revision": revision,
            "checked_at": datetime.now(timezone.utc).isoformat(), "checks": checks,
            "all_checks_passed": all(c["status"] == "passed" for c in checks)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=Path("config/release-signatures.template.json"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/signature-verification.json"))
    parser.add_argument("--powershell", default="powershell.exe")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        plan_file = root / args.plan
        data = plan_file.read_bytes()
        if len(data) > 256 * 1024:
            raise ValueError("signature plan exceeds budget")
        report = check_plan(json.loads(data), root, vars(args))
        report["plan_sha256"] = hashlib.sha256(data).hexdigest()
        output = root / args.output
        if output.resolve() in {plan_file.resolve(), *(artifact_path(root, c["path"]) for c in report["checks"])}:
            raise ValueError("report must not overwrite plan or package")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        for check in report["checks"]:
            print(str(check["platform"]) + ": " + check["status"] + (" — " + check["reason"] if "reason" in check else ""))
        return 0 if report["all_checks_passed"] else (1 if any(c["status"] == "failed" for c in report["checks"]) else 2)
    except (ValueError, OSError) as error:
        print("invalid signature plan: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
