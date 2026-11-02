#!/usr/bin/env python3
"""Fetch the original disposable public-PKI fixture on hosted Actions only.

Reuse the cloudflared 2026.10.7 Windows TUN acceptance pin. The Linux digest is
from that same official GitHub release's asset digest, not a floating package.
This executable is a test fixture and is never bundled with NestLink.
"""
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import urllib.request
import uuid


TAG = "2026.10.7"
COMMIT = "872b241f94871665c1c157adefcf90c11f0ead96"
ASSETS = {
    "Linux": ("cloudflared-linux-amd64", "1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872"),
    "Windows": ("cloudflared-windows-amd64.exe", "2493dbc168923bb3e59e5e7716f71deced92992eea9acd6e9d74f84ac7751343"),
}
LICENSE_SHA256 = "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd"


def fetch(url, target, expected):
    request = urllib.request.Request(url, headers={"User-Agent": "NestLink-hosted-acceptance"})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit(f"Frozen HTTPS fixture digest mismatch: {target.name}")
    target.write_bytes(data)


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise SystemExit("R02: fixture tool installation requires a GitHub-hosted Actions runner")
    name, digest = ASSETS[os.environ["RUNNER_OS"]]
    directory = pathlib.Path(os.environ["RUNNER_TEMP"]) / f"nestlink-offline-https-tool-{uuid.uuid4().hex}"
    if os.name == "nt":
        # Reuse the original Windows acceptance tool directory ACL. Python's
        # 0700 directory can otherwise retain only the elevated runner's
        # default owner, which the actual filtered child cannot execute from.
        from network_rewrite_wfp_native import Native
        Native().directory(directory, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)")
    else:
        directory.mkdir(mode=0o700)
    tool = directory / name
    url = f"https://github.com/cloudflare/cloudflared/releases/download/{TAG}/{name}"
    fetch(url, tool, digest)
    license_url = f"https://raw.githubusercontent.com/cloudflare/cloudflared/{COMMIT}/LICENSE"
    license_path = pathlib.Path(os.environ["RUNNER_TEMP"]) / "nestlink-native-offline-https-license.txt"
    fetch(license_url, license_path, LICENSE_SHA256)
    if os.name == "nt":
        # Reuse the original acceptance fixture's administrator-owned image;
        # its child still runs under the actual ordinary Windows test token.
        subprocess.run(["icacls.exe", str(tool), "/setowner", "*S-1-5-32-544"], check=True)
    else:
        tool.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    receipt = {
        "schema_version": 1,
        "source_revision": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "runner": os.environ["RUNNER_OS"],
        "tag": TAG,
        "commit": COMMIT,
        "url": url,
        "executable_sha256": digest,
        "license": "Apache-2.0",
        "license_url": license_url,
        "license_sha256": LICENSE_SHA256,
        "test_fixture_only": True,
        "tls_boundary": "Public PKI TLS terminates at Cloudflare; disposable original management HTTP upstream is loopback-only. This is not end-to-end peer encryption.",
    }
    receipt_path = pathlib.Path(os.environ["RUNNER_TEMP"]) / "nestlink-native-offline-https-tool.json"
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    with pathlib.Path(os.environ["GITHUB_ENV"]).open("a", encoding="utf-8") as environment:
        environment.write(f"NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED={tool}\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
