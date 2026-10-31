#!/usr/bin/env python3
"""Qualify the real ordinary/admin Wintun mechanism on its hosted Actions VM.

All builds, driver acquisition and native execution occur here on GitHub-hosted
Windows. These are exact-source mechanism receipts, not production online or
two-device target acceptance. Failed native capabilities remain failures.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import uuid
import zipfile

from network_rewrite_wfp_native import Native, checked

DRIVER_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
ARCHIVE_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
ROLE = "network_tun_system::windows::native_tests::hosted_native_role"
ROLE_ARGS = ["--ignored", "--exact", ROLE, "--nocapture", "--test-threads=1", "--color=never"]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    env = dict(os.environ)
    if (sys.platform != "win32" or env.get("GITHUB_ACTIONS") != "true"
        or env.get("RUNNER_ENVIRONMENT") != "github-hosted" or env.get("RUNNER_OS") != "Windows"
        or env.get("RUNNER_ARCH") != "X64" or env.get("NESTLINK_TUN_NATIVE_LAB") != "1"
        or env.get("GITHUB_REPOSITORY") != "ZHanry/NestLink"
        or not env.get("GITHUB_WORKFLOW_REF", "").startswith("ZHanry/NestLink/.github/workflows/windows-managed-tun.yml@refs/")
        or re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is None):
        raise ValueError("R02: this experiment requires its dedicated GitHub-hosted x64 Windows workflow")
    if not c.windll.shell32.IsUserAnAdmin():
        raise ValueError("the fixture coordinator must start with the hosted administrator token")
    source, temp, output = Path.cwd().resolve(), Path(env["RUNNER_TEMP"]).resolve(), args.output.resolve()
    if not args.output.is_absolute() or output == temp or not output.is_relative_to(temp) or output.exists():
        raise ValueError("fresh evidence directory beneath RUNNER_TEMP required")
    output.mkdir()
    result = {"schema_version": 1, "kind": "windows-managed-tun-hosted-mechanism", "status": "failed",
              "evidence_level": "L2_hosted_kernel", "production_online_validated": False,
              "two_target_acceptance": False, "commands": [], "cases": {},
              "build_provenance": {"source_revision": env["GITHUB_SHA"], "dependency_lock_sha256": digest(source / "Cargo.lock"),
                  "workflow_ref": env["GITHUB_WORKFLOW_REF"], "workflow_revision": env["GITHUB_WORKFLOW_SHA"],
                  "run_id": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "job": env["GITHUB_JOB"],
                  "runner_environment": env["RUNNER_ENVIRONMENT"], "image_os": env.get("IMAGEOS"), "image_version": env.get("IMAGEVERSION")},
              "execution_provenance": {"environment": "disposable_github_hosted_windows_vm", "source_revision": env["GITHUB_SHA"],
                  "started_at_unix": time.time(), "run_id": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"]}}
    native, active, retained = Native(), [], []
    fixture = Path(env["PROGRAMFILES"]) / ("NestLink-TUN-Lab-" + uuid.uuid4().hex)
    protected_acl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

    def execute(name, argv, *, extra=None, timeout=30, required=True):
        entry = {"name": name, "argv": [str(v) for v in argv], "log": name + ".log", "started_at_unix": time.time()}
        result["commands"].append(entry)
        with (output / entry["log"]).open("wb") as stream:
            completed = subprocess.run(entry["argv"], stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT,
                                       env=dict(env, **(extra or {})), creationflags=0x08000000, timeout=timeout, check=False)
        entry.update(return_code=completed.returncode, log_sha256=digest(output / entry["log"]), finished_at_unix=time.time())
        text = (output / entry["log"]).read_text(encoding="utf-8", errors="replace")
        if required and completed.returncode:
            raise RuntimeError(f"{name} failed; see its exact retained log")
        return completed.returncode, text

    def ps(name, code):
        # The workflow shell is PowerShell 7. Its inherited module search path
        # must not be used by the separately selected system Windows PS 5.1.
        # Keep Authenticode checking on the real inbox security implementation.
        system_ps = Path(env["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0"
        return execute(name, [system_ps / "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                              "$ErrorActionPreference='Stop'; " + code],
                       extra={"PSModulePath": str(system_ps / "Modules")})[1].lstrip("\ufeff").strip()

    def start(name, argv, extra):
        log = (output / (name + ".log")).open("wb")
        process = subprocess.Popen([str(v) for v in argv], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   env=dict(env, **extra), creationflags=0x08000000)
        active.append((process, log))
        result["commands"].append({"name": name, "argv": [str(v) for v in argv], "pid": process.pid, "log": Path(log.name).name})
        return process

    def await_json(path, process=None, budget=20):
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                if process is not None and process.poll() is not None:
                    raise RuntimeError(f"native actor exited before {path.name}")
                time.sleep(0.025)
        raise TimeoutError(f"bounded cooperation receipt wait expired: {path.name}")

    def owner_handle(identity):
        native.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        native.kernel.OpenProcess.restype = w.HANDLE
        native.kernel.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
        native.kernel.GetProcessTimes.restype = w.BOOL
        handle = native.kernel.OpenProcess(0x101001, False, identity["pid"])
        checked(handle)
        created, exited, kernel, user = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
        checked(native.kernel.GetProcessTimes(handle, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)))
        if created.dwLowDateTime | created.dwHighDateTime << 32 != identity["creation"]:
            native.kernel.CloseHandle(handle)
            raise ValueError("original medium owner PID was reused")
        retained.append(handle)
        return handle

    try:
        if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != env["GITHUB_SHA"] or subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"]):
            raise ValueError("exact clean source SHA required before building")
        execute("actual-medium-token", [sys.executable, source / "scripts/refactor-windows-normal-user.py", "--check"])
        archive = output / "wintun-0.14.1.zip"
        with urllib.request.urlopen(DRIVER_URL, timeout=60) as response, archive.open("xb") as stream:
            shutil.copyfileobj(response, stream)
        if digest(archive) != ARCHIVE_SHA256:
            raise ValueError("official Wintun archive differs from the frozen published SHA256")
        native.directory(fixture, protected_acl)
        binaries = {}
        with zipfile.ZipFile(archive) as package:
            (output / "wintun-license.txt").write_bytes(package.read("wintun/LICENSE.txt"))
            for architecture in ("amd64", "arm", "arm64", "x86"):
                dll = package.read(f"wintun/bin/{architecture}/wintun.dll")
                binaries[architecture] = hashlib.sha256(dll).hexdigest()
                if architecture == "amd64":
                    (fixture / "wintun.dll").write_bytes(dll)
            write(output / "wintun-archive-files.json", package.namelist())
        execute("driver-protected-owner", ["icacls.exe", fixture / "wintun.dll", "/setowner", "*S-1-5-32-544"])
        signature = json.loads(ps("official-driver-authenticode", f"$s=Get-AuthenticodeSignature -LiteralPath '{fixture / 'wintun.dll'}'; @{{Status=$s.Status.ToString();Subject=$s.SignerCertificate.Subject;Thumbprint=$s.SignerCertificate.Thumbprint}} | ConvertTo-Json -Compress"))
        if signature["Status"] != "Valid" or "WireGuard LLC" not in signature["Subject"]:
            raise ValueError("official architecture driver Authenticode validation failed")
        result["build_provenance"]["wintun"] = {"url": DRIVER_URL, "archive_sha256": digest(archive), "architecture_sha256": binaries,
              "binary_license": "wintun-license.txt", "license_sha256": digest(output / "wintun-license.txt"), "authenticode": signature}
        _, build = execute("build-same-daemon-image", ["cargo", "test", "--locked", "-p", "nestlink-daemon", "--bin", "nestlink-daemon", "--no-run", "--message-format=json"], timeout=2400)
        artifacts = []
        for line in build.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "nestlink-daemon" and item.get("profile", {}).get("test") and item.get("executable"):
                artifacts.append(Path(item["executable"]).resolve())
        if len(artifacts) != 1 or not artifacts[0].is_relative_to(source / "target"):
            raise ValueError("expected one exact-source daemon native fixture executable")
        executable = fixture / "nestlink-daemon-native.exe"
        shutil.copyfile(artifacts[0], executable)
        execute("image-protected-owner", ["icacls.exe", executable, "/setowner", "*S-1-5-32-544"])
        if digest(executable) != digest(artifacts[0]):
            raise ValueError("protected fixture differs from the Actions-built executable")
        result["build_provenance"]["executable"] = {"build_path": str(artifacts[0]), "execution_path": str(executable), "sha256": digest(executable)}
        runner_sid = ps("runner-sid", "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
        provider_case = output / "provider-negative"
        native.directory(provider_case, f"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{runner_sid})")
        unreviewed = fixture / "unreviewed-provider"
        native.directory(unreviewed, protected_acl)
        (unreviewed / "wintun.dll").write_bytes(b"NestLink native provider rejection fixture; never executable.\n")
        execute("unreviewed-provider-protected-owner", ["icacls.exe", unreviewed / "wintun.dll", "/setowner", "*S-1-5-32-544"])
        execute("native-provider-rejections", [executable, *ROLE_ARGS], extra={
            "NESTLINK_TUN_NATIVE_ROLE": "provider-negative", "NESTLINK_TUN_NATIVE_CASE": str(provider_case),
            "NESTLINK_TUN_NATIVE_RECEIPT": str(fixture / "unused-provider-negative-receipt.json"),
            "NESTLINK_TUN_NATIVE_DRIVER": str(fixture / "wintun.dll"),
            "NESTLINK_TUN_NATIVE_DRIVER_SHA256": binaries["amd64"],
            "NESTLINK_TUN_NATIVE_UNSIGNED": str(unreviewed / "wintun.dll")})
        provider_negative = await_json(provider_case / "provider-negative.json")
        if (provider_negative["rejected"] != ["wrong_digest", "other_architecture", "unreviewed_matching_digest", "ordinary_writable_path"]
            or not provider_negative["official_bytes_unchanged"] or not provider_negative["pinned_image_write_denied"]
            or bytes(provider_negative["official_sha256"]).hex() != binaries["amd64"]
            or digest(fixture / "wintun.dll") != binaries["amd64"]):
            raise ValueError("production provider trust checks did not reject unreviewed or mutable inputs")
        result["cases"]["provider-negative"] = {"status": "passed", "receipt": provider_negative}
        for scenario in ("normal", "crash", "raw-peer"):
            case = output / scenario
            native.directory(case, f"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{runner_sid})")
            root = fixture / scenario
            native.directory(root, protected_acl)
            extra = {"NESTLINK_TUN_NATIVE_CASE": str(case), "NESTLINK_TUN_NATIVE_RECEIPT": str(root / "receipt.json"),
                     "NESTLINK_TUN_NATIVE_JOURNAL": str(root / "journal"), "NESTLINK_TUN_NATIVE_DRIVER": str(fixture / "wintun.dll"),
                     "NESTLINK_TUN_NATIVE_DRIVER_SHA256": binaries["amd64"], "TEMP": str(case), "TMP": str(case),
                     "NESTLINK_TUN_NATIVE_PAUSE": "1" if scenario == "raw-peer" else "0"}
            ordinary = start(scenario + "-ordinary", [sys.executable, source / "scripts/refactor-windows-normal-user.py", executable, *ROLE_ARGS], dict(extra, NESTLINK_TUN_NATIVE_ROLE="ordinary"))
            ready = await_json(case / "plan-ready.json", ordinary)
            identity = ready["identity"]
            if identity["elevated"] or not 0x2000 <= identity["integrity"] < 0x3000 or identity["sid"] != runner_sid or identity["session"] <= 0:
                raise ValueError("ordinary actor was not the original medium non-admin user")
            handle = owner_handle(identity)
            helper = start(scenario + "-administrator", [executable, *ROLE_ARGS], dict(extra, NESTLINK_TUN_NATIVE_ROLE="apply"))
            if scenario == "raw-peer":
                published = await_json(root / "receipt.json", helper)
                if (published["binding"]["process"] != identity or published["helper"]["pid"] != helper.pid
                    or not published["helper"]["elevated"] or published["helper"]["integrity"] != 0x3000):
                    raise ValueError("raw-client negative lacks the original medium/high OS binding")
                execute("raw-same-sid-pipe-client", [sys.executable, source / "scripts/refactor-windows-normal-user.py", executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="raw-foreign"))
                denied = await_json(case / "raw-foreign-denied.json")
                helper.wait(timeout=10)
                helper_log = (output / (scenario + "-administrator.log")).read_text(encoding="utf-8", errors="replace")
                if (helper.returncode == 0 or "TUN packet pipe client is not the original admitted ordinary process" not in helper_log
                    or not denied["denied"] or denied["identity"]["elevated"] or not 0x2000 <= denied["identity"]["integrity"] < 0x3000
                    or denied["identity"]["sid"] != identity["sid"] or denied["identity"]["pid"] == identity["pid"]
                    or denied["original_pid"] != identity["pid"] or denied["helper_pid"] != helper.pid):
                    raise ValueError("actual raw same-SID OS client was not rejected before packet admission")
                code, log = execute("raw-peer-live-owner-recovery-denied", [executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="recover"), required=False)
                # The helper already confirmed physical cleanup and may have
                # cleared its exact record. If no record remains, recovery is
                # a no-op; it must never introduce a replacement adapter.
                if code and "original ordinary owner is still alive" not in log:
                    raise ValueError("unexpected raw-peer recovery failure")
                checked(native.kernel.TerminateProcess(handle, 73)); checked(native.kernel.WaitForSingleObject(handle, 5000) == 0)
                ordinary.wait(timeout=10)
                execute("raw-peer-dead-owner-recovery", [executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="recover"))
                execute("raw-peer-final-inspection", [executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="inspect"))
                inspection = await_json(case / "inspection.json")
                if inspection["record"] is not None or inspection["current"] is not None or (root / "receipt.json").exists():
                    raise ValueError("raw-peer negative did not close and recover its exact original adapter")
                result["cases"][scenario] = {"status": "passed", "plan": ready, "receipt": published, "raw_foreign": denied, "inspection": inspection}
                continue
            packets = await_json(case / "packets-ready.json", ordinary)
            receipt = packets["receipt"]
            if (receipt["binding"]["process"] != identity or receipt["helper"]["pid"] != helper.pid
                or not receipt["helper"]["elevated"] or receipt["helper"]["integrity"] != 0x3000
                or receipt["helper"]["image_volume"] != identity["image_volume"] or receipt["helper"]["image_index"] != identity["image_index"]
                or packets["kernel_udp_replies"] != 2 or packets["ipv4_packet_bytes"] != 1280 or packets["ipv6_packet_bytes"] != 1280):
                raise ValueError("separate high helper/medium owner/full kernel packet binding failed")
            execute(scenario + "-foreign-process-denied", [sys.executable, source / "scripts/refactor-windows-normal-user.py", executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="foreign"))
            foreign = await_json(case / "foreign-denied.json")
            if not foreign["denied"] or foreign["pid"] == identity["pid"] or foreign["original_pid"] != identity["pid"]:
                raise ValueError("foreign same-SID packet session denial missing")
            identity_negative = None
            if scenario == "normal":
                execute("nonoriginal-kernel-recovery-denied", [executable, *ROLE_ARGS],
                        extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="recovery-identity-negative"))
                identity_negative = await_json(case / "recovery-identity-negative.json")
                if (identity_negative["rejected_fields"] != ["interface_index", "luid", "alias", "guid"]
                    or not identity_negative["kernel_unchanged"]
                    or identity_negative["configuration_sha256"] != receipt["provider"]["configuration_sha256"]):
                    raise ValueError("nonoriginal PnP recovery did not preserve the exact original kernel state")
            if scenario == "normal":
                write(case / "stop.json", {"stop": True})
                ordinary.wait(timeout=10); helper.wait(timeout=10)
                stopped = await_json(case / "ordinary-stopped.json")
                if ordinary.returncode or helper.returncode or not stopped["kernel_absent"] or stopped["normal_cleanup_ms"] >= 5000:
                    raise ValueError("normal original provider cleanup failed")
            else:
                helper.kill(); helper.wait(timeout=10)
                code, log = execute("live-owner-recovery-denied", [executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="recover"), required=False)
                if code == 0 or "original ordinary owner is still alive" not in log or native.kernel.WaitForSingleObject(handle, 0) != 258:
                    raise ValueError("recovery did not refuse the retained original live owner")
                checked(native.kernel.TerminateProcess(handle, 73)); checked(native.kernel.WaitForSingleObject(handle, 5000) == 0)
                ordinary.wait(timeout=10)
                execute("dead-owner-exact-recovery", [executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="recover"))
            execute(scenario + "-final-inspection", [executable, *ROLE_ARGS], extra=dict(extra, NESTLINK_TUN_NATIVE_ROLE="inspect"))
            inspection = await_json(case / "inspection.json")
            if inspection["record"] is not None or inspection["current"] is not None or (root / "receipt.json").exists():
                raise ValueError("exact kernel/resource recovery did not clear its protected record")
            result["cases"][scenario] = {"status": "passed", "plan": ready, "packets": packets, "foreign_process": foreign,
                                         "recovery_identity_negative": identity_negative, "inspection": inspection}
        result["status"] = "passed"
    except BaseException as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        for handle in retained:
            if native.kernel.WaitForSingleObject(handle, 0) == 258:
                native.kernel.TerminateProcess(handle, 74)
            native.kernel.CloseHandle(handle)
        for process, log in active:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            log.close()
        if result["status"] != "passed":
            # Retain exact public recovery metadata and kernel identity after
            # stopping our original actors. Never recover/delete on failure.
            # ProgramFiles is outside the uploaded evidence tree and the hosted
            # VM is disposable, so leaving only a pathname would lose evidence.
            inspections = result.setdefault("failure_inspections", {})
            for scenario in ("normal", "crash", "raw-peer"):
                case, root = output / scenario, fixture / scenario
                if not case.is_dir() or not root.is_dir():
                    continue
                try:
                    code, _ = execute(scenario + "-failure-inspection", [executable, *ROLE_ARGS],
                        extra={"NESTLINK_TUN_NATIVE_CASE": str(case),
                            "NESTLINK_TUN_NATIVE_RECEIPT": str(root / "receipt.json"),
                            "NESTLINK_TUN_NATIVE_JOURNAL": str(root / "journal"),
                            "NESTLINK_TUN_NATIVE_ROLE": "inspect"}, timeout=10, required=False)
                    inspections[scenario] = {"return_code": code}
                    for name, original in (("protected-journal.json", root / "journal/network-tun-owner.json"),
                                           ("protected-receipt.json", root / "receipt.json")):
                        if original.is_file():
                            if not 0 < original.stat().st_size <= 65_536:
                                raise ValueError("failure metadata exceeds the production bound")
                            shutil.copyfile(original, case / name)
                            inspections[scenario][name] = digest(case / name)
                except Exception as diagnostic:
                    inspections[scenario] = {"diagnostic_error": str(diagnostic)}
        result["execution_provenance"]["finished_at_unix"] = time.time()
        for command in result["commands"]:
            log_path = output / command["log"]
            if log_path.is_file():
                command["log_sha256"] = digest(log_path)
        result["fixture_preserved_for_disposable_vm"] = str(fixture)
        write(output / "receipt.json", result)


if __name__ == "__main__":
    main()
