#!/usr/bin/env python3
"""Run real medium-user SDK/WFP cases only on their disposable hosted VM.

Build and execution provenance are separate. A failed native capability or
missing different-SID process fails this experiment; it never becomes a skip
or a root-only substitute. No production CLI/real-device acceptance is claimed.
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
import uuid

from network_rewrite_wfp_native import Account, Native, Wfp, checked

PREFIX = "NESTLINK_WFP_ROLE_RESULT="
ARGS = ["--ignored", "--exact", "raw_windows::probe_role", "--nocapture", "--test-threads=1", "--color=never"]


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def normal(identity):
    return (identity["elevated"] is False and 0x2000 <= identity["integrity"] < 0x3000
            and identity["session"] > 0 and identity["pid"] > 0 and identity["creation"] > 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    env = dict(os.environ)
    if (os.name != "nt" or env.get("NESTLINK_WFP_KERNEL") != "1"
        or env.get("GITHUB_ACTIONS") != "true" or env.get("RUNNER_ENVIRONMENT") != "github-hosted"
        or env.get("RUNNER_OS") != "Windows" or env.get("GITHUB_REPOSITORY") != "ZHanry/NestLink"
        or not env.get("GITHUB_WORKFLOW_REF", "").startswith("ZHanry/NestLink/.github/workflows/windows-local-port-gate.yml@refs/")
        or re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is None):
        raise ValueError("R02: this experiment requires its dedicated GitHub-hosted Windows workflow")
    if not c.windll.shell32.IsUserAnAdmin():
        raise ValueError("the coordinator requires the hosted elevated runner token")
    source, temp, output = Path.cwd().resolve(), Path(env["RUNNER_TEMP"]).resolve(), arguments.output.resolve()
    if not arguments.output.is_absolute() or output == temp or not output.is_relative_to(temp) or output.exists():
        raise ValueError("a fresh evidence directory beneath RUNNER_TEMP is required")
    output.mkdir()
    result = {"schema_version": 1, "kind": "windows-sdk-wfp-hosted-kernel", "evidence_level": "L2_hosted_sdk_kernel",
              "production_cli_validated": False, "status": "failed", "cases": {}, "commands": [],
              "build_provenance": {"source_revision": env["GITHUB_SHA"], "lock_sha256": digest(source / "Cargo.lock"),
                  "workflow_ref": env["GITHUB_WORKFLOW_REF"], "workflow_revision": env["GITHUB_WORKFLOW_SHA"],
                  "run_id": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "job": env["GITHUB_JOB"],
                  "runner_environment": env["RUNNER_ENVIRONMENT"], "runner_os": env["RUNNER_OS"],
                  "runner_arch": env.get("RUNNER_ARCH"), "image_os": env.get("IMAGEOS"), "image_version": env.get("IMAGEVERSION")},
              "execution_provenance": {"source_revision": env["GITHUB_SHA"], "environment": "disposable_github_hosted_windows_vm",
                  "workflow_run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "started_at_unix": time.time()}}
    native, account, wfp = Native(), None, None
    # Python's Windows environment mapping normalizes names to uppercase;
    # converting it to a plain dict removes case-insensitive lookup semantics.
    fixture = Path(env["PROGRAMFILES"]) / ("NestLink-WFP-Lab-" + uuid.uuid4().hex)
    executable = None
    active, owner_handles, roots = [], [], []
    sentinel = "NestLink-WFP-Lab-" + uuid.uuid4().hex
    sentinel_before = None
    foreign = None
    probe_incarnations = set()
    admin_acl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"

    def execute(name, argv, *, extra=None, timeout=30, required=True):
        log = output / (name + ".log")
        item = {"name": name, "argv": [str(word) for word in argv], "timeout_seconds": timeout,
                "started_at_unix": time.time(), "log": log.name}
        result["commands"].append(item)
        with log.open("wb") as stream:
            process = subprocess.Popen(item["argv"], stdin=subprocess.DEVNULL, stdout=stream,
                                       stderr=subprocess.STDOUT, env=dict(env, **(extra or {})), creationflags=0x08000000)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)
                item["timed_out"] = True
            item["return_code"] = process.returncode
        item["finished_at_unix"], item["log_sha256"] = time.time(), digest(log)
        text = log.read_text(encoding="utf-8", errors="replace")
        if required and (item.get("timed_out") or process.returncode):
            raise RuntimeError(f"{name} failed; inspect its exact retained log")
        return process.returncode, text

    def powershell(name, code, **kwargs):
        return execute(name, ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; " + code], **kwargs)[1].lstrip("\ufeff").strip()

    def await_json(path, budget=30, process=None):
        deadline = time.monotonic() + budget
        while time.monotonic() < deadline:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                if process is not None and process.poll() is not None:
                    raise RuntimeError(f"cooperation process exited before {path.name}")
                time.sleep(0.05)
        raise TimeoutError(f"bounded wait expired for {path.name}")

    def role(action, root, extra=None, required=True):
        code, text = execute(root.name + "-" + action + "-" + uuid.uuid4().hex[:6],
            [executable, "--ignored", "--exact", "raw_windows::administrator_role", "--nocapture", "--test-threads=1", "--color=never"],
            extra=dict(extra or {}, NESTLINK_WFP_ACTION=action, NESTLINK_WFP_ROOT=str(root)), required=required, timeout=15)
        if not required:
            return code, text
        rows = [row.split(PREFIX, 1)[1] for row in text.splitlines() if PREFIX in row]
        if len(rows) != 1:
            raise ValueError("missing exact administrator role result")
        return json.loads(rows[0])

    def start(name, argv, extra):
        log = (output / (name + ".log")).open("wb")
        process = subprocess.Popen([str(word) for word in argv], stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, env=dict(env, **extra), creationflags=0x08000000)
        active.append((process, log))
        result["commands"].append({"name": name, "argv": [str(word) for word in argv], "pid": process.pid,
                                   "log": Path(log.name).name, "started_at_unix": time.time()})
        return process

    def retain_owner(plan):
        native.kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        native.kernel.OpenProcess.restype = w.HANDLE
        native.kernel.GetProcessTimes.argtypes = [w.HANDLE, c.POINTER(w.FILETIME), c.POINTER(w.FILETIME), c.POINTER(w.FILETIME), c.POINTER(w.FILETIME)]
        native.kernel.GetProcessTimes.restype = w.BOOL
        handle = native.kernel.OpenProcess(0x101001, False, plan["process"]["pid"])
        checked(handle)
        created, exited, kernel, user = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
        checked(native.kernel.GetProcessTimes(handle, c.byref(created), c.byref(exited), c.byref(kernel), c.byref(user)))
        if (created.dwLowDateTime | created.dwHighDateTime << 32) != plan["process"]["creation"]:
            native.kernel.CloseHandle(handle)
            raise ValueError("owner PID was reused before coordinator acquired its retained handle")
        owner_handles.append(handle)
        return handle

    def probe(name, identity_kind, endpoint, transport, *, empty=False, expected=None):
        directory = output / "probes" / identity_kind
        target = directory / (name + ".json")
        extra = {"NESTLINK_WFP_RESULT": str(target), "NESTLINK_WFP_PROBE": "identity" if endpoint is None else "exchange",
                 "NESTLINK_WFP_ENDPOINT": endpoint or "127.0.0.1:1", "NESTLINK_WFP_TRANSPORT": transport,
                 "NESTLINK_WFP_NONCE": uuid.uuid4().hex, "NESTLINK_WFP_EMPTY": "1" if empty else "0"}
        if identity_kind == "other":
            pid = account.run(executable, ARGS, dict(env, **extra, TEMP=str(directory), TMP=str(directory)), fixture)
        else:
            _, log = execute(name, [sys.executable, source / "scripts/refactor-windows-normal-user.py", executable, *ARGS], extra=extra, timeout=15)
            if "test result: ok. 1 passed; 0 failed; 0 ignored;" not in log:
                raise ValueError("same-SID cooperation probe did not execute exactly once")
            pid = None
        value = await_json(target, 2)
        if not normal(value["identity"]):
            raise ValueError("probe was not an actual medium, non-elevated interactive process")
        incarnation = (value["identity"]["pid"], value["identity"]["creation"])
        if incarnation in probe_incarnations:
            raise ValueError("probe result reused an earlier process incarnation")
        probe_incarnations.add(incarnation)
        if identity_kind == "same" and value["identity"]["sid"] != runner_sid:
            raise ValueError("same-SID probe changed OS account")
        if identity_kind == "other" and (value["identity"]["sid"] != account.sid or pid != value["identity"]["pid"]):
            raise ValueError("different-SID result does not identify the actual Logon process")
        if expected is not None and value["allowed"] is not expected:
            raise ValueError(f"{name}: actual kernel admission disagreed with expectation")
        return value

    def sentinel_snapshot():
        return json.loads(powershell("sentinel-observe-" + uuid.uuid4().hex[:5],
            f"Get-NetFirewallRule -Name '{sentinel}' | Select-Object Name,Enabled,Direction,Action,Profile,PolicyStoreSourceType | ConvertTo-Json -Compress"))

    try:
        if subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() != env["GITHUB_SHA"] or subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"]):
            raise ValueError("exact clean Actions source SHA required")
        service = powershell("native-service-capabilities", "@{BFE=(Get-Service BFE).Status.ToString();SecondaryLogon=(Get-Service seclogon).Status.ToString()} | ConvertTo-Json -Compress")
        result["execution_provenance"]["services"] = json.loads(service)
        if result["execution_provenance"]["services"]["BFE"] != "Running":
            raise RuntimeError("native Base Filtering Engine is unavailable")
        execute("verify-medium-token-capability", [sys.executable, source / "scripts/refactor-windows-normal-user.py", "--check"])
        account = Account(native)
        result["execution_provenance"]["different_sid"] = account.sid
        if json.loads(service)["SecondaryLogon"] != "Running":
            powershell("start-native-secondary-logon", "Start-Service seclogon")
        _, log = execute("build-same-sdk-executable", ["cargo", "test", "--locked", "-p", "nestlink-sdk", "--test", "private_services", "--no-run", "--message-format=json"], timeout=2400)
        artifacts = []
        for line in log.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "private_services" and item.get("profile", {}).get("test") is True and item.get("executable"):
                artifacts.append(Path(item["executable"]).resolve())
        if len(artifacts) != 1 or not artifacts[0].is_relative_to(source / "target"):
            raise ValueError("expected one same-source SDK test artifact")
        native.directory(fixture, admin_acl)
        executable = fixture / "private-services.exe"
        shutil.copyfile(artifacts[0], executable)
        execute("protect-executable-owner", ["icacls.exe", executable, "/setowner", "*S-1-5-32-544"])
        if digest(executable) != digest(artifacts[0]):
            raise ValueError("protected cooperation executable differs from build")
        result["build_provenance"]["executable"] = {"build_path": str(artifacts[0]), "execution_path": str(executable), "sha256": digest(executable)}
        # The runner SID gets only this output tree; never widen workspace,
        # ProgramFiles or any production/private installation directory.
        runner_sid = powershell("runner-user-sid", "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value")
        execute("allow-owner-evidence-only", ["icacls.exe", output, "/grant", f"*{runner_sid}:(OI)(CI)M"])
        probes = output / "probes"
        native.directory(probes, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        native.directory(probes / "same", f"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{runner_sid})")
        native.directory(probes / "other", f"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{account.sid})")
        same = probe("same-sid-capability", "same", None, "tcp")
        other = probe("different-sid-capability", "other", None, "tcp")
        if same["identity"]["sid"] == other["identity"]["sid"] or same["identity"]["sid"] != runner_sid:
            raise ValueError("different-SID proof was replaced by the runner account")
        result["execution_provenance"]["ordinary_tokens"] = [same, other]
        powershell("create-unrelated-firewall-sentinel", f"New-NetFirewallRule -Name '{sentinel}' -DisplayName '{sentinel}' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress 192.0.2.1 -RemotePort 9 -Enabled True | Out-Null")
        sentinel_before = sentinel_snapshot()
        for transport in ("tcp", "udp"):
            root = fixture / transport
            native.directory(root, admin_acl)
            roots.append(root)
            case = output / transport
            native.directory(case, f"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{runner_sid})")
            owner = start(transport + "-ordinary-sdk", [sys.executable, source / "scripts/refactor-windows-normal-user.py", executable,
                "--ignored", "--exact", "raw_windows::sdk_owner_role", "--nocapture", "--test-threads=1", "--color=never"],
                {"NESTLINK_WFP_ROOT": str(root), "NESTLINK_WFP_OUTPUT": str(case), "NESTLINK_WFP_TRANSPORT": transport,
                 "TEMP": str(case), "TMP": str(case), "NESTLINK_NODE_TEST_USAGE_ROOT": str(case)})
            plan_ready = await_json(case / "plan-ready.json", 30, owner)
            plan = plan_ready["plan"]
            original = retain_owner(plan)
            if not normal(plan["process"]) or plan["process"]["sid"] != runner_sid or plan["process"] != plan_ready["identity"]:
                raise ValueError("SDK owner is not the original normal runner process")
            preflight = [probe(transport + "-preflight-same", "same", plan_ready["network_control_endpoint"], transport, expected=True),
                         probe(transport + "-preflight-different", "other", plan_ready["network_control_endpoint"], transport, expected=True)]
            helper = start(transport + "-administrative-helper", [executable, "--ignored", "--exact", "raw_windows::administrator_role", "--nocapture", "--test-threads=1", "--color=never"],
                {"NESTLINK_WFP_ROOT": str(root), "NESTLINK_WFP_PLAN": str(case / "private-plan/plan.json"), "NESTLINK_WFP_ACTION": "install"})
            ready = await_json(case / "sdk-ready.json", 20, owner)
            attestation = ready["receipt"]
            if ready["occupied_port_rejected"] is not True or attestation["plan"] != plan or attestation["helper"]["pid"] != helper.pid or not attestation["helper"]["elevated"] or attestation["helper"]["integrity"] != 0x3000:
                raise ValueError("administrative gate receipt did not bind the original separate helper")
            for field in ("image_volume", "image_index", "image"):
                if plan["process"][field] != attestation["helper"][field]:
                    raise ValueError("ordinary/admin executable identities differ")
            probes_before = [probe(transport + "-same-before", "same", plan["endpoint"], transport, expected=True),
                             probe(transport + "-different-denied", "other", plan["endpoint"], transport, expected=False),
                             probe(transport + "-same-after", "same", plan["endpoint"], transport, expected=True)]
            if transport == "udp":
                probes_before.append(probe("udp-empty", "same", plan["endpoint"], transport, empty=True, expected=True))
                helper.kill(); helper.wait(timeout=10)
                retained = role("inspect", root)["state"]
                if retained["current"] != attestation["installed"]:
                    raise ValueError("helper termination removed or changed the persistent WFP fence")
                write(case / "after-helper-kill.json", retained)
                code, log = role("recover", root, required=False)
                if code == 0 or "original Windows socket owner is still alive" not in log:
                    raise ValueError("recovery did not refuse the actual still-live original owner")
            else:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    state = await_json(root / "current.json", 2, helper)
                    if state["denying"]:
                        break
                    time.sleep(0.1)
                else:
                    raise TimeoutError("actual expiry never retained the deny-all fence")
                if len(state["installed"]["filters"]) != 2:
                    raise ValueError("expiry did not remove only the SID permit")
                write(case / "expiry-deny.json", state)
            write(root / "control.json", {"stage": "witness"})
            witness = await_json(case / "witness-ready.json", 20, owner)
            if witness["identity"] != plan["process"] or native.kernel.WaitForSingleObject(original, 0) != 258:
                raise ValueError("kernel witness did not retain the original live process")
            kernel_probes = [probe(transport + "-live-control", "same", witness["control_endpoint"], transport, expected=True),
                             probe(transport + "-retained-same", "same", plan["endpoint"], transport, expected=transport == "udp"),
                             probe(transport + "-retained-different", "other", plan["endpoint"], transport, expected=False),
                             probe(transport + "-different-live-control", "other", witness["control_endpoint"], transport, expected=True)]
            write(root / "control.json", {"stage": "finish"})
            owner.wait(timeout=15)
            if owner.returncode or native.kernel.WaitForSingleObject(original, 5000) != 0:
                raise ValueError("original SDK/socket owner did not physically exit")
            scenario = await_json(case / "scenario.json", 2)
            if (scenario["source_revision"] != env["GITHUB_SHA"] or scenario["plan"] != plan
                or scenario["status"] != "passed_before_original_process_exit"
                or scenario["socket_closed"] is not True or scenario["cleanup_failures"] != 0
                or scenario["original_usage"]["outstanding_bytes"] != 0):
                raise ValueError("incomplete original SDK/physical/budget scenario")
            if any(proof["payload"] not in scenario["preflight_control_payloads"] for proof in preflight):
                raise ValueError("native same/different-SID network capability lacks baseline byte witnesses")
            if any(kernel_probes[index]["payload"] not in scenario["control_payloads"] for index in (0, 3)):
                raise ValueError("ungated live control has no actual socket byte witness")
            if transport == "tcp" and scenario["witness_payloads"]:
                raise ValueError("expired deny-all fence admitted bytes to its still-live listener")
            for proof in probes_before:
                if proof["allowed"] != (proof["payload"] in scenario["backend_payloads"]):
                    raise ValueError("SID admission disagrees with actual approved private backend bytes")
            if transport == "udp":
                if scenario["forwarded_datagrams"] < 6:
                    raise ValueError("empty/nonempty SDK UDP roundtrip evidence is incomplete")
                for proof in kernel_probes[1:3]:
                    if proof["allowed"] != (proof["payload"] in scenario["witness_payloads"]):
                        raise ValueError("persistent SID fence disagrees with actual live local witness bytes")
                wfp = Wfp()
                foreign = wfp.inject(plan)
                before = role("inspect", root)["state"]
                write(case / "foreign-before.json", before)
                code, log = role("recover", root, required=False)
                after = role("inspect", root)["state"]
                if code == 0 or before != after or "WFP object IDs/configuration changed" not in log:
                    raise ValueError("recovery changed or adopted the injected foreign filter")
                write(case / "foreign-after.json", after)
                wfp.remove_exact(foreign); foreign = None
                role("recover", root)
            else:
                helper.wait(timeout=12)
                if helper.returncode or await_json(root / "helper-finished.json", 2) != {"cleaned_after_owner_exit": True}:
                    raise ValueError("original helper did not confirm physical-exit cleanup")
            final = role("inspect", root)["state"]
            if final != {"journal": None, "current": None} or sentinel_snapshot() != sentinel_before:
                raise ValueError("exact cleanup failed or unrelated firewall configuration changed")
            scenario.update({"preflight_network_probes": preflight, "probes": probes_before, "kernel_witness_probes": kernel_probes, "owner_process_exited": True,
                             "gate_and_journal_removed": True, "unrelated_firewall_preserved": True,
                             "foreign_filter_preserved": transport == "udp", "expiry_deny_all": transport == "tcp",
                             "helper_crash_persistent_sid_fence": transport == "udp", "status": "passed_scoped_hosted_sdk_kernel"})
            result["cases"][transport] = scenario
        if digest(executable) != result["build_provenance"]["executable"]["sha256"]:
            raise ValueError("cooperation executable changed during execution")
        result["status"] = "passed_scoped_hosted_sdk_kernel"
    except BaseException as error:
        result["failure"] = type(error).__name__ + ": " + str(error)
        print(result["failure"], flush=True)
    finally:
        for handle in owner_handles:
            if native.kernel.WaitForSingleObject(handle, 0) == 258:
                if not native.kernel.TerminateProcess(handle, 125) or native.kernel.WaitForSingleObject(handle, 10000) != 0:
                    result.setdefault("cleanup_failures", []).append("original retained owner handle did not confirm physical exit")
        for process, stream in reversed(active):
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            except Exception as error:
                result.setdefault("cleanup_failures", []).append(str(error))
            finally:
                stream.close()
        for handle in owner_handles:
            native.kernel.CloseHandle(handle)
        for root in roots:
            if executable is not None:
                retained = output / (root.name + "-ownership")
                retained.mkdir()
                for relative in ("receipt.json", "current.json", "control.json", "helper-finished.json", "journal/local-port-owner.json"):
                    try:
                        original = root / relative
                        if original.is_file() and not original.is_symlink() and not (original.stat(follow_symlinks=False).st_file_attributes & 0x400):
                            shutil.copyfile(original, retained / relative.replace("/", "-"))
                    except Exception as error:
                        result.setdefault("cleanup_failures", []).append(str(error))
                try:
                    state = role("inspect", root)["state"]
                    write(output / (root.name + "-final-ownership.json"), state)
                    if foreign is None:
                        role("recover", root)
                except Exception as error:
                    result.setdefault("cleanup_failures", []).append(str(error))
        if wfp is not None:
            try:
                wfp.close()
            except Exception as error:
                result.setdefault("cleanup_failures", []).append(str(error))
        if account is not None:
            try:
                account.close()
            except Exception as error:
                result.setdefault("cleanup_failures", []).append(str(error))
        if sentinel_before is not None:
            try:
                if sentinel_snapshot() != sentinel_before:
                    raise ValueError("sentinel changed; preserve it for operator inspection")
                powershell("remove-exact-unrelated-sentinel", f"Remove-NetFirewallRule -Name '{sentinel}'")
            except Exception as error:
                result.setdefault("cleanup_failures", []).append(str(error))
        # The small uniquely owned ProgramFiles fixture is intentionally left
        # for this disposable VM's destruction. Failure artifacts retain every
        # journal/filter identity; there is no recursive privileged deletion.
        result["retained_fixture_directory"] = str(fixture)
        result["execution_provenance"]["finished_at_unix"] = time.time()
        result["execution_provenance"]["logs"] = {path.name: digest(path) for path in output.glob("*.log")}
        if result.get("cleanup_failures"):
            result["status"] = "failed"
        write(output / "receipt.json", result)
    print(json.dumps({"status": result["status"], "evidence": str(output)}, indent=2))
    return 0 if result["status"] == "passed_scoped_hosted_sdk_kernel" else 1


if __name__ == "__main__":
    raise SystemExit(main())
