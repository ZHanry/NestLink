"""Exercise the original unsigned Inno candidate installers on hosted Windows.

This checks installed bytes and uninstall ownership. It does not activate the
optional broker, launch business owners, or grant signed/physical-target status.
"""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import time

APP_IDS = {"desktop": "{4FA00357-4E53-495E-AB25-F5A18C15CA01}_is1",
           "privileged": "{4FA00357-4E53-495E-AB25-F5A18C15CA02}_is1"}


def registered(role):
    import winreg
    name = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + APP_IDS[role]
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            try:
                with winreg.OpenKey(hive, name, 0, winreg.KEY_READ | view):
                    return True
            except FileNotFoundError:
                pass
    return False


def qualify(value, output, payload, installers, producer):
    if os.name != "nt" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise ValueError("candidate installer execution requires hosted Windows")
    evidence = output / "evidence"
    evidence.mkdir(exist_ok=True)
    report_path = evidence / "windows-candidate-installation.json"
    report = {"schema_version": 1, "source_revision": value["source_revision"], "status": "failed",
              "run_id": os.environ["GITHUB_RUN_ID"], "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "workflow_revision": os.environ["GITHUB_WORKFLOW_SHA"],
              "workflow": os.environ["GITHUB_WORKFLOW_REF"],
              "runner_environment": os.environ["RUNNER_ENVIRONMENT"], "platform": platform.platform(),
              "runner_token_is_administrator": bool(ctypes.windll.shell32.IsUserAnAdmin()),
              "production_update_eligible": False, "roles": {}, "commands": [],
              "limitations": ["Original unsigned candidate Inno installers on a disposable hosted Windows runner",
                              "User data is an explicitly owned sentinel fixture, not an enrolled identity",
                              "No ordinary-user, Windows 10/11 target, GUI, signed update or privileged activation qualification"]}
    state = Path(os.environ["LOCALAPPDATA"]) / "NestLink-RC"
    state_owned = False

    def command(name, argv):
        path = evidence / ("windows-" + name + "-process.log")
        with path.open("wb") as log:
            result = subprocess.run([str(item) for item in argv], stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT, timeout=120, check=False)
            log.write(("\n[qualification process exit: " + str(result.returncode) + "]\n").encode())
        report["commands"].append({"name": name, "return_code": result.returncode,
                                    "log": path.name, "sha256": producer.digest(path)})
        if result.returncode != 0:
            raise ValueError("original candidate installer operation failed: " + name)

    try:
        if state.exists() or state.is_symlink() or any(registered(role) for role in APP_IDS):
            raise ValueError("runner already contains candidate registration or user state")
        state.mkdir()
        state_owned = True
        sentinel = state / "hosted-install-retained-data"
        sentinel.write_bytes(os.urandom(128))
        retained = producer.digest(sentinel)
        with tempfile.TemporaryDirectory(prefix="nestlink-candidate-install-") as temporary:
            for role in APP_IDS:
                directory = Path(temporary) / role
                expected = {"nestlink-" + name + ".exe": producer.digest(payload / ("nestlink-" + name + ".exe"))
                            for name in (("desktop", "daemon", "privileged") if role == "privileged" else ("desktop", "daemon"))}
                installer = installers[role]
                owned = False
                try:
                    for operation in ("install", "reinstall"):
                        owned = True
                        installer_log = evidence / ("windows-" + role + "-" + operation + "-inno.log")
                        command(role + "-" + operation, [installer, "/SP-", "/VERYSILENT", "/SUPPRESSMSGBOXES",
                            "/NORESTART", "/NOICONS", "/TASKS=", "/DIR=" + str(directory), "/LOG=" + str(installer_log)])
                        actual = {path.name: producer.digest(path) for path in directory.glob("nestlink-*.exe")}
                        if actual != expected or not registered(role) or producer.digest(sentinel) != retained:
                            raise ValueError("installed/reinstalled candidate bytes, registration or retained user data differ")
                    report["roles"][role] = {"installer_sha256": producer.digest(installer), "installed_payload_sha256": expected,
                        "install_and_reinstall_exact_bytes": True, "uninstall_passed": False}
                finally:
                    if owned:
                        uninstaller = directory / "unins000.exe"
                        if not uninstaller.is_file():
                            raise ValueError("failed candidate installation has no original uninstaller; runner recovery remains explicit")
                        command(role + "-uninstall", [uninstaller, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                            "/LOG=" + str(evidence / ("windows-" + role + "-uninstall-inno.log"))])
                        deadline = time.monotonic() + 30
                        while registered(role) or any(directory.glob("*.exe")):
                            if time.monotonic() >= deadline:
                                raise ValueError("original candidate uninstaller left payload bytes or registration")
                            time.sleep(0.05)
                        if producer.digest(sentinel) != retained:
                            raise ValueError("candidate uninstall changed retained user data")
                        if role in report["roles"]:
                            report["roles"][role]["uninstall_passed"] = True
                            report["roles"][role]["retained_user_sentinel_unchanged"] = True
        report["status"] = "passed"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        if state_owned:
            try:
                (state / "hosted-install-retained-data").unlink(missing_ok=True)
                state.rmdir()
            except OSError:
                report["owned_state_cleanup_failed"] = True
                report["status"] = "failed"
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["status"] != "passed":
        raise ValueError("candidate installation fixture cleanup failed")
