"""Run original native offline owners on GitHub, retaining every scoped failure.

This focused matrix reuses rust-core's original tests, codec installation,
ordinary Windows token and frozen HTTPS fixture. It never qualifies the full
workspace, physical dual-device targets, public NAT or advanced media.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import traceback


ROOT = pathlib.Path(__file__).resolve().parents[1]
RESIDENT_TESTS = {
    "management_commands_fence_delivery_before_success_or_failed_http_and_never_rearm",
    "pending_original_listener_eof_stop_logout_and_identity_change_join_actual_socket",
    "resident_quic_original_http_consume_real_pixels_files_rebuild_and_eof",
    "resident_tls_original_http_consume_real_pixels_files_rebuild_and_ipc_exit",
}
CORE_TESTS = {
    "independent_offline_app_core_quic_delivers_pixels_and_actual_file_after_online_expiry",
    "independent_offline_app_core_tls_delivers_pixels_and_actual_file_after_online_expiry",
}


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


def source():
    return {
        "revision": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "status": git("status", "--porcelain=v1", "--untracked-files=all"),
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"),
    }


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise SystemExit("R02: all native resident build/lint/execution requires GitHub-hosted Actions")
    output = pathlib.Path(os.environ["RUNNER_TEMP"]) / "nestlink-offline-resident-focused"
    output.mkdir()
    receipt = {
        "schema_version": 1,
        "scope": "Focused original offline AppCore/daemon/desktop and complete resident integration only; not full Rust core, physical target, public NAT or advanced-media acceptance",
        "source_revision": os.environ["GITHUB_SHA"],
        "run_id": os.environ["GITHUB_RUN_ID"],
        "run_attempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "workflow": os.environ["GITHUB_WORKFLOW_REF"],
        "workflow_revision": os.environ["GITHUB_WORKFLOW_SHA"],
        "runner_os": os.environ["RUNNER_OS"],
        "runner_environment": os.environ["RUNNER_ENVIRONMENT"],
        "image_os": os.environ.get("ImageOS"),
        "image_version": os.environ.get("ImageVersion"),
        "execution_identity": "verified original medium non-admin wrapper" if os.name == "nt" else "original non-root hosted runner and original PAM desktop session",
        "commands": [],
        "passed": False,
    }
    wrapper = [sys.executable, str(ROOT / "scripts/refactor-windows-normal-user.py")] if os.name == "nt" else []

    def execute(name, arguments, *, expected_count=None, expected_names=None, timeout=1800):
        command = [*wrapper, *arguments]
        path = output / f"{name}.log"
        entry = {"name": name, "command": command, "log": path.name, "started_unix": time.time(), "passed": False}
        receipt["commands"].append(entry)
        print(json.dumps({"starting": name, "command": command}), flush=True)
        try:
            with path.open("wb") as stream:
                result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout, check=False)
            entry["exit_code"] = result.returncode
            text = path.read_text(encoding="utf-8", errors="replace")
            entry["passed"] = result.returncode == 0
            if expected_count is not None:
                cases = re.findall(r"^test ([^\r\n]+) \.\.\. (ok|FAILED|ignored)\s*$", text, re.MULTILINE)
                summaries = re.findall(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;", text)
                entry.update(cases=cases, summaries=summaries)
                entry["passed"] &= (len(cases) == expected_count
                                    and len({name for name, _ in cases}) == expected_count
                                    and all(result == "ok" for _, result in cases)
                                    and summaries == [(str(expected_count), "0", "0")])
                if expected_names is not None:
                    entry["expected_tests"] = sorted(expected_names)
                    entry["passed"] &= {name for name, _ in cases} == expected_names
        except Exception as error:
            entry["error"] = str(error)
        entry["finished_unix"] = time.time()
        print(json.dumps(entry), flush=True)

    try:
        receipt["source_before"] = source()
        write(output / "source-before.json", receipt["source_before"])
        if receipt["source_before"]["revision"] != receipt["source_revision"] or receipt["source_before"]["status"]:
            raise RuntimeError("exact clean workflow source required before native validation")
        for name, arguments in [
            ("rustc-version", ["rustc", "--version", "--verbose"]),
            ("cargo-version", ["cargo", "--version"]),
        ]:
            execute(name, arguments, timeout=60)
        tool_receipt = pathlib.Path(os.environ["RUNNER_TEMP"]) / "nestlink-native-offline-https-tool.json"
        for path in (tool_receipt, tool_receipt.with_name("nestlink-native-offline-https-license.txt"),
                     pathlib.Path(os.environ["NESTLINK_CODEC_PREFIX"]) / "nestlink-codecs.json"):
            if path.is_file():
                shutil.copyfile(path, output / path.name)
        if "NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED" in os.environ:
            tool = pathlib.Path(os.environ["NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED"])
            receipt["https_tool_sha256_before"] = digest(tool)
            receipt["https_tool_matches_frozen_receipt"] = (
                receipt["https_tool_sha256_before"] == json.loads(tool_receipt.read_text())["executable_sha256"])
        else:
            receipt["https_tool_matches_frozen_receipt"] = False
        tests = [
            ("app-core", ["-p", "nestlink-app-core", "--test", "native_offline"], 2, CORE_TESTS),
            ("app-core-capture-terminal-unit", ["-p", "nestlink-app-core", "--lib", "runtime::native_capture_failure_tests::"], 1, None),
            ("daemon-remote-unit", ["-p", "nestlink-daemon", "--bin", "nestlink-daemon", "offline_remote::tests::"], 2, None),
            ("daemon-private-unit", ["-p", "nestlink-daemon", "--bin", "nestlink-daemon", "private_service_proxy::offline::tests::"], 2, None),
            ("daemon-download-consent-unit", ["-p", "nestlink-daemon", "--bin", "nestlink-daemon", "native_files::tests::download_consent_outlives_the_destination_ack_and_still_honors_session_revoke"], 1, None),
            ("daemon-entry-unit", ["-p", "nestlink-daemon", "--bin", "nestlink-daemon", "entry_tests::"], 1, None),
            ("desktop-layout", ["-p", "nestlink-desktop", "--lib", "layout_tests::independent_offline_"], 2, None),
            ("resident", ["-p", "nestlink-daemon", "--test", "offline_remote_resident"], 4, RESIDENT_TESTS),
        ]
        for name, arguments, count, names in tests:
            execute(name, ["cargo", "test", "--locked", *arguments, "--", "--show-output", "--test-threads=1", "--color", "never"],
                    expected_count=count, expected_names=names)
        for name, arguments in [
            ("app-core-clippy", ["-p", "nestlink-app-core", "--test", "native_offline"]),
            ("daemon-clippy", ["-p", "nestlink-daemon", "--bin", "nestlink-daemon"]),
            ("resident-clippy", ["-p", "nestlink-daemon", "--test", "offline_remote_resident"]),
        ]:
            execute(name, ["cargo", "clippy", "--locked", *arguments, "--", "-D", "warnings"])
        if "NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED" in os.environ:
            receipt["https_tool_sha256_after"] = digest(pathlib.Path(os.environ["NESTLINK_OFFLINE_RESIDENT_CLOUDFLARED"]))
        receipt["passed"] = (all(entry["passed"] for entry in receipt["commands"])
                             and receipt["https_tool_matches_frozen_receipt"]
                             and receipt.get("https_tool_sha256_after") == receipt.get("https_tool_sha256_before"))
    except Exception as error:
        receipt["error"] = str(error)
        (output / "coordinator-error.log").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        try:
            receipt["source_after"] = source()
            write(output / "source-after.json", receipt["source_after"])
            receipt["source_unchanged"] = receipt.get("source_before") == receipt["source_after"]
            receipt["passed"] &= receipt["source_unchanged"]
        except Exception as error:
            receipt["source_audit_error"] = str(error)
            receipt["passed"] = False
        receipt["files"] = [{"name": path.name, "bytes": path.stat().st_size, "sha256": digest(path)}
                            for path in sorted(output.iterdir()) if path.is_file()]
        write(output / "receipt.json", receipt)
        print(json.dumps(receipt, indent=2), flush=True)
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
