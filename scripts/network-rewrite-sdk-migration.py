#!/usr/bin/env python3
"""Measure the production SDK automatic file-only migration under real relay DROP.

GitHub-hosted Linux only. One owned network namespace contains ordinary-user
management, two production node owners, endpoint proof and actual approved OS
FileRead workers. The external controller only applies nftables packet DROP.
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import struct
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nestlink_sdk_socket_helpers", ROOT / "scripts/network-rewrite-socket.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing existing socket experiment helpers")
SOCKET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOCKET)
EVIDENCE, require = SOCKET.EVIDENCE, SOCKET.require
EVIDENCE.WORKFLOW_PATH = ".github/workflows/network-sdk-migration.yml"
TEST = "route_sets::physical_loss::automatic_original_inner_survives_real_relay_drop_within_original_authority"
TRIALS = 20


def wait_json(root: Path, name: str, process: tuple, timeout: float = 12) -> dict:
    deadline = time.monotonic() + timeout
    path = root / name
    while not path.is_file():
        require(process[0].poll() is None, "production SDK test exited before " + name)
        require(time.monotonic() < deadline, "production SDK test marker timeout: " + name)
        time.sleep(0.01)
    value = json.loads(path.read_text())
    require(isinstance(value, dict), "invalid production SDK marker: " + name)
    return value


def address_port(text: str) -> int:
    host, port = text.rsplit(":", 1)
    require(ipaddress.ip_address(host).is_loopback, "fault targets must remain inside the owned loopback namespace")
    port = int(port)
    require(0 < port <= 65535, "invalid signed relay port")
    return port


def capture_facts(path: Path, trials: list[dict]) -> dict:
    """Validate every complete Ethernet/IPv4/UDP record from Linux loopback."""
    data = path.read_bytes()
    orders = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
              b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    require(len(data) >= 24 and data[:4] in orders, "missing classic pcap header")
    order, scale = orders[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(order + "HHIIII", data[4:24])
    require((major, minor) == (2, 4) and snaplen >= 65535 and linktype == 1, "complete Linux loopback Ethernet capture required")
    counts = [{"active_initials": 0, "standby_initials": 0, "standby_udp_after_drop": 0} for _ in trials]
    offset = 24
    packets = 0
    while offset < len(data):
        require(len(data) - offset >= 16, "truncated pcap record header")
        seconds, fraction, included, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        require(0 < included == original <= snaplen and offset + included <= len(data), "truncated pcap frame")
        frame = data[offset:offset + included]
        offset += included
        packets += 1
        if len(frame) < 42 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        if ip[0] >> 4 != 4 or header < 20 or len(ip) < header + 8 or ip[9] != 17:
            continue
        require(ip[12:16] == b"\x7f\x00\x00\x01" and ip[16:20] == b"\x7f\x00\x00\x01", "unexpected non-loopback UDP traffic")
        udp = ip[header:]
        source, destination = struct.unpack("!HH", udp[:4])
        payload = udp[8:]
        stamp = seconds * 1_000_000_000 + fraction * scale
        initial = len(payload) >= 1200 and payload[0] & 0xc0 == 0xc0 and (
            (int.from_bytes(payload[1:5], "big") == 1 and payload[0] & 0x30 == 0) or
            (int.from_bytes(payload[1:5], "big") == 0x6b3343cf and payload[0] & 0x30 == 0x10))
        for trial, count in zip(trials, counts):
            if trial["started_wall_ns"] <= stamp <= trial["completed_wall_ns"]:
                if initial and destination == trial["active_port"]:
                    count["active_initials"] += 1
                if initial and destination == trial["standby_port"]:
                    count["standby_initials"] += 1
                if stamp >= trial["drop_installed_wall_ns"] and trial["standby_port"] in (source, destination):
                    count["standby_udp_after_drop"] += 1
    require(packets > 0, "no complete captured traffic")
    for count in counts:
        require(all(value > 0 for value in count.values()), "capture lacks original/standby QUIC Initial or actual new-path UDP after DROP")
    return {"complete_packets": packets, "trials": counts, "sha256": EVIDENCE.sha256_file(path)}


def run_slice(experiment: SOCKET.Experiment, executable: Path, private: Path) -> dict:
    namespace = "nl-sdk-migration-" + secrets.token_hex(5)
    table = "nestlink_sdk_migration"
    facts = {"passed": False, "namespace": namespace, "trials": [], "cleanup_failures": []}
    created = False
    capture = None
    try:
        experiment.command("namespace-add", ["sudo", "-n", "ip", "netns", "add", namespace])
        created = True
        experiment.command("loopback-up", ["sudo", "-n", "ip", "-n", namespace, "link", "set", "lo", "up"])
        prefix = ["sudo", "-n", "ip", "netns", "exec", namespace]
        result = experiment.command("kernel-namespace", [*prefix, "readlink", "/proc/self/ns/net"])
        ids = (experiment.output / result["log"]).read_text().splitlines()[1:]
        require(len(ids) == 1 and ids[0] != os.readlink("/proc/self/ns/net"), "dedicated kernel namespace required")
        facts["kernel_namespace"] = ids[0]
        capture = experiment.launch("production-sdk-capture", [*prefix, "tcpdump", "--immediate-mode", "-i", "lo", "-nn", "-U", "-s", "0", "-Z", pwd.getpwuid(os.getuid()).pw_name, "-w", str(experiment.output / "production-sdk.pcap"), "udp"])
        deadline = time.monotonic() + 3
        while "listening on lo" not in (experiment.output / capture[2]["log"]).read_text(errors="replace"):
            require(capture[0].poll() is None and time.monotonic() < deadline, "tcpdump did not become ready")
            time.sleep(0.02)
        variables = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_REPOSITORY": EVIDENCE.REPOSITORY,
                     "RUNNER_TEMP": os.environ["RUNNER_TEMP"], "NESTLINK_SDK_MIGRATION_FIXTURE": str(private),
                     "NESTLINK_NETWORK_RUNNER_NAMESPACE": os.readlink("/proc/self/ns/net"), "RUST_BACKTRACE": "1"}
        previous_completed = time.time_ns()
        process = experiment.launch("production-sdk-test", [*prefix, "setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()), "--clear-groups", "--", "env",
            *[name + "=" + value for name, value in variables.items()], str(executable), "--ignored", "--exact", TEST, "--nocapture", "--test-threads=1"])
        for index in range(TRIALS):
            ready = wait_json(private, f"ready-{index:02}.json", process)
            require(ready.get("trial") == index, "out-of-order production trial")
            active, standby = address_port(ready["active_relay"]), address_port(ready["standby_relay"])
            require(active != standby, "DROP must isolate only the original relay")
            (experiment.output / f"ready-{index:02}.json").write_text(json.dumps(ready, indent=2) + "\n")
            rules = experiment.output / f"drop-{index:02}.nft"
            rules.write_text(f"table inet {table} {{\n chain output {{ type filter hook output priority 0; policy accept;\n udp sport {active} counter drop\n udp dport {active} counter drop\n }}\n}}\n")
            experiment.command(f"trial-{index:02}-drop-install", [*prefix, "nft", "-f", str(rules)])
            installed = time.time_ns()
            SOCKET.write_marker(private, f"installed-{index:02}")
            completed = wait_json(private, f"completed-{index:02}.json", process, 6)
            completed_wall = time.time_ns()
            require(completed.get("trial") == index and 0 < completed.get("elapsed_us", 0) <= 3_000_000, "original network p95 threshold cannot be enlarged")
            require(completed.get("path_epoch") == 2 and completed.get("verified_file_bytes") == 98_335, "actual new-path source verification missing")
            require(all(completed.get(key) is True for key in ("original_udp_released", "standby_udp_released", "file_worker_joined")), "actual physical/worker cleanup missing")
            counter = experiment.command(f"trial-{index:02}-drop-counters", [*prefix, "nft", "--json", "list", "table", "inet", table])
            nft = json.loads("\n".join((experiment.output / counter["log"]).read_text().splitlines()[1:]))
            counters = [expression["counter"]["packets"] for entry in nft["nftables"] for expression in entry.get("rule", {}).get("expr", []) if "counter" in expression]
            require(len(counters) == 2 and sum(counters) > 0, "no real old-relay packet hit DROP")
            experiment.command(f"trial-{index:02}-drop-delete", [*prefix, "nft", "delete", "table", "inet", table])
            SOCKET.write_marker(private, f"cleared-{index:02}")
            (experiment.output / f"completed-{index:02}.json").write_text(json.dumps(completed, indent=2) + "\n")
            facts["trials"].append({"trial": index, "active_port": active, "standby_port": standby,
                "started_wall_ns": previous_completed, "drop_installed_wall_ns": installed,
                "completed_wall_ns": completed_wall, "drop_packet_counters": counters, **completed})
            previous_completed = completed_wall
        receipt = wait_json(private, "sdk-receipt.json", process)
        (experiment.output / "sdk-receipt.json").write_bytes((private / "sdk-receipt.json").read_bytes())
        experiment.finish(process, 8)
        content = (experiment.output / process[2]["log"]).read_text(errors="replace")
        require("test result: ok. 1 passed; 0 failed; 0 ignored" in content, "exact ignored SDK test did not execute once")
        observed = re.findall(r'namespace="(net:\[[0-9]+\])" pid=([0-9]+) Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)', content)
        require(len(observed) == 1 and observed[0][0] == facts["kernel_namespace"]
                and all(int(uid) == os.getuid() for uid in observed[0][2:]), "actual SDK process namespace and ordinary UID must match the owned fixture")
        facts["observed_sdk_pid"] = int(observed[0][1])
        facts["observed_sdk_uid"] = int(observed[0][2])
        require(len(receipt.get("trials", [])) == TRIALS and receipt.get("p95_us", 3_000_001) <= 3_000_000, "missing unchanged p95 gate")
        samples = [{"trial": trial["trial"], "elapsed_us": trial["elapsed_us"]} for trial in facts["trials"]]
        require(receipt["trials"] == samples, "final SDK samples differ from independently retained completion markers")
        durations = sorted(trial["elapsed_us"] for trial in samples)
        require(receipt["p95_us"] == durations[(TRIALS * 95 + 99) // 100 - 1], "p95 must match the actual samples")
        facts["sdk"] = receipt
        experiment.stop_capture(capture)
        capture = None
        experiment.command("capture-readable", ["sudo", "-n", "chown", pwd.getpwuid(os.getuid()).pw_name, str(experiment.output / "production-sdk.pcap")])
        facts["capture"] = capture_facts(experiment.output / "production-sdk.pcap", facts["trials"])
        facts["passed"] = True
    except BaseException as error:
        facts["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        if capture is not None:
            try:
                experiment.stop_capture(capture)
            except BaseException as error:
                facts["cleanup_failures"].append("capture: " + str(error))
        facts["cleanup_failures"].extend(experiment.cleanup_processes())
        if created:
            prefix = ["sudo", "-n", "ip", "netns", "exec", namespace]
            try:
                # The namespace is owned by this run; never touch host nftables.
                experiment.command("owned-nft-cleanup", [*prefix, "nft", "flush", "ruleset"])
                result = experiment.command("owned-pids-before-delete", ["sudo", "-n", "ip", "netns", "pids", namespace])
                pids = (experiment.output / result["log"]).read_text().splitlines()[1:]
                require(not pids, "owned namespace still contains a child after complete process cleanup")
                experiment.command("namespace-delete", ["sudo", "-n", "ip", "netns", "delete", namespace])
                result = experiment.command("namespace-after-cleanup", ["ip", "netns", "list"])
                require(namespace not in (experiment.output / result["log"]).read_text(), "owned namespace survived deletion")
                facts["owned_namespace_removed"] = True
            except BaseException as error:
                facts["cleanup_failures"].append("namespace: " + str(error))
        facts["passed"] = facts["passed"] and not facts["cleanup_failures"]
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = EVIDENCE.validate_actions_environment(os.environ)
    require("RUST_MIN_STACK" not in os.environ, "the original ordinary stack cannot be enlarged")
    require(sys.platform == "linux" and identity["runner"]["os"] == "Linux" and os.getuid() != 0, "ordinary GitHub-hosted Linux runner required")
    require(ROOT.resolve() == Path(os.environ["GITHUB_WORKSPACE"]).resolve(), "source must be GITHUB_WORKSPACE")
    output = EVIDENCE.validate_output_path(args.output, ROOT, Path(os.environ["RUNNER_TEMP"]))
    output.mkdir(parents=True)
    commands, processes = [], []
    experiment = SOCKET.Experiment(output, commands, processes)
    before = after = executable_record = slice_facts = None
    failure = None
    try:
        before = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
        EVIDENCE.require_unchanged_source(before, before)
        experiment.command("network-tool-index", ["sudo", "-n", "apt-get", "update"], 180)
        experiment.command("network-tools", ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends", "iproute2", "tcpdump", "util-linux", "nftables"], 180)
        for label, argv in (("rust-version", ["rustc", "--version", "--verbose"]), ("cargo-version", ["cargo", "--version"]), ("kernel", ["uname", "-a"])):
            experiment.command(label, argv)
        built = experiment.command("build-production-sdk-test", ["cargo", "test", "--locked", "-p", "nestlink-sdk", "--test", "network_relay", "--no-run", "--message-format=json"], 1800)
        binaries = []
        for line in (output / built["log"]).read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "network_relay" and item.get("profile", {}).get("test") and item.get("executable"):
                binaries.append(Path(item["executable"]).resolve())
        require(len(binaries) == 1 and binaries[0].is_file(), "one exact-source production SDK test binary required")
        executable = binaries[0]
        executable_record = {"path": executable.relative_to(ROOT).as_posix(), "sha256": EVIDENCE.sha256_file(executable),
            "source_revision": identity["source_revision"], "dependency_lock_sha256": before["dependency_lock_sha256"], "exact_ignored_test": TEST}
        with tempfile.TemporaryDirectory(prefix="nestlink-sdk-migration-private-", dir=os.environ["RUNNER_TEMP"]) as private:
            Path(private).chmod(0o700)
            slice_facts = run_slice(experiment, executable, Path(private))
        require(slice_facts["passed"], "production SDK DROP slice failed; retained exact-source receipts/logs are authoritative")
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        cleanup = experiment.cleanup_processes()
        if cleanup:
            failure = (failure or "") + "; process cleanup: " + "; ".join(cleanup)
        try:
            after = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
            require(before is not None, "missing initial source snapshot")
            EVIDENCE.require_unchanged_source(before, after)
        except BaseException as error:
            failure = (failure or "") + "; source integrity: " + str(error)
        receipt = {"schema_version": 1, "kind": "nestlink-production-sdk-automatic-relay-drop", "passed": failure is None, "failure": failure,
            "production_migration_protocol_exercised": bool(slice_facts and slice_facts.get("passed")), "w14_complete": False, "ac22_passed": False,
            "build_provenance": {**identity, "source_before": before, "source_after": after, "executable": executable_record},
            "execution_provenance": {"environment": "github-hosted-linux-owned-network-namespace", "process_uid": os.getuid(),
                "runner_namespace": os.readlink("/proc/self/ns/net"), "trials": TRIALS, "exact_ignored_test": TEST},
            "slice": slice_facts, "commands": commands, "processes": processes, "files": EVIDENCE.artifact_files(output),
            "limitations": ["Controlled loopback relay DROP exercises production SDK, four signed phases, original inner Quinn connection and real approved OS FileRead",
                "Network p95 <=3s is unchanged and measured conservatively from before fault-controller dispatch to all fresh file bytes verified",
                "No public NAT, independent relay-process crash, native Windows input/media presentation, interactive p95 <=5s, adaptive PMTU or full cancellation/poller matrix qualification"]}
        (output / "production-sdk-migration-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"passed": receipt["passed"], "failure": failure, "evidence": str(output)}, indent=2), flush=True)
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
