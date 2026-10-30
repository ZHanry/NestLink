#!/usr/bin/env python3
"""Run a bounded production QUIC/FileRead slice on GitHub-hosted Linux only.

Two ordinary-user Rust processes run in distinct owned network namespaces.
Linux veth/netem and tcpdump provide actual packet/fault evidence. This does
not implement or certify NAT, relay routing, installed-product or AC04 gates.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nestlink_network_evidence", ROOT / "scripts/network-rewrite-ci.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing existing Actions evidence helpers")
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
CASES = ("success", "blackhole", "cancel")


def require(value: bool, reason: str) -> None:
    if not value:
        raise RuntimeError(reason)


def pcap_packets(path: Path) -> dict:
    """Validate the complete classic-pcap container, including packet bodies."""
    data = path.read_bytes()
    require(len(data) >= 24, "missing pcap global header")
    byte_orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                   b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    order = byte_orders.get(data[:4])
    require(order is not None, "unexpected pcap encoding")
    major, minor, _, _, snaplen, linktype = struct.unpack(order + "HHIIII", data[4:24])
    require((major, minor) == (2, 4) and snaplen >= 65535 and linktype == 1,
            "capture must retain complete Ethernet frames")
    offset = 24
    count = 0
    initials = 0
    while offset < len(data):
        require(len(data) - offset >= 16, "truncated pcap packet header")
        _, _, included, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        require(included == original and 0 < included <= snaplen, "truncated or invalid captured packet")
        require(offset + included <= len(data), "truncated pcap packet body")
        packet = data[offset:offset + included]
        if len(packet) >= 42 and packet[12:14] == b"\x08\x00":
            ip = packet[14:]
            header = (ip[0] & 15) * 4
            if ip[0] >> 4 == 4 and header >= 20 and len(ip) >= header + 8 and ip[9] == 17 and ip[16:20] == bytes((10, 201, 0, 2)):
                udp = ip[header:]
                payload = udp[8:]
                if int.from_bytes(udp[2:4], "big") == 4433 and len(payload) >= 1200 and payload[0] & 0xc0 == 0xc0:
                    version = int.from_bytes(payload[1:5], "big")
                    packet_type = payload[0] & 0x30
                    if (version == 1 and packet_type == 0) or (version == 0x6b3343cf and packet_type == 0x10):
                        initials += 1
        offset += included
        count += 1
    require(count > 0, "no packets captured; socket coverage cannot be claimed")
    require(initials > 0, "no full-sized QUIC Initial reached the host capture; ARP failure is not QUIC evidence")
    return {"complete_packets": count, "quic_initial_datagrams_to_host": initials}


class Experiment:
    def __init__(self, output: Path, commands: list[dict], processes: list[dict]):
        self.output = output
        self.commands = commands
        self.processes = processes
        self.sequence = 0
        self.active: list[tuple[subprocess.Popen, object, dict]] = []

    def command(self, label: str, argv: list[str], timeout: int = 60,
                accepted: tuple[int, ...] = (0,)) -> dict:
        self.sequence += 1
        result = EVIDENCE.run_command(f"{self.sequence:03d}-{label}", argv, ROOT,
                                      self.output, self.commands, timeout)
        result["expected_return_codes"] = list(accepted)
        require(result["return_code"] in accepted and not result["timed_out"],
                label + " failed; retained command log is authoritative")
        return result

    def launch(self, label: str, argv: list[str], environment: dict | None = None) -> tuple:
        path = self.output / (label + ".log")
        log = path.open("wb")
        record = {"name": label, "argv": argv, "log": path.name,
                  "started_at": EVIDENCE.utc_now(), "return_code": None,
                  "pid": None, "forced_cleanup": False}
        self.processes.append(record)
        try:
            process = subprocess.Popen(argv, cwd=ROOT, env=environment, stdout=log,
                                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                       start_new_session=True)
        except BaseException:
            log.close()
            raise
        record["pid"] = process.pid
        entry = (process, log, record)
        self.active.append(entry)
        return entry

    def finish(self, entry: tuple, timeout: float = 8, accepted: tuple[int, ...] = (0,)) -> None:
        process, log, record = entry
        record["expected_return_codes"] = list(accepted)
        try:
            record["return_code"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            raise RuntimeError(record["name"] + " exceeded its process deadline")
        finally:
            if process.poll() is not None:
                log.close()
                record["finished_at"] = EVIDENCE.utc_now()
                record["log_sha256"] = EVIDENCE.sha256_file(self.output / record["log"])
                if entry in self.active:
                    self.active.remove(entry)
        require(record["return_code"] in accepted, record["name"] + " failed; inspect its retained log")
        if record["name"].endswith(("-host", "-client", "-prepare")):
            content = (self.output / record["log"]).read_text(errors="replace")
            require("test result: ok. 1 passed; 0 failed; 0 ignored" in content,
                    record["name"] + " did not execute exactly one requested Rust role")

    def stop_capture(self, entry: tuple) -> None:
        process, _, record = entry
        require(process.poll() is None, "tcpdump terminated before experiment completion")
        self.command(record["name"] + "-interrupt", ["sudo", "-n", "kill", "-INT", "--", "-" + str(process.pid)])
        self.finish(entry, 5, (0, 130))
        content = (self.output / record["log"]).read_text(errors="replace")
        require("0 packets dropped by kernel" in content, "capture lost kernel packets")

    def cleanup_processes(self) -> list[str]:
        failures = []
        for entry in list(reversed(self.active)):
            process, log, record = entry
            record["forced_cleanup"] = True
            # A process may exit between poll and kill. ESRCH is acceptable only
            # when a subsequent wait actually reaps it. A failed TERM must not
            # skip KILL or discard the still-live process handle.
            for requested_signal in ("TERM", "KILL"):
                if process.poll() is not None:
                    break
                try:
                    self.command(record["name"] + "-cleanup-" + requested_signal.lower(),
                                 ["sudo", "-n", "kill", "-" + requested_signal, "--", "-" + str(process.pid)],
                                 accepted=(0, 1))
                except BaseException as error:
                    failures.append(record["name"] + " signal " + requested_signal + ": " + str(error))
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    continue
                except BaseException as error:
                    failures.append(record["name"] + " wait: " + str(error))
            if process.poll() is not None:
                record["return_code"] = process.returncode
                record["finished_at"] = EVIDENCE.utc_now()
                log.close()
                record["log_sha256"] = EVIDENCE.sha256_file(self.output / record["log"])
                self.active.remove(entry)
            else:
                failures.append(record["name"] + ": process remains alive after TERM/KILL; handle retained for cleanup retry")
        return failures


def marker(root: Path, name: str, processes: tuple = (), timeout: float = 8) -> None:
    deadline = time.monotonic() + timeout
    while not (root / name).is_file():
        for process, _, record in processes:
            require(process.poll() is None, record["name"] + " exited before " + name)
        require(time.monotonic() < deadline, "missing real execution marker: " + name)
        time.sleep(0.02)
    require((root / name).read_bytes() == b"observed\n", "invalid execution marker: " + name)


def write_marker(root: Path, name: str) -> None:
    pending = root / (name + ".pending")
    pending.write_bytes(b"observed\n")
    pending.rename(root / name)


def namespace_argv(namespace: str, executable: Path, role: str, fixture: Path, case: str) -> list[str]:
    # Neither credentials nor seeds occur in argv/environment. Each role reads
    # its own seed from the private, non-artifact fixture directory.
    variables = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                 "GITHUB_REPOSITORY": EVIDENCE.REPOSITORY, "RUNNER_TEMP": os.environ["RUNNER_TEMP"],
                 "NESTLINK_NETWORK_FIXTURE": str(fixture), "NESTLINK_NETWORK_CASE": case,
                 "RUST_BACKTRACE": "1"}
    return ["sudo", "-n", "ip", "netns", "exec", namespace,
            "setpriv", "--reuid", str(os.getuid()), "--regid", str(os.getgid()), "--clear-groups",
            "--", "env", *[name + "=" + value for name, value in variables.items()],
            str(executable), "--ignored", "--exact", role + "_process", "--nocapture", "--test-threads=1"]


def case(experiment: Experiment, executable: Path, name: str, private: Path) -> dict:
    record = {"name": name, "started_at": EVIDENCE.utc_now(), "passed": False,
              "endpoint_processes": 2, "relay_processes": 0, "fault": None,
              "failure": None, "cleanup_failures": []}
    fixture = private / name
    fixture.mkdir(mode=0o700)
    for role in ("host", "controller"):
        path = fixture / (role + ".seed")
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
    payload = secrets.token_bytes(262_144)
    (fixture / "payload.bin").write_bytes(payload)
    (fixture / "payload.sha256").write_bytes(hashlib.sha256(payload).digest())
    record["source_file"] = {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
    suffix = secrets.token_hex(5)
    controller_ns, host_ns = "nl-" + suffix + "-c", "nl-" + suffix + "-h"
    controller_link, host_link = "nc" + suffix, "nh" + suffix
    namespaces: list[str] = []
    namespace_ids: dict[str, str] = {}
    mac_addresses: dict[str, str] = {}
    link_created = False
    capture = None
    try:
        for namespace in (controller_ns, host_ns):
            experiment.command(name + "-namespace-add", ["sudo", "-n", "ip", "netns", "add", namespace])
            namespaces.append(namespace)
        experiment.command(name + "-veth-add", ["sudo", "-n", "ip", "link", "add", controller_link,
                                                "type", "veth", "peer", "name", host_link])
        link_created = True
        for namespace, interface, address in ((controller_ns, controller_link, "10.201.0.1/30"),
                                               (host_ns, host_link, "10.201.0.2/30")):
            experiment.command(name + "-veth-move", ["sudo", "-n", "ip", "link", "set", interface, "netns", namespace])
            for operation in (["link", "set", "lo", "up"], ["address", "add", address, "dev", interface],
                              ["link", "set", interface, "up"]):
                experiment.command(name + "-interface", ["sudo", "-n", "ip", "-n", namespace, *operation])
            facts = experiment.command(name + "-namespace-facts", ["sudo", "-n", "ip", "netns", "exec", namespace,
                                                                    "readlink", "/proc/self/ns/net"])
            observed_ids = re.findall(r"^net:\[[0-9]+\]$", (experiment.output / facts["log"]).read_text(), re.MULTILINE)
            require(len(observed_ids) == 1, "missing actual kernel namespace identity")
            namespace_ids[namespace] = observed_ids[0]
            link_facts = experiment.command(name + "-link-facts", ["sudo", "-n", "ip", "-j", "-n", namespace, "link", "show", "dev", interface])
            links = json.loads((experiment.output / link_facts["log"]).read_text().splitlines()[-1])
            require(len(links) == 1 and links[0].get("ifname") == interface, "unexpected veth facts")
            address = links[0].get("address", "")
            require(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", address) is not None, "invalid veth MAC address")
            mac_addresses[namespace] = address
            experiment.command(name + "-routes", ["sudo", "-n", "ip", "-n", namespace, "-details", "route", "show"])
        require(len(set(namespace_ids.values())) == 2 and os.readlink("/proc/self/ns/net") not in namespace_ids.values(),
                "endpoint namespaces must be distinct from each other and the runner")
        # Resolve L2 before loss injection. Otherwise netem may drop ARP replies
        # and turn a claimed QUIC blackhole into an unrelated neighbor failure.
        for namespace, interface, peer, peer_address in (
                (controller_ns, controller_link, host_ns, "10.201.0.2"),
                (host_ns, host_link, controller_ns, "10.201.0.1")):
            experiment.command(name + "-static-neighbor", ["sudo", "-n", "ip", "-n", namespace, "neigh", "replace",
                peer_address, "lladdr", mac_addresses[peer], "nud", "permanent", "dev", interface])
            neighbor_facts = experiment.command(name + "-neighbor-facts", ["sudo", "-n", "ip", "-j", "-n", namespace, "neigh", "show", "dev", interface])
            neighbors = json.loads((experiment.output / neighbor_facts["log"]).read_text().splitlines()[-1])
            require(len(neighbors) == 1 and neighbors[0].get("dst") == peer_address
                    and neighbors[0].get("lladdr") == mac_addresses[peer] and "PERMANENT" in neighbors[0].get("state", []),
                    "static peer neighbor was not installed before fault injection")
        record["topology"] = {"controller_namespace": controller_ns, "host_namespace": host_ns,
                              "kernel_namespace_ids": namespace_ids,
                              "veth_mac_addresses": mac_addresses, "static_neighbors_verified_before_netem": True,
                              "controller_address": "10.201.0.1/30", "host_address": "10.201.0.2/30",
                              "host_network_namespace": os.readlink("/proc/self/ns/net"),
                              "external_network_route": False, "nat": False}
        pcap = experiment.output / (name + ".pcap")
        capture = experiment.launch(name + "-capture", ["sudo", "-n", "ip", "netns", "exec", host_ns,
            "tcpdump", "-i", host_link, "-nn", "-s", "0", "-U", "-Z", pwd.getpwuid(os.getuid()).pw_name,
            "-w", str(pcap), "udp", "port", "4433"])
        deadline = time.monotonic() + 3
        while "listening on" not in (experiment.output / (name + "-capture.log")).read_text(errors="replace"):
            require(capture[0].poll() is None and time.monotonic() < deadline, "tcpdump did not become ready")
            time.sleep(0.02)
        environment = dict(os.environ, NESTLINK_NETWORK_FIXTURE=str(fixture), NESTLINK_NETWORK_CASE=name)
        prepare = experiment.launch(name + "-prepare", [str(executable), "--ignored", "--exact", "prepare_fixture",
                                                       "--nocapture", "--test-threads=1"], environment)
        experiment.finish(prepare, 3)
        if name == "blackhole":
            experiment.command(name + "-netem", ["sudo", "-n", "ip", "netns", "exec", host_ns,
                                                 "tc", "qdisc", "add", "dev", host_link, "root", "netem", "loss", "100%"])
            record["fault"] = {"kind": "kernel_netem", "direction": "host_egress", "loss_percent": 100,
                               "installed_before_connect": True}
        host = experiment.launch(name + "-host", namespace_argv(host_ns, executable, "host", fixture, name))
        marker(fixture, "host-ready", (host,))
        client = experiment.launch(name + "-client", namespace_argv(controller_ns, executable, "client", fixture, name))
        if name != "blackhole":
            for observed in ("host-authorized", "client-authorized", "ungranted-input-rejected", "client-first-chunk"):
                marker(fixture, observed, (host, client))
            if name == "cancel":
                experiment.command(name + "-netem", ["sudo", "-n", "ip", "netns", "exec", host_ns,
                    "tc", "qdisc", "add", "dev", host_link, "root", "netem", "loss", "100%"])
                record["fault"] = {"kind": "kernel_netem", "direction": "host_egress", "loss_percent": 100,
                                   "installed_after_verified_first_chunk": True}
                write_marker(fixture, "fault-installed")
                marker(fixture, "client-next-blocked", (host,))
                marker(fixture, "client-cancelled", (host,))
                record["cancellation"] = "production stop signal unblocks a verified pending FileRead next request"
            else:
                marker(fixture, "client-complete", (host,))
                received = fixture / "received.bin"
                require(received.read_bytes() == payload, "remote FileRead bytes differ from actual source file")
                shutil.copyfile(received, experiment.output / "success-received.bin")
                record["verified_file_bytes"] = len(payload)
            write_marker(fixture, "host-stop")
        experiment.finish(client, 8)
        experiment.finish(host, 8)
        for observed in ("host-finished", "client-finished"):
            marker(fixture, observed, timeout=1)
        if name == "blackhole":
            marker(fixture, "client-blackhole-rejected", timeout=1)
            phases = [phase for phase in ("host-no-incoming", "host-handshake-rejected") if (fixture / phase).is_file()]
            require(len(phases) == 1, "blackhole host must report its actual pre-authorization failure phase")
            record["host_failure_phase"] = phases[0]
        fault_facts = experiment.command(name + "-fault-facts", ["sudo", "-n", "ip", "netns", "exec", host_ns,
                                                                "tc", "-s", "qdisc", "show", "dev", host_link])
        if name in ("blackhole", "cancel"):
            content = (experiment.output / fault_facts["log"]).read_text()
            dropped = re.findall(r"\bdropped ([0-9]+)\b", content)
            require("netem" in content and "loss 100%" in content and any(int(count) > 0 for count in dropped),
                    "kernel did not record actual packet drops for the injected blackhole")
            record["fault"]["kernel_dropped_packets"] = sum(int(count) for count in dropped)
        experiment.stop_capture(capture)
        capture = None
        record["capture_facts"] = pcap_packets(pcap)
        experiment.command(name + "-capture-decode", ["tcpdump", "-nn", "-tt", "-r", str(pcap)])
        record["passed"] = True
    except BaseException as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        if capture is not None and capture in experiment.active and capture[0].poll() is None:
            try:
                experiment.stop_capture(capture)
            except BaseException as error:
                record["cleanup_failures"].append("capture: " + str(error))
        record["cleanup_failures"].extend(experiment.cleanup_processes())
        for namespace in reversed(namespaces):
            try:
                facts = experiment.command(name + "-remaining-processes", ["sudo", "-n", "ip", "netns", "pids", namespace])
                lines = [line.strip() for line in (experiment.output / facts["log"]).read_text().splitlines()[1:] if line.strip()]
                require(all(line.isdigit() for line in lines), "unrecognized namespace process inventory")
                if lines:
                    record["cleanup_failures"].append(namespace + ": leftover namespace processes required forced cleanup: " + ",".join(lines))
                    experiment.command(name + "-leftover-process-kill", ["sudo", "-n", "kill", "-KILL", "--", *lines], accepted=(0, 1))
                    deadline = time.monotonic() + 3
                    while True:
                        remaining = experiment.command(name + "-namespace-recheck", ["sudo", "-n", "ip", "netns", "pids", namespace])
                        output_lines = (experiment.output / remaining["log"]).read_text().splitlines()[1:]
                        if not any(line.strip() for line in output_lines):
                            break
                        require(time.monotonic() < deadline, "owned namespace still contains processes after forced cleanup")
                        time.sleep(0.05)
                experiment.command(name + "-namespace-delete", ["sudo", "-n", "ip", "netns", "delete", namespace])
            except BaseException as error:
                record["cleanup_failures"].append(namespace + ": " + str(error))
        record["cleanup_failures"].extend(experiment.cleanup_processes())
        if link_created:
            # On partial setup the link may still be in the runner namespace.
            # A fully moved/deleted pair no longer exists there (exit code 1).
            for interface in (controller_link, host_link):
                try:
                    found = experiment.command(name + "-remaining-veth", ["ip", "link", "show", "dev", interface], accepted=(0, 1))
                    if found["return_code"] == 0:
                        experiment.command(name + "-veth-delete", ["sudo", "-n", "ip", "link", "delete", interface])
                except BaseException as error:
                    record["cleanup_failures"].append(interface + ": " + str(error))
        record["passed"] = record["passed"] and not record["cleanup_failures"]
        record["finished_at"] = EVIDENCE.utc_now()
        (experiment.output / (name + "-receipt.json")).write_text(json.dumps(record, indent=2) + "\n")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = EVIDENCE.validate_actions_environment(os.environ)
    require(sys.platform == "linux" and identity["runner"]["os"] == "Linux", "Linux GitHub-hosted runner required")
    require(os.getuid() != 0, "build and endpoint roles must run as the ordinary runner user")
    require(ROOT.resolve() == Path(os.environ["GITHUB_WORKSPACE"]).resolve(), "source must be GITHUB_WORKSPACE")
    output = EVIDENCE.validate_output_path(args.output, ROOT, Path(os.environ["RUNNER_TEMP"]))
    output.mkdir(parents=True)
    commands: list[dict] = []
    processes: list[dict] = []
    experiments: list[dict] = []
    before = after = executable_record = None
    failure = None
    experiment = Experiment(output, commands, processes)
    try:
        before = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
        EVIDENCE.require_unchanged_source(before, before)
        experiment.command("install-network-tool-index", ["sudo", "-n", "apt-get", "update"], 180)
        experiment.command("install-network-tools", ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends",
                                                       "iproute2", "tcpdump", "util-linux"], 180)
        for name, argv in (("rust-version", ["rustc", "--version", "--verbose"]), ("cargo-version", ["cargo", "--version"]),
                           ("kernel", ["uname", "-a"]), ("ip-version", ["ip", "-Version"]),
                           ("tc-version", ["tc", "-Version"]), ("tcpdump-version", ["tcpdump", "--version"]),
                           ("setpriv-version", ["setpriv", "--version"])):
            experiment.command(name, argv)
        experiment.command("lint-process-roles", ["cargo", "clippy", "-p", "nestlink-remote", "--locked",
            "--test", "network_socket", "--", "-D", "warnings"], 1200)
        built = experiment.command("compile-roles", ["cargo", "test", "-p", "nestlink-remote", "--locked",
            "--test", "network_socket", "--no-run", "--message-format=json"], 1200)
        binaries = []
        for line in (output / built["log"]).read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "network_socket" and item.get("profile", {}).get("test") and item.get("executable"):
                binaries.append(Path(item["executable"]).resolve())
        require(len(binaries) == 1 and binaries[0].is_file(), "expected exactly one freshly built process-role executable")
        executable = binaries[0]
        executable_record = {"path": executable.relative_to(ROOT).as_posix(), "sha256": EVIDENCE.sha256_file(executable),
                             "source_revision": identity["source_revision"], "dependency_lock_sha256": before["dependency_lock_sha256"]}
        with tempfile.TemporaryDirectory(prefix="nestlink-network-private-", dir=os.environ["RUNNER_TEMP"]) as private:
            Path(private).chmod(0o700)
            for name in CASES:
                experiments.append(case(experiment, executable, name, Path(private)))
        require(len(experiments) == len(CASES) and all(item["passed"] for item in experiments),
                "one or more production socket experiments failed; inspect every retained case receipt")
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        cleanup_errors = experiment.cleanup_processes()
        if cleanup_errors:
            failure = (failure or "") + "; process cleanup: " + "; ".join(cleanup_errors)
        try:
            after = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
            if before is None:
                raise RuntimeError("missing original exact-source snapshot")
            EVIDENCE.require_unchanged_source(before, after)
        except BaseException as error:
            failure = (failure or "") + "; source integrity: " + str(error)
        files = EVIDENCE.artifact_files(output)
        receipt = {
            "schema_version": 1, "kind": "nestlink-production-socket-experiment", "passed": failure is None,
            "failure": failure, "ac04_passed": False,
            "scope": "partial production socket development experiment; two endpoints, zero relays, no NAT",
            "build_provenance": {**identity, "source_before": before, "source_after": after, "executable": executable_record},
            "execution_provenance": {**identity, "environment": "github-hosted-linux-network-namespaces",
                                     "endpoint_uid": os.getuid(), "host_namespace": os.readlink("/proc/self/ns/net")},
            "cases": experiments, "commands": commands, "processes": processes, "files": files,
            "limitations": ["No two-relay or NAT topology, real LAN or target device qualification",
                            "No SDK signaling/discovery, TLS/WSS fallback, new network routing or migration qualification",
                            "FileRead uses production client/server with a fixture adapter approving one real file",
                            "No screen capture, OS input injection, installation, performance, 24h or UU acceptance",
                            "Environment guards prevent accidental local execution; GitHub run/job/artifact records remain authoritative"],
        }
        (output / "network-socket-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"passed": receipt["passed"], "failure": failure, "evidence": str(output)}, indent=2), flush=True)
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
