#!/usr/bin/env python3
"""Actions-only three-process opaque QUIC slice behind two actual kernel NATs.

This reuses the socket experiment's process/cleanup/provenance helpers. It does
not qualify ICE hole punching, business endpoint proof, TUN or external NAT.
"""
from __future__ import annotations
import argparse
import importlib.util
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
SPEC = importlib.util.spec_from_file_location("nestlink_socket_experiment", ROOT / "scripts/network-rewrite-socket.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing existing socket experiment helpers")
SOCKET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SOCKET)
EVIDENCE, require = SOCKET.EVIDENCE, SOCKET.require
CASES = ("success", "blackhole", "cancel")
MARKER = b"NestLink owned routed opaque payload 1280"


def capture_facts(path: Path, source: str, destination: str, source_port: int, destination_port: int) -> dict:
    """Read complete Ethernet/IPv4/UDP records; reject IP or capture truncation."""
    data = path.read_bytes()
    orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    require(len(data) >= 24 and data[:4] in orders, "missing classic pcap header")
    order = orders[data[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(order + "HHIIII", data[4:24])
    require((major, minor) == (2, 4) and snaplen >= 65535 and linktype == 1, "complete Ethernet capture required")
    offset, packets, forward, reverse, initials, maximum = 24, 0, 0, 0, 0, 0
    expected = (source, destination, source_port, destination_port)
    reflected = (destination, source, destination_port, source_port)
    while offset < len(data):
        require(len(data) - offset >= 16, "truncated pcap packet header")
        _, _, included, original = struct.unpack(order + "IIII", data[offset:offset + 16])
        offset += 16
        require(included == original and 0 < included <= snaplen and offset + included <= len(data), "truncated captured frame")
        packet = data[offset:offset + included]
        offset += included
        packets += 1
        require(len(packet) >= 42 and packet[12:14] == b"\x08\x00", "unexpected non-IPv4 UDP capture")
        ip = packet[14:]
        header = (ip[0] & 15) * 4
        total = int.from_bytes(ip[2:4], "big")
        require(ip[0] >> 4 == 4 and header >= 20 and header + 8 <= total <= len(ip) and ip[9] == 17, "invalid IPv4 UDP framing")
        require(int.from_bytes(ip[6:8], "big") & 0x3fff == 0, "implicit IP fragmentation cannot qualify the route")
        udp = ip[header:total]
        require(int.from_bytes(udp[4:6], "big") == len(udp), "incomplete UDP datagram")
        payload = udp[8:]
        require(0 < len(payload) <= 1200, "physical UDP payload exceeded the frozen 1200-byte outer budget")
        require(MARKER not in payload, "owned application plaintext appeared on physical relay traffic")
        maximum = max(maximum, len(payload))
        flow = (".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20])),
                int.from_bytes(udp[:2], "big"), int.from_bytes(udp[2:4], "big"))
        require(flow in (expected, reflected), "unexpected flow in owned QUIC capture")
        if flow == expected:
            forward += 1
            if len(payload) >= 1200 and payload[0] & 0xc0 == 0xc0:
                version, kind = int.from_bytes(payload[1:5], "big"), payload[0] & 0x30
                if (version == 1 and kind == 0) or (version == 0x6b3343cf and kind == 0x10):
                    initials += 1
        else:
            reverse += 1
    require(packets > 0 and forward > 0 and initials > 0, "missing full-sized outer QUIC Initial on actual NAT leg")
    return {"packets": packets, "forward_datagrams": forward, "reverse_datagrams": reverse,
            "full_outer_quic_initials": initials, "maximum_udp_payload_bytes": maximum,
            "ip_fragmentation_observed": False, "owned_plaintext_marker_observed": False,
            "expected_forward_flow": list(expected)}


def output_json(experiment: SOCKET.Experiment, record: dict):
    return json.loads((experiment.output / record["log"]).read_text().splitlines()[-1])


def finish_role(experiment: SOCKET.Experiment, entry: tuple, timeout: float = 10, namespace: str | None = None) -> None:
    experiment.finish(entry, timeout)
    text = (experiment.output / entry[2]["log"]).read_text(errors="replace")
    require("test result: ok. 1 passed; 0 failed; 0 ignored" in text, "requested Rust role did not execute exactly once")
    if namespace is not None:
        observed = re.findall(r'namespace="(net:\[[0-9]+\])" pid=([0-9]+) Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)', text)
        require(len(observed) == 1 and observed[0][0] == namespace
                and all(int(uid) == os.getuid() for uid in observed[0][2:]),
                "actual process did not attest the expected namespace and ordinary UID")
        entry[2]["observed_kernel_namespace"] = observed[0][0]
        entry[2]["observed_role_pid"] = int(observed[0][1])
        entry[2]["observed_uid"] = int(observed[0][2])


def nat_facts(experiment: SOCKET.Experiment, name: str, namespace: str, source: str,
              relay: str, local_port: int, relay_port: int, public: str, translated: int) -> dict:
    record = experiment.command(name + "-conntrack", ["sudo", "-n", "ip", "netns", "exec", namespace,
        "conntrack", "-L", "-p", "udp", "-s", source, "-d", relay, "-o", "extended"])
    text = (experiment.output / record["log"]).read_text()
    tuples = re.findall(r"\bsrc=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)", text)
    original = (source, relay, str(local_port), str(relay_port))
    reply = (relay, public, str(relay_port), str(translated))
    require(original in tuples and reply in tuples, "actual conntrack tuple does not prove configured source address/port NAT")
    counters = experiment.command(name + "-nat-counters", ["sudo", "-n", "ip", "netns", "exec", namespace,
        "iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v", "-x"])
    rows = re.findall(r"^\s*(\d+)\s+(\d+)\s+SNAT\s", (experiment.output / counters["log"]).read_text(), re.MULTILINE)
    require(len(rows) == 1 and int(rows[0][0]) > 0, "kernel SNAT rule matched no actual packets")
    return {"original_tuple": list(original), "reply_tuple": list(reply),
            "nat_rule_packets": int(rows[0][0]), "nat_rule_bytes": int(rows[0][1]),
            "conntrack_log": record["log"], "counter_log": counters["log"]}


def case(experiment: SOCKET.Experiment, executable: Path, name: str, private: Path) -> dict:
    facts = {"name": name, "passed": False, "failure": None, "started_at": EVIDENCE.utc_now(),
             "endpoint_processes": 2, "relay_processes": 1, "kernel_nat_namespaces": 2,
             "business_endpoint_proof_exercised": False, "cleanup_failures": []}
    fixture = private / name
    fixture.mkdir(mode=0o700)
    for role in ("first", "second", "relay", "authority"):
        path = fixture / (role + ".seed")
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
    (fixture / "payload.bin").write_bytes(secrets.token_bytes(65_536))
    token = secrets.token_hex(4)
    ns = {role: "nr-" + token + "-" + role for role in ("first", "second", "relay", "nat1", "nat2")}
    namespaces, links, captures = [], [], []
    endpoints = {}
    kernel_ids = {}
    try:
        for role, namespace in ns.items():
            experiment.command(name + "-namespace-add", ["sudo", "-n", "ip", "netns", "add", namespace])
            namespaces.append(namespace)
            experiment.command(name + "-loopback", ["sudo", "-n", "ip", "-n", namespace, "link", "set", "lo", "up"])
            record = experiment.command(name + "-namespace-id", ["sudo", "-n", "ip", "netns", "exec", namespace, "readlink", "/proc/self/ns/net"])
            observed = re.findall(r"^net:\[[0-9]+\]$", (experiment.output / record["log"]).read_text(), re.MULTILINE)
            require(len(observed) == 1, "missing actual kernel namespace identity")
            kernel_ids[role] = observed[0]
        require(len(set(kernel_ids.values())) == 5 and os.readlink("/proc/self/ns/net") not in kernel_ids.values(), "five isolated kernel namespaces required")
        specs = (("first", "f", "10.210.1.2", "nat1", "l1", "10.210.1.1"),
                 ("nat1", "w1", "10.211.1.2", "relay", "r1", "10.211.1.1"),
                 ("second", "s", "10.210.2.2", "nat2", "l2", "10.210.2.1"),
                 ("nat2", "w2", "10.211.2.2", "relay", "r2", "10.211.2.1"))
        for left, tag1, ip1, right, tag2, ip2 in specs:
            a, b = "v" + token + tag1, "v" + token + tag2
            experiment.command(name + "-veth-add", ["sudo", "-n", "ip", "link", "add", a, "type", "veth", "peer", "name", b])
            links.extend((a, b))
            macs = {}
            for role, tag, interface, address in ((left, tag1, a, ip1), (right, tag2, b, ip2)):
                namespace = ns[role]
                endpoints[tag] = (namespace, interface, address)
                experiment.command(name + "-veth-move", ["sudo", "-n", "ip", "link", "set", interface, "netns", namespace])
                for argv in (["address", "add", address + "/30", "dev", interface], ["link", "set", interface, "mtu", "1280"], ["link", "set", interface, "up"]):
                    experiment.command(name + "-interface", ["sudo", "-n", "ip", "-n", namespace, *argv])
                experiment.command(name + "-offloads-disable", ["sudo", "-n", "ip", "netns", "exec", namespace,
                    "ethtool", "-K", interface, "gro", "off", "gso", "off", "tso", "off", "tx-udp-segmentation", "off"])
                offload = experiment.command(name + "-offload-facts", ["sudo", "-n", "ip", "netns", "exec", namespace, "ethtool", "-k", interface])
                offload_text = (experiment.output / offload["log"]).read_text()
                for feature in ("generic-receive-offload", "generic-segmentation-offload", "tx-udp-segmentation"):
                    require(re.search(r"^" + feature + r": off\b", offload_text, re.MULTILINE) is not None, "capture offload remains enabled")
                link = output_json(experiment, experiment.command(name + "-link-facts", ["sudo", "-n", "ip", "-j", "-n", namespace, "link", "show", "dev", interface]))
                require(len(link) == 1 and link[0].get("mtu") == 1280, "physical link MTU does not match budget")
                macs[role] = link[0]["address"]
            for role, interface, peer, address in ((left, a, right, ip2), (right, b, left, ip1)):
                experiment.command(name + "-neighbor", ["sudo", "-n", "ip", "-n", ns[role], "neigh", "replace", address,
                    "lladdr", macs[peer], "nud", "permanent", "dev", interface])
        for role, gateway in (("first", "10.210.1.1"), ("second", "10.210.2.1")):
            experiment.command(name + "-endpoint-route", ["sudo", "-n", "ip", "-n", ns[role], "route", "add", "default", "via", gateway])
        for index in (1, 2):
            namespace = ns["nat" + str(index)]
            lan, wan = endpoints["l" + str(index)][1], endpoints["w" + str(index)][1]
            source, destination, public = f"10.210.{index}.2", f"10.211.{index}.1", f"10.211.{index}.2"
            port, remote, translated = 45000 + index, 4432 + index, 55000 + index
            prefix = ["sudo", "-n", "ip", "netns", "exec", namespace]
            experiment.command(name + "-forwarding-enable", [*prefix, "sysctl", "-w", "net.ipv4.ip_forward=1"])
            for rule in (["-P", "FORWARD", "DROP"],
                         ["-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                         ["-A", "FORWARD", "-i", lan, "-o", wan, "-p", "udp", "-s", source, "-d", destination,
                          "--sport", str(port), "--dport", str(remote), "-j", "ACCEPT"],
                         ["-t", "nat", "-A", "POSTROUTING", "-o", wan, "-p", "udp", "-s", source, "-d", destination,
                          "--sport", str(port), "--dport", str(remote), "-j", "SNAT", "--to-source", public + ":" + str(translated)]):
                experiment.command(name + "-owned-nat-rule", [*prefix, "iptables", *rule])
        experiment.command(name + "-relay-kernel-forwarding-off", ["sudo", "-n", "ip", "netns", "exec", ns["relay"], "sysctl", "-w", "net.ipv4.ip_forward=0"])
        for role, namespace in ns.items():
            routes = output_json(experiment, experiment.command(name + "-route-facts", ["sudo", "-n", "ip", "-j", "-n", namespace, "route", "show"]))
            if role not in ("first", "second"):
                require(not any(route.get("dst") == "default" for route in routes), "NAT/relay namespace has an external default route")
        facts["topology"] = {"namespaces": ns, "kernel_namespace_ids": kernel_ids, "runner_namespace": os.readlink("/proc/self/ns/net"),
                             "kernel_nat": "two independent fixed-source-port SNAT gateways", "link_mtu":1280,
                             "external_route":False,"relay_kernel_forwarding":False,"offloads_disabled":True}
        for tag in ("f", "s", "r1", "r2"):
            namespace, interface, _ = endpoints[tag]
            path = experiment.output / (name + "-" + tag + ".pcap")
            entry = experiment.launch(name + "-capture-" + tag, ["sudo", "-n", "ip", "netns", "exec", namespace,
                "tcpdump", "--immediate-mode", "-i", interface, "-nn", "-s", "0", "-U", "-Z", pwd.getpwuid(os.getuid()).pw_name, "-w", str(path), "udp"])
            captures.append((tag, path, entry))
            deadline = time.monotonic() + 3
            while "listening on" not in (experiment.output / entry[2]["log"]).read_text(errors="replace"):
                require(entry[0].poll() is None and time.monotonic() < deadline, "capture did not become ready")
                time.sleep(0.02)
        environment = dict(os.environ, NESTLINK_NETWORK_FIXTURE=str(fixture), NESTLINK_NETWORK_CASE=name)
        prepare = experiment.launch(name + "-prepare", [str(executable), "--ignored", "--exact", "prepare_fixture", "--nocapture", "--test-threads=1"], environment)
        finish_role(experiment, prepare, 3)
        relay = experiment.launch(name + "-relay", SOCKET.namespace_argv(ns["relay"], executable, "relay", fixture, name))
        SOCKET.marker(fixture, "relay-ready", (relay,))
        first = experiment.launch(name + "-first", SOCKET.namespace_argv(ns["first"], executable, "first", fixture, name))
        second = experiment.launch(name + "-second", SOCKET.namespace_argv(ns["second"], executable, "second", fixture, name))
        if name == "blackhole":
            for marker in ("relay-forwarding", "first-adjacency-ready", "second-adjacency-ready"):
                SOCKET.marker(fixture, marker, (relay, first, second))
            facts["fault"] = SOCKET.drop_egress(experiment, name, ns["relay"], endpoints["r1"][1], "relay_to_first_nat")
            facts["fault"]["installed_after_physical_adjacency_before_inner_quic"] = True
            SOCKET.write_marker(fixture, "inner-start")
        else:
            for marker in ("relay-forwarding", "first-established", "second-established", "first-payload-verified", "second-payload-verified"):
                SOCKET.marker(fixture, marker, (relay, first, second))
            if name == "cancel":
                SOCKET.marker(fixture, "second-request-received", (relay, first, second))
                facts["fault"] = SOCKET.drop_egress(experiment, name, ns["relay"], endpoints["r1"][1], "relay_to_first_nat")
                SOCKET.write_marker(fixture, "fault-installed")
                SOCKET.marker(fixture, "second-response-sent", (relay, first, second))
                SOCKET.marker(fixture, "first-read-blocked", (relay, first, second))
                facts["pending_read_observed_at_unix_ns"] = time.time_ns()
            SOCKET.write_marker(fixture, "stop-all")
        for role, entry in (("first", first), ("second", second), ("relay", relay)):
            finish_role(experiment, entry, namespace=kernel_ids[role])
        for role in ("first", "second", "relay"):
            role_facts = json.loads((fixture / (role + "-receipt.json")).read_text())
            require(role_facts.get("passed") is True and role_facts.get("released_udp_sockets") == (2 if role == "relay" else 1), "missing original physical socket release evidence")
            (experiment.output / (name + "-" + role + "-receipt.json")).write_text(json.dumps(role_facts, indent=2) + "\n")
            facts[role] = role_facts
        if name == "blackhole":
            require(not any((fixture / (role + "-established")).exists() for role in ("first", "second")), "blackholed route became established")
        if name == "cancel":
            SOCKET.marker(fixture, "first-read-cancelled", timeout=1)
            require(facts["first"].get("pending_read_cancelled") is True, "pending read was not cancelled")
        facts["nat_mappings"] = [nat_facts(experiment, name + "-nat" + str(index), ns["nat" + str(index)],
            f"10.210.{index}.2", f"10.211.{index}.1", 45000 + index, 4432 + index, f"10.211.{index}.2", 55000 + index) for index in (1, 2)]
        if name in ("blackhole", "cancel"):
            drop = experiment.command(name + "-drop-counters", ["sudo", "-n", "ip", "netns", "exec", ns["relay"], "tc", "-s", "qdisc", "show", "dev", endpoints["r1"][1]])
            text = (experiment.output / drop["log"]).read_text()
            drops = re.findall(r"\bdropped (\d+)\b", text)
            require("loss 100%" in text and any(int(value) > 0 for value in drops), "kernel did not drop actual QUIC traffic")
            facts["fault"]["kernel_dropped_packets"] = sum(map(int, drops))
        flows = {"f": ("10.210.1.2", "10.211.1.1", 45001, 4433), "s": ("10.210.2.2", "10.211.2.1", 45002, 4434),
                 "r1": ("10.211.1.2", "10.211.1.1", 55001, 4433), "r2": ("10.211.2.2", "10.211.2.1", 55002, 4434)}
        facts["captures"] = {}
        for tag, path, entry in list(captures):
            experiment.stop_capture(entry)
            captures.remove((tag, path, entry))
            facts["captures"][tag] = capture_facts(path, *flows[tag])
            if name != "blackhole":
                require(facts["captures"][tag]["reverse_datagrams"] > 0, "successful NAT leg lacks return packets")
        facts["passed"] = True
    except BaseException as error:
        facts["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        for _, _, entry in captures:
            if entry in experiment.active and entry[0].poll() is None:
                try:
                    experiment.stop_capture(entry)
                except BaseException as error:
                    facts["cleanup_failures"].append("capture: " + str(error))
        facts["cleanup_failures"].extend(experiment.cleanup_processes())
        for namespace in reversed(namespaces):
            try:
                record = experiment.command(name + "-remaining-pids", ["sudo", "-n", "ip", "netns", "pids", namespace])
                pids = [line.strip() for line in (experiment.output / record["log"]).read_text().splitlines()[1:] if line.strip()]
                require(all(pid.isdigit() for pid in pids), "unrecognized namespace process inventory")
                if pids:
                    facts["cleanup_failures"].append(namespace + ": process survived normal role completion")
                    experiment.command(name + "-force-owned-pids", ["sudo", "-n", "kill", "-KILL", "--", *pids], accepted=(0, 1))
                deadline = time.monotonic() + 3
                while True:
                    record = experiment.command(name + "-remaining-pids-recheck", ["sudo", "-n", "ip", "netns", "pids", namespace])
                    if not any(line.strip() for line in (experiment.output / record["log"]).read_text().splitlines()[1:]):
                        break
                    require(time.monotonic() < deadline, "namespace still owns processes after cleanup")
                    time.sleep(0.05)
                experiment.command(name + "-namespace-delete", ["sudo", "-n", "ip", "netns", "delete", namespace])
            except BaseException as error:
                facts["cleanup_failures"].append(namespace + ": " + str(error))
        for interface in links:
            try:
                record = experiment.command(name + "-remaining-veth", ["ip", "link", "show", "dev", interface], accepted=(0, 1))
                if record["return_code"] == 0:
                    experiment.command(name + "-partial-veth-delete", ["sudo", "-n", "ip", "link", "delete", interface])
            except BaseException as error:
                facts["cleanup_failures"].append(interface + ": " + str(error))
        facts["cleanup_failures"].extend(experiment.cleanup_processes())
        try:
            record = experiment.command(name + "-namespace-catalog-after-cleanup", ["ip", "netns", "list"])
            remaining = {line.split()[0] for line in (experiment.output / record["log"]).read_text().splitlines()[1:] if line.strip()}
            require(not remaining.intersection(namespaces), "owned namespace survived deletion")
            facts["owned_namespaces_removed"] = True
        except BaseException as error:
            facts["cleanup_failures"].append("namespace inventory: " + str(error))
        facts["passed"] = facts["passed"] and not facts["cleanup_failures"]
        facts["finished_at"] = EVIDENCE.utc_now()
        (experiment.output / (name + "-receipt.json")).write_text(json.dumps(facts, indent=2) + "\n")
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    identity = EVIDENCE.validate_actions_environment(os.environ)
    require(sys.platform == "linux" and identity["runner"]["os"] == "Linux" and os.getuid() != 0, "ordinary GitHub-hosted Linux runner required")
    require(ROOT.resolve() == Path(os.environ["GITHUB_WORKSPACE"]).resolve(), "source must be GITHUB_WORKSPACE")
    output = EVIDENCE.validate_output_path(args.output, ROOT, Path(os.environ["RUNNER_TEMP"]))
    output.mkdir(parents=True)
    commands, processes, cases = [], [], []
    experiment = SOCKET.Experiment(output, commands, processes)
    before = after = executable_record = None
    failure = None
    try:
        before = EVIDENCE.source_snapshot(ROOT, identity["source_revision"])
        EVIDENCE.require_unchanged_source(before, before)
        experiment.command("tool-index", ["sudo", "-n", "apt-get", "update"], 180)
        experiment.command("network-tools", ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends",
            "iproute2", "tcpdump", "util-linux", "iptables", "conntrack", "ethtool"], 180)
        for label, argv in (("rust-version", ["rustc", "--version", "--verbose"]), ("cargo-version", ["cargo", "--version"]),
                            ("kernel", ["uname", "-a"]), ("iptables-version", ["iptables", "--version"]),
                            ("conntrack-version", ["conntrack", "--version"]), ("offload-tool-version", ["ethtool", "--version"])):
            experiment.command(label, argv)
        experiment.command("capture-boundary-tests", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests/network", "-p", "test_routed_evidence.py"], 60)
        experiment.command("lint-routed-roles", ["cargo", "clippy", "-p", "nestlink-transport-quic", "--locked", "--test", "network_routed_socket", "--", "-D", "warnings"], 1200)
        built = experiment.command("build-routed-roles", ["cargo", "test", "-p", "nestlink-transport-quic", "--locked", "--test", "network_routed_socket", "--no-run", "--message-format=json"], 1200)
        binaries = []
        for line in (output / built["log"]).read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "network_routed_socket" and item.get("profile", {}).get("test") and item.get("executable"):
                binaries.append(Path(item["executable"]).resolve())
        require(len(binaries) == 1 and binaries[0].is_file(), "one freshly built routed test executable required")
        executable = binaries[0]
        executable_record = {"path":executable.relative_to(ROOT).as_posix(),"sha256":EVIDENCE.sha256_file(executable),
                             "source_revision":identity["source_revision"],"dependency_lock_sha256":before["dependency_lock_sha256"]}
        with tempfile.TemporaryDirectory(prefix="nestlink-routed-private-", dir=os.environ["RUNNER_TEMP"]) as private:
            Path(private).chmod(0o700)
            for name in CASES:
                cases.append(case(experiment, executable, name, Path(private)))
        require(len(cases) == len(CASES) and all(item["passed"] for item in cases), "one or more actual routed/NAT cases failed")
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
        receipt = {"schema_version":1,"kind":"nestlink-routed-kernel-nat-experiment","passed":failure is None,"failure":failure,
            "scope":"two endpoints, one authenticated relay, two actual Linux SNAT gateways; raw routed transport only",
            "ac04_passed":False,"ac10_passed":False,"ac11_passed":False,"ac13_passed":False,
            "build_provenance":{**identity,"source_before":before,"source_after":after,"executable":executable_record},
            "execution_provenance":{**identity,"environment":"github-hosted-linux-network-namespaces","process_uid":os.getuid()},
            "cases":cases,"commands":commands,"processes":processes,"files":EVIDENCE.artifact_files(output),
            "limitations":["No bilateral ICE/STUN nomination, consent or same-socket hole-punching qualification",
                "No public/external NAT, dual relay, multi-hop discovery or path migration",
                "Inner QUIC handshakes and complete 1280-byte IPv6-shaped payloads run through the production routed adapter; no TUN injection",
                "No business SessionPermit endpoint proof, actual FileRead worker or SDK signaling; framed bytes are transport checks only",
                "Physical captures show encrypted outer UDP and actual SNAT tuples; they do not decrypt inner Initial packets",
                "Credentials/seeds remain in an owned temporary fixture outside artifact output; no installed-device or full acceptance qualification"]}
        (output / "network-routed-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"passed":receipt["passed"],"failure":failure,"evidence":str(output)}, indent=2), flush=True)
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
