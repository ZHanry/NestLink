#!/usr/bin/env python3
"""Actions-only Quinn carrier replacement feasibility, never production migration.

Reuse the existing namespace/process/capture/provenance owners and both signed
NRD1 relay authorizations. Run the private libtest roles explicitly with
--ignored --exact; a normal test suite's ignored count is not execution evidence.
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
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nestlink_routed_experiment", ROOT / "scripts/network-rewrite-routed.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("missing existing routed experiment helpers")
ROUTED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROUTED)
SOCKET, EVIDENCE, require = ROUTED.SOCKET, ROUTED.EVIDENCE, ROUTED.require
PREFIX = "routed::migration_experiment::"
CASES = ("switch", "cancel")
ROLES = ("first", "second", "relay_a", "relay_b")


def namespace_argv(namespace: str, executable: Path, role: str, fixture: Path, case: str) -> list[str]:
    argv = SOCKET.namespace_argv(namespace, executable, role, fixture, case)
    argv[argv.index("--exact") + 1] = PREFIX + role + "_process"
    return argv


def finish_role(experiment: SOCKET.Experiment, entry: tuple, namespace: str | None = None) -> None:
    experiment.finish(entry, 10)
    text = (experiment.output / entry[2]["log"]).read_text(errors="replace")
    require("test result: ok. 1 passed; 0 failed; 0 ignored" in text, "explicit private Rust role did not execute exactly once")
    if namespace is not None:
        found = re.findall(r'namespace="(net:\[[0-9]+\])" pid=([0-9]+) Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)', text)
        require(len(found) == 1 and found[0][0] == namespace and all(int(uid) == os.getuid() for uid in found[0][2:]),
                "actual role namespace or ordinary UID differs from the owned fixture")
        entry[2]["observed_namespace"] = found[0][0]
        entry[2]["observed_role_pid"] = int(found[0][1])
        entry[2]["observed_uid"] = int(found[0][2])


def role_receipt(experiment: SOCKET.Experiment, fixture: Path, name: str, role: str) -> dict:
    facts = json.loads((fixture / (role + "-receipt.json")).read_text())
    require(facts.get("passed") is True and facts.get("explicit_close_completed") is True
            and facts.get("released_udp_sockets") == 2, "two original physical UDP release receipts are required per role")
    (experiment.output / (name + "-" + role + "-receipt.json")).write_text(json.dumps(facts, indent=2) + "\n")
    return facts


def case(experiment: SOCKET.Experiment, executable: Path, name: str, private: Path) -> dict:
    facts = {"name": name, "passed": False, "failure": None, "cleanup_failures": [], "started_at": EVIDENCE.utc_now()}
    fixture = private / name
    fixture.mkdir(mode=0o700)
    for role in (*ROLES, "authority"):
        path = fixture / (role + ".seed")
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
    (fixture / "payload.bin").write_bytes(ROUTED.MARKER + secrets.token_bytes(32_768 - len(ROUTED.MARKER)))
    token = secrets.token_hex(4)
    ns = {role: "nm-" + token + "-" + role for role in ROLES}
    namespaces, links, captures = [], [], []
    ids, interfaces = {}, {}
    active = {}
    try:
        for role, namespace in ns.items():
            experiment.command(name + "-namespace-add", ["sudo", "-n", "ip", "netns", "add", namespace])
            namespaces.append(namespace)
            experiment.command(name + "-loopback", ["sudo", "-n", "ip", "-n", namespace, "link", "set", "lo", "up"])
            result = experiment.command(name + "-namespace-id", ["sudo", "-n", "ip", "netns", "exec", namespace, "readlink", "/proc/self/ns/net"])
            observed = re.findall(r"^net:\[[0-9]+\]$", (experiment.output / result["log"]).read_text(), re.MULTILINE)
            require(len(observed) == 1, "missing kernel namespace identity")
            ids[role] = observed[0]
            experiment.command(name + "-forwarding-off", ["sudo", "-n", "ip", "netns", "exec", namespace, "sysctl", "-w", "net.ipv4.ip_forward=0"])
        require(len(set(ids.values())) == 4 and os.readlink("/proc/self/ns/net") not in ids.values(), "four isolated namespaces required")
        specs = (("first", "fa", "10.214.1.2", "relay_a", "af", "10.214.1.1", 1280, "5ms"),
                 ("second", "sa", "10.214.2.2", "relay_a", "as", "10.214.2.1", 1280, "5ms"),
                 ("first", "fb", "10.214.3.2", "relay_b", "bf", "10.214.3.1", 1450, "35ms"),
                 ("second", "sb", "10.214.4.2", "relay_b", "bs", "10.214.4.1", 1450, "35ms"))
        for left, tag1, ip1, right, tag2, ip2, mtu, delay in specs:
            a, b = "v" + token + tag1, "v" + token + tag2
            experiment.command(name + "-veth-add", ["sudo", "-n", "ip", "link", "add", a, "type", "veth", "peer", "name", b])
            links.extend((a, b))
            macs = {}
            for role, tag, interface, address in ((left, tag1, a, ip1), (right, tag2, b, ip2)):
                namespace = ns[role]
                interfaces[tag] = (namespace, interface, address)
                experiment.command(name + "-veth-move", ["sudo", "-n", "ip", "link", "set", interface, "netns", namespace])
                for argv in (["address", "add", address + "/30", "dev", interface], ["link", "set", interface, "mtu", str(mtu)], ["link", "set", interface, "up"]):
                    experiment.command(name + "-interface", ["sudo", "-n", "ip", "-n", namespace, *argv])
                experiment.command(name + "-offloads-disable", ["sudo", "-n", "ip", "netns", "exec", namespace,
                    "ethtool", "-K", interface, "gro", "off", "gso", "off", "tso", "off", "tx-udp-segmentation", "off"])
                record = experiment.command(name + "-offload-facts", ["sudo", "-n", "ip", "netns", "exec", namespace, "ethtool", "-k", interface])
                offload = (experiment.output / record["log"]).read_text()
                for feature in ("generic-receive-offload", "generic-segmentation-offload", "tx-udp-segmentation"):
                    require(re.search(r"^" + feature + r": off\b", offload, re.MULTILINE) is not None, "capture offload remains active")
                link = ROUTED.output_json(experiment, experiment.command(name + "-link-facts", ["sudo", "-n", "ip", "-j", "-n", namespace, "link", "show", "dev", interface]))
                require(len(link) == 1 and link[0].get("mtu") == mtu, "actual physical MTU differs from the fixture")
                macs[role] = link[0]["address"]
                qdisc = ["tc", "qdisc", "add", "dev", interface, "root", "netem", "delay", delay]
                if right == "relay_b":
                    qdisc += ["loss", "1%", "rate", "4mbit"]
                experiment.command(name + "-real-kernel-netem", ["sudo", "-n", "ip", "netns", "exec", namespace, *qdisc])
            for role, interface, other, address in ((left, a, right, ip2), (right, b, left, ip1)):
                experiment.command(name + "-neighbor", ["sudo", "-n", "ip", "-n", ns[role], "neigh", "replace", address,
                    "lladdr", macs[other], "nud", "permanent", "dev", interface])
        for role, namespace in ns.items():
            routes = ROUTED.output_json(experiment, experiment.command(name + "-routes", ["sudo", "-n", "ip", "-j", "-n", namespace, "route", "show"]))
            require(not any(route.get("dst") == "default" for route in routes), "isolated role acquired an external default route")
        facts["topology"] = {"namespaces": ns, "kernel_namespace_ids": ids, "external_routes": False, "kernel_forwarding": False,
            "old_path_link_mtu": 1280, "new_path_link_mtu": 1450, "old_egress_delay_ms": 5, "new_egress_delay_ms": 35,
            "new_egress_loss_percent": 1, "new_egress_rate_mbit": 4, "offloads_disabled": True, "actual_nat": False}
        for tag in ("fa", "sa", "fb", "sb"):
            namespace, interface, _ = interfaces[tag]
            path = experiment.output / (name + "-" + tag + ".pcap")
            entry = experiment.launch(name + "-capture-" + tag, ["sudo", "-n", "ip", "netns", "exec", namespace,
                "tcpdump", "--immediate-mode", "-i", interface, "-nn", "-s", "0", "-U", "-Z", pwd.getpwuid(os.getuid()).pw_name, "-w", str(path), "udp"])
            captures.append((tag, path, entry))
            started = time.monotonic()
            while "listening on" not in (experiment.output / entry[2]["log"]).read_text(errors="replace"):
                require(entry[0].poll() is None and time.monotonic() - started < 3, "capture did not become ready")
                time.sleep(0.02)
        environment = dict(os.environ, NESTLINK_NETWORK_FIXTURE=str(fixture), NESTLINK_NETWORK_CASE=name)
        prepared = experiment.launch(name + "-prepare", [str(executable), "--ignored", "--exact", PREFIX + "prepare_fixture", "--nocapture", "--test-threads=1"], environment)
        finish_role(experiment, prepared)
        for role in ("relay_a", "relay_b"):
            active[role] = experiment.launch(name + "-" + role, namespace_argv(ns[role], executable, role, fixture, name))
        for role in ("relay_a", "relay_b"):
            SOCKET.marker(fixture, role + "-ready", tuple(active.values()))
        for role in ("first", "second"):
            active[role] = experiment.launch(name + "-" + role, namespace_argv(ns[role], executable, role, fixture, name))
        for role in ("first", "second"):
            for suffix in ("two-authorized-carriers", "old-stream-verified"):
                SOCKET.marker(fixture, role + "-" + suffix, tuple(active.values()))
        SOCKET.write_marker(fixture, "switch-now")
        continued = tuple(active[role] for role in ("first", "second", "relay_b"))
        for role in ("first", "second"):
            SOCKET.marker(fixture, role + "-old-physical-released", continued)
        SOCKET.marker(fixture, "relay_a-finished", continued)
        finish_role(experiment, active.pop("relay_a"), ids["relay_a"])
        facts["relay_a"] = role_receipt(experiment, fixture, name, "relay_a")
        for tag in ("fa", "af", "sa", "as"):
            namespace, interface, _ = interfaces[tag]
            experiment.command(name + "-old-link-down", ["sudo", "-n", "ip", "-n", namespace, "link", "set", interface, "down"])
            link = ROUTED.output_json(experiment, experiment.command(name + "-old-link-disabled-fact", ["sudo", "-n", "ip", "-j", "-n", namespace, "link", "show", "dev", interface]))
            require(len(link) == 1 and "UP" not in link[0].get("flags", []), "old physical path remained enabled")
        facts["old_path_fully_closed_at"] = EVIDENCE.utc_now()
        facts["old_path_endpoints_and_relay_released_sockets"] = 4
        facts["old_path_all_veth_ends_down"] = True
        SOCKET.write_marker(fixture, "old-path-fully-closed")
        for role in ("first", "second"):
            SOCKET.marker(fixture, role + "-new-stream-verified", continued)
        if name == "cancel":
            SOCKET.marker(fixture, "first-read-blocked", continued)
        SOCKET.write_marker(fixture, "stop-all")
        for role in ("first", "second", "relay_b"):
            finish_role(experiment, active.pop(role), ids[role])
            facts[role] = role_receipt(experiment, fixture, name, role)
        for role in ("first", "second"):
            endpoint = facts[role]
            require(all(endpoint.get(key) is True for key in ("same_inner_connection", "same_stream", "same_original_path_grant", "same_original_permit", "old_physical_closed_before_new_application_bytes", "old_counts_frozen")), "continuity or original authority binding missing")
            require(endpoint.get("application_file_bytes_after_old_closed") == 262_144
                    and endpoint.get("joined_receiver_tasks") == 2 and endpoint.get("abstract_socket_release_receipts") == 2,
                    "missing real application data or original cleanup receipts")
            require(endpoint.get("bidirectional_application_file_verified") is True
                    and endpoint.get("application_file_bytes_sent_before_switch") == 131_072
                    and endpoint.get("application_file_bytes_received_before_switch") == 131_072
                    and endpoint.get("application_file_bytes_sent_after_old_closed") == 262_144
                    and endpoint.get("application_file_bytes_received_after_old_closed") == 262_144,
                    "both original stream directions must verify file bytes before and after carrier replacement")
            samples = endpoint.get("samples", [])
            require(len(samples) == 12 and len({sample["stable_id"] for sample in samples}) == 1, "measurement trajectory changed inner connection")
            require(all(sample["cwnd_bytes"] > 0 and sample["rtt_us"] > 0 and 1200 <= sample["current_mtu_bytes"] <= 1400 for sample in samples), "missing observed RTT/cwnd/PMTU state")
            require(all(isinstance(sample.get("outer_quic"), dict)
                        and sample["outer_quic"].get("rtt_us", 0) > 0
                        and sample["outer_quic"].get("cwnd_bytes", 0) > 0
                        and sample["outer_quic"].get("current_mtu_bytes") == 1200
                        and sample["outer_quic"].get("udp_tx_bytes", 0) > 0
                        and sample["outer_quic"].get("udp_rx_bytes", 0) > 0
                        for sample in samples), "missing real fixed-MTU outer carrier measurement trajectory")
        require(facts["first"]["tls_exporter_sha256"] == facts["second"]["tls_exporter_sha256"], "endpoints disagree about original inner TLS session")
        if name == "cancel":
            require(facts["first"].get("pending_read_cancelled") is True, "pending original stream read did not terminate on cancellation")
        facts["kernel_netem_counters"] = []
        dropped = 0
        for tag in ("fb", "bf", "sb", "bs"):
            namespace, interface, _ = interfaces[tag]
            record = experiment.command(name + "-new-path-real-netem-counters", ["sudo", "-n", "ip", "netns", "exec", namespace, "tc", "-s", "qdisc", "show", "dev", interface])
            text = (experiment.output / record["log"]).read_text()
            require("netem" in text and "delay 35ms" in text and "loss 1%" in text, "new carrier damage was not configured on the actual egress")
            dropped += sum(map(int, re.findall(r"\bdropped (\d+)\b", text)))
            facts["kernel_netem_counters"].append(record["log"])
        require(dropped > 0, "no actual packet loss was observed; configured loss alone is not evidence")
        facts["new_path_kernel_dropped_packets"] = dropped
        flows = {"fa": ("10.214.1.2", "10.214.1.1", 45001, 4433), "sa": ("10.214.2.2", "10.214.2.1", 45002, 4434),
                 "fb": ("10.214.3.2", "10.214.3.1", 45003, 4435), "sb": ("10.214.4.2", "10.214.4.1", 45004, 4436)}
        facts["captures"] = {}
        for tag, path, entry in list(captures):
            experiment.stop_capture(entry)
            captures.remove((tag, path, entry))
            facts["captures"][tag] = ROUTED.capture_facts(path, *flows[tag])
            require(facts["captures"][tag]["reverse_datagrams"] > 0, "real path lacks reverse QUIC traffic")
        facts["passed"] = True
    except BaseException as error:
        facts["failure"] = type(error).__name__ + ": " + str(error)
    finally:
        for _, _, entry in captures:
            try:
                if entry in experiment.active and entry[0].poll() is None:
                    experiment.stop_capture(entry)
            except BaseException as error:
                facts["cleanup_failures"].append("capture: " + str(error))
        facts["cleanup_failures"].extend(experiment.cleanup_processes())
        for namespace in reversed(namespaces):
            try:
                record = experiment.command(name + "-remaining-role-pids", ["sudo", "-n", "ip", "netns", "pids", namespace])
                pids = [line.strip() for line in (experiment.output / record["log"]).read_text().splitlines()[1:] if line.strip()]
                require(all(pid.isdigit() for pid in pids), "unrecognized owned namespace process inventory")
                if pids:
                    facts["cleanup_failures"].append(namespace + ": process survived normal completion")
                    experiment.command(name + "-force-only-owned-namespace-pids", ["sudo", "-n", "kill", "-KILL", "--", *pids], accepted=(0, 1))
                deadline = time.monotonic() + 3
                while True:
                    record = experiment.command(name + "-remaining-role-pids-recheck", ["sudo", "-n", "ip", "netns", "pids", namespace])
                    if not any(line.strip() for line in (experiment.output / record["log"]).read_text().splitlines()[1:]):
                        break
                    require(time.monotonic() < deadline, "owned namespace still contains a process after cleanup")
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
        experiment.command("network-tools", ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends", "iproute2", "tcpdump", "util-linux", "ethtool"], 180)
        for label, argv in (("rust-version", ["rustc", "--version", "--verbose"]), ("cargo-version", ["cargo", "--version"]), ("kernel", ["uname", "-a"])):
            experiment.command(label, argv)
        experiment.command("lint-quinn-prototype", ["cargo", "clippy", "-p", "nestlink-transport-quic", "--locked", "--lib", "--tests", "--", "-D", "warnings"], 1200)
        built = experiment.command("build-quinn-prototype", ["cargo", "test", "-p", "nestlink-transport-quic", "--locked", "--lib", "--no-run", "--message-format=json"], 1200)
        binaries = []
        for line in (output / built["log"]).read_text(errors="replace").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("target", {}).get("name") == "nestlink_transport_quic" and item.get("profile", {}).get("test") and item.get("executable"):
                binaries.append(Path(item["executable"]).resolve())
        require(len(binaries) == 1 and binaries[0].is_file(), "one freshly built transport-quic libtest executable required")
        executable = binaries[0]
        executable_record = {"path": executable.relative_to(ROOT).as_posix(), "sha256": EVIDENCE.sha256_file(executable),
            "source_revision": identity["source_revision"], "dependency_lock_sha256": before["dependency_lock_sha256"], "explicit_test_filter_prefix": PREFIX}
        with tempfile.TemporaryDirectory(prefix="nestlink-migration-private-", dir=os.environ["RUNNER_TEMP"]) as private:
            Path(private).chmod(0o700)
            for name in CASES:
                cases.append(case(experiment, executable, name, Path(private)))
        require(len(cases) == len(CASES) and all(item["passed"] for item in cases), "one or more actual carrier-replacement cases failed")
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
        receipt = {"schema_version": 1, "kind": "nestlink-quinn-carrier-replacement-feasibility", "passed": failure is None, "failure": failure,
            "w14_complete": False, "ac22_passed": False, "production_migration_protocol_exercised": False,
            "build_provenance": {**identity, "source_before": before, "source_after": after, "executable": executable_record},
            "execution_provenance": {**identity, "environment": "github-hosted-linux-network-namespaces", "process_uid": os.getuid(),
                "ignored_roles_explicitly_executed_per_case": 5, "cases": list(CASES)},
            "cases": cases, "commands": commands, "processes": processes, "files": EVIDENCE.artifact_files(output),
            "limitations": ["Private cfg(test,Linux) prototype uses Quinn rebind_abstract after out-of-band fixture agreement; no production migration negotiation",
                "Production path epoch remains one; no simultaneous proposal, lost ACK, bounded epoch drain, grant renewal or old-v15 semantic change",
                "Same original PathGrant, Permit and transport group; each real preauthenticated relay has its own signed TransitGrant and unchanged deadlines/quotas",
                "Fresh phase-tagged OS file bytes traverse one pinned inner QUIC stream after all old physical sockets release and old interfaces are down",
                "No business endpoint SessionPermit proof, actual FileRead worker, input/media/TCP recovery, SDK signaling or full AC22 qualification",
                "RTT, congestion and logical PLPMTUD trajectories are observations; Quinn local_address_changed changes CID and sends ping without resetting these estimates",
                "NRD fragmentation adapts logical packets up to 1400 bytes onto outer QUIC fixed at 1200 bytes; logical PMTU is not physical dynamic PMTU convergence",
                "Four isolated kernel namespaces and actual netem loss/delay/rate, no NAT/public Internet/installed device acceptance; private credentials are excluded from artifacts"]}
        (output / "network-migration-evidence.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"passed": receipt["passed"], "failure": failure, "evidence": str(output)}, indent=2), flush=True)
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
