"""Owned HL loopback targets. Never approves or creates a NestLink publication."""
import argparse
import copy
import contextlib
import json
from pathlib import Path
import re
import secrets
import socket
import socketserver
import threading
import time
import uuid

from common import (CheckFailed, MAX_REPORT_EVENTS, TCP_MAX, UDP_MAX, canonical, frame,
                    load_config, new_output, public_ip, receive_tcp, require, send_tcp, sha, unframe, write_json)


def validate_gate_command(command):
    fields = {"start": {"source_ip", "operator_evidence"},
              "stop-arm": {"stop_marker"}, "stopped": {"operator_evidence"}, "finish": {"visitor_done_marker"}}
    require(type(command) is dict and command.get("phase") in fields, "gate-command-kind")
    require(set(command) == {"run", "sequence", "phase"} | fields[command["phase"]], "gate-command-fields")
    require(str(uuid.UUID(command["run"])) == command["run"] and type(command["sequence"]) is int and 1 <= command["sequence"] <= 4, "gate-command-identity")
    for key in ("source_ip",):
        if key in command:
            public_ip(command[key])
    if "operator_evidence" in command:
        require(type(command["operator_evidence"]) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", command["operator_evidence"]), "gate-evidence-id")
    for key in ("stop_marker", "visitor_done_marker"):
        if key in command:
            require(type(command[key]) is str and re.fullmatch(r"[0-9a-f]{32}", command[key]), "gate-marker")


class ResponderCore:
    def __init__(self, config):
        self.config = config
        self.lock = threading.RLock()
        self.peers = {}
        self.gate = {"phase": "waiting", "control_sequence": 0, "source_ip": None,
                     "acl_prefix": 32, "operator_evidence": None, "stop_marker": None, "visitor_done_marker": None}
        self.report = {"schema_version": 1, "protocol": config["protocol"], "run": config["run"], "nonce_sha256": sha(bytes.fromhex(config["nonce_hex"])),
                       "started_unix_ms": int(time.time() * 1000), "ended_unix_ms": None, "lifecycle": "running",
                       "tcp_fin_received": 0, "tcp_fin_replies": 0, "udp_empty_received": 0,
                       "udp_maximum_received": 0, "udp_authenticated_oversize_received": 0,
                       "udp_peer_count": 0, "rejected_frames": 0, "events": [], "gate_history": [],
                       "publication_created_by_tool": False, "target_consent_given_by_tool": False,
                       "public_tunnel_acceptance": "not_assessed", "product_lease_renewal_verified": False}

    def change_gate(self, command):
        with self.lock:
            validate_gate_command(command)
            require(command["run"] == self.config["run"] and command["sequence"] == self.gate["control_sequence"] + 1, "gate-sequence")
            phase = command["phase"]
            transitions = {"waiting": "start", "start": "stop-arm", "stop-arm": "stopped", "stopped": "finish"}
            require(transitions.get(self.gate["phase"]) == phase, "gate-transition")
            following = copy.deepcopy(self.gate)
            following.update(phase=phase, control_sequence=command["sequence"])
            if phase == "start":
                following.update(source_ip=public_ip(command["source_ip"]))
                require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", command["operator_evidence"]), "evidence-id-required")
                following["operator_evidence"] = command["operator_evidence"]
            elif phase == "stop-arm":
                require(re.fullmatch(r"[0-9a-f]{32}", command["stop_marker"]), "stop-marker-required")
                following["stop_marker"] = command["stop_marker"]
            elif phase == "stopped":
                require(re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", command["operator_evidence"]), "stop-evidence-id-required")
                following["stop_evidence"] = command["operator_evidence"]
            elif phase == "finish":
                require(re.fullmatch(r"[0-9a-f]{32}", command["visitor_done_marker"]), "visitor-done-marker-required")
                following["visitor_done_marker"] = command["visitor_done_marker"]
            self.gate = following
            self.report["gate_history"].append({**following, "observed_unix_ms": int(time.time() * 1000)})

    def record(self, protocol, sequence, kind, payload):
        require(len(self.report["events"]) < MAX_REPORT_EVENTS, "owned-target-event-budget")
        self.report["events"].append({"protocol": protocol, "sequence": sequence, "kind": kind.decode(),
                                      "payload_bytes": len(payload), "payload_sha256": sha(payload),
                                      "received_unix_ms": int(time.time() * 1000)})

    def respond(self, protocol, peer, raw, fin=False):
        with self.lock:
            require(protocol == self.config["protocol"], "target-protocol")
            key = (protocol, peer)
            if raw == b"" and protocol == "udp":
                require(key in self.peers, "empty-udp-needs-authenticated-peer")
                self.report["udp_empty_received"] += 1
                self.record(protocol, 0, b"P", b"")
                return b""
            kind, sequence, payload = unframe(self.config, raw)
            require(sequence > self.peers.get(key, 0), "target-replayed-sequence")
            if protocol == "udp" and len(raw) > UDP_MAX:
                # An over-limit packet reaching the approved target is a product
                # boundary failure, even when this target refuses to echo it.
                require(key in self.peers, "oversize-needs-authenticated-peer")
                self.report["udp_authenticated_oversize_received"] += 1
                self.record(protocol, sequence, b"P", payload)
                return None
            require(len(raw) <= (UDP_MAX if protocol == "udp" else TCP_MAX), "target-wire-bound")
            if key not in self.peers:
                require(len(self.peers) < 16, "owned-target-peer-budget")
                require(kind in ((b"H",) if protocol == "udp" else (b"O", b"F")), "target-handshake-required")
                if protocol == "udp":
                    self.report["udp_peer_count"] += 1
            if kind == b"F":
                require(protocol == "tcp" and fin, "tcp-fin-required-before-reply")
                self.report["tcp_fin_received"] += 1
            require(kind in (b"H", b"O", b"Q", b"P", b"F", b"C"), "request-kind-required")
            self.peers[key] = sequence
            self.record(protocol, sequence, kind, payload)
            if protocol == "udp" and len(raw) == UDP_MAX:
                self.report["udp_maximum_received"] += 1
            if kind in (b"H", b"O", b"Q"):
                response = {**self.gate, "server_unix_ms": int(time.time() * 1000), "probe_sha256": sha(payload)}
                return frame(self.config, b"A", sequence, canonical(response))
            return frame(self.config, b"R", sequence, payload)

    def snapshot(self):
        with self.lock:
            return copy.deepcopy(self.report)


class OwnedTcp(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self):
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", 0), TcpHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        peer = uuid.uuid4().hex
        try:
            require(self.client_address[0] == "127.0.0.1", "loopback-target-only")
            while not self.server.ended.is_set():
                raw = receive_tcp(self.request)
                kind, _, _ = unframe(self.server.core.config, raw)
                fin = False
                if kind == b"F":
                    require(self.request.recv(1) == b"", "fin-request-has-trailing-bytes")
                    fin = True
                    # Actual reply is delayed until after EOF from visitor FIN.
                    time.sleep(0.15)
                reply = self.server.core.respond("tcp", peer, raw, fin=fin)
                send_tcp(self.request, reply)
                if fin:
                    with self.server.core.lock:
                        self.server.core.report["tcp_fin_replies"] += 1
                    self.request.shutdown(socket.SHUT_WR)
                    return
                if kind == b"C":
                    return
        except (CheckFailed, OSError):
            return


def serve(config, output):
    output = new_output(output)
    core = ResponderCore(config)
    control_token = secrets.token_hex(32)
    ended = threading.Event()
    with contextlib.ExitStack() as stack:
        tcp = udp = thread = None
        if config["protocol"] == "tcp":
            tcp = stack.enter_context(OwnedTcp())
            tcp.core, tcp.ended = core, ended
            thread = threading.Thread(target=tcp.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
            thread.start()
        else:
            udp = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp.bind(("127.0.0.1", 0))
            udp.settimeout(0.2)
        ready = {"schema_version": 1, "protocol": config["protocol"], "run": config["run"], "nonce_sha256": core.report["nonce_sha256"],
                 "target": "127.0.0.1:" + str(tcp.server_address[1] if tcp else udp.getsockname()[1]),
                 "control_token": control_token, "result_file": str(output / "responder-result.json")}
        write_json(output / "ready.json", ready)
        write_json(output / "responder-result.json", core.snapshot())
        print(json.dumps({"marker": "NESTLINK_HL_TARGETS_READY", "run": config["run"], "protocol": ready["protocol"], "target": ready["target"]}), flush=True)
        deadline = time.monotonic() + config["duration_seconds"]
        last_saved = 0.0
        try:
            while time.monotonic() < deadline and core.gate["phase"] != "finish":
                control = output / "control.json"
                if control.is_file() and not control.is_symlink() and control.stat().st_size <= 2048:
                    command = json.loads(control.read_text())
                    require(secrets.compare_digest(command.pop("control_token"), control_token), "control-token")
                    if command["sequence"] > core.gate["control_sequence"]:
                        core.change_gate(command)
                        write_json(output / "gate-state.json", core.gate)
                try:
                    if udp is None:
                        time.sleep(0.2)
                        raise socket.timeout()
                    raw, peer = udp.recvfrom(65535)
                    require(peer[0] == "127.0.0.1", "loopback-target-only")
                    reply = core.respond("udp", peer, raw)
                    if reply is not None:
                        udp.sendto(reply, peer)
                except socket.timeout:
                    pass
                except CheckFailed:
                    with core.lock:
                        core.report["rejected_frames"] += 1
                if time.monotonic() - last_saved >= 0.5:
                    write_json(output / "responder-result.json", core.snapshot())
                    last_saved = time.monotonic()
        finally:
            ended.set()
            if tcp is not None:
                tcp.shutdown()
                thread.join(timeout=2)
            with core.lock:
                core.report.update(lifecycle="ended", ended_unix_ms=int(time.time() * 1000),
                                   ended_reason="operator-finish" if core.gate["phase"] == "finish" else "deadline-or-failure")
            write_json(output / "responder-result.json", core.snapshot())


def gate(ready_path, phase, source=None, evidence=None, marker=None):
    ready_path = Path(ready_path).resolve(strict=True)
    require(ready_path.name == "ready.json", "owned-ready-required")
    ready = json.loads(ready_path.read_text())
    require(ready["result_file"] == str(ready_path.parent / "responder-result.json"), "owned-result-path")
    state_path = ready_path.parent / "gate-state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {"control_sequence": 0, "phase": "waiting"}
    require({"waiting": "start", "start": "stop-arm", "stop-arm": "stopped", "stopped": "finish"}.get(state["phase"]) == phase, "wait-for-previous-gate-acknowledgement")
    command = {"run": ready["run"], "sequence": state["control_sequence"] + 1, "phase": phase, "control_token": ready["control_token"]}
    if phase == "start":
        command.update(source_ip=public_ip(source), operator_evidence=evidence)
    elif phase == "stop-arm":
        command["stop_marker"] = marker
    elif phase == "stopped":
        command["operator_evidence"] = evidence
    elif phase == "finish":
        command["visitor_done_marker"] = marker
    validate_gate_command({k: v for k, v in command.items() if k != "control_token"})
    write_json(ready_path.parent / "control.json", command)
    print(json.dumps({"run": ready["run"], "phase_requested": phase, "sequence": command["sequence"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parts = parser.add_subparsers(dest="command", required=True)
    start = parts.add_parser("serve")
    start.add_argument("--config", required=True)
    start.add_argument("--output", required=True)
    control = parts.add_parser("gate")
    control.add_argument("--ready", required=True)
    control.add_argument("--phase", choices=("start", "stop-arm", "stopped", "finish"), required=True)
    control.add_argument("--source-ip")
    control.add_argument("--evidence")
    control.add_argument("--marker")
    args = parser.parse_args()
    if args.command == "serve":
        serve(load_config(args.config), args.output)
    else:
        gate(args.ready, args.phase, args.source_ip, args.evidence, args.marker)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "failed", "reason": "owned-responder-failed-inspect-own-receipt"}))
        raise SystemExit(1) from None
