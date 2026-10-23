"""Approved-endpoint TCP/UDP visitor. Data facts only; no management credentials."""
import argparse
import contextlib
import json
import secrets
import socket
import sys
import time

from common import (CheckFailed, OVERHEAD, SERVER, TCP_PORT, UDP_MAX, UDP_PORT,
                    echo_reply, frame, load_config, new_output, public_ip, receive_tcp,
                    require, send_tcp, sha, unframe, write_json)


def udp_socket():
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if sys.platform.startswith("linux"):
        # Only this owned fixture socket permits IPv4 fragmentation for the
        # 60000-byte negative case. No OS or product networking option changes.
        peer.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 0)
    return peer


class Visitor:
    def __init__(self, config, output):
        self.config, self.output = config, output
        self.sequence = 0
        self.deadline = time.monotonic() + config["duration_seconds"]
        self.report = {"schema_version": 1, "protocol": config["protocol"], "run": config["run"], "nonce_sha256": sha(bytes.fromhex(config["nonce_hex"])),
                       "endpoint": {"ip": SERVER, "tcp_port": TCP_PORT, "udp_port": UDP_PORT},
                       "started_unix_ms": int(time.time() * 1000), "finished_unix_ms": None,
                       "tool_data_checks_passed": False, "failure": None, "checks": [], "markers": [],
                       "public_tunnel_acceptance": "not_assessed", "product_lease_renewal_verified": False,
                       "requires_product_lease_sequence_evidence": True, "requires_responder_drop_counters": True,
                       "requires_exact_source_acl_evidence": True, "requires_product_stop_evidence": True}
        (output / "markers").mkdir(mode=0o700)

    def remaining(self):
        left = self.deadline - time.monotonic()
        require(left > 0, "visitor-run-deadline")
        return left

    def marker(self, name, **fields):
        value = {"marker": name, "run": self.config["run"], "unix_ms": int(time.time() * 1000), **fields}
        self.report["markers"].append(value)
        write_json(self.output / "markers" / (name + ".json"), value)
        print(json.dumps(value, sort_keys=True), flush=True)

    def packet(self, kind, payload):
        self.sequence += 1
        return frame(self.config, kind, self.sequence, payload)

    def udp_exchange(self, peer, raw, timeout=2):
        peer.settimeout(min(timeout, self.remaining()))
        peer.send(raw)
        reply = peer.recv(65535)
        return reply

    def status(self, sent, received):
        _, sequence, payload = unframe(self.config, sent)
        kind, actual_sequence, response = unframe(self.config, received)
        require(kind == b"A" and sequence == actual_sequence, "status-response-identity")
        value = json.loads(response)
        require(value["probe_sha256"] == sha(payload), "status-probe-mismatch")
        return value

    def tcp_exchange(self, peer, raw):
        peer.settimeout(min(3, self.remaining()))
        send_tcp(peer, raw)
        return receive_tcp(peer)

    def exchange(self, peer, raw, timeout=2):
        return self.tcp_exchange(peer, raw) if self.config["protocol"] == "tcp" else self.udp_exchange(peer, raw, timeout)

    def connect_peer(self):
        if self.config["protocol"] == "tcp":
            return socket.create_connection((SERVER, TCP_PORT), timeout=min(2, self.remaining()))
        peer = udp_socket()
        peer.connect((SERVER, UDP_PORT))
        return peer

    def wait_for_source(self):
        self.marker("source-probe-ready", nonce_sha256=self.report["nonce_sha256"],
                    protocol=self.config["protocol"], expected_source_observation="authenticated-server-peer-this-run")
        limit = min(self.deadline, time.monotonic() + 90)
        while time.monotonic() < limit:
            try:
                with self.connect_peer() as peer:
                    raw = self.packet(b"O" if self.config["protocol"] == "tcp" else b"H", secrets.token_bytes(32))
                    value = self.status(raw, self.exchange(peer, raw))
                    require(value["phase"] == "source-only", "source-observer-phase")
                    public_ip(value["source_ip"])
                    require(value["protocol"] == self.config["protocol"] and value["nonce_sha256"] == self.report["nonce_sha256"], "source-observer-identity")
                    if self.config["protocol"] == "tcp":
                        peer.shutdown(socket.SHUT_WR)
                    self.report["source_observation"] = value
                    self.marker("source-observed", **value)
                    return
            except (OSError, CheckFailed, ValueError):
                time.sleep(min(1, self.remaining()))
        raise CheckFailed("same-run-source-observer-not-observed")

    def wait_for_start(self):
        limit = min(self.deadline, time.monotonic() + 150)
        peer = None
        while time.monotonic() < limit:
            try:
                if peer is None:
                    peer = self.connect_peer()
                raw = self.packet(b"O" if self.config["protocol"] == "tcp" else b"H", secrets.token_bytes(32))
                sent = int(time.time() * 1000)
                status = self.status(raw, self.exchange(peer, raw))
                received = int(time.time() * 1000)
                if status["phase"] != "start":
                    time.sleep(min(0.5, self.remaining()))
                    continue
                require(status["acl_prefix"] == 32 and status["source_ip"] == self.report["source_observation"]["source_ip"], "observed-source-exact-acl-required")
                require(status["operator_evidence"], "source-acl-operator-evidence-required")
                self.report["operator_start_gate"] = status
                self.report["host_clock_offset_ms_bounds"] = [status["server_unix_ms"] - received, status["server_unix_ms"] - sent]
                return peer
            except (OSError, CheckFailed, ValueError):
                if peer is not None:
                    peer.close()
                    peer = None
                time.sleep(min(0.5, self.remaining()))
        if peer is not None:
            peer.close()
        raise CheckFailed("published-target-and-exact-acl-start-gate-not-observed")

    def test_fin(self):
        payload = secrets.token_bytes(32) + b"NestLink-070-after-FIN-" * 80
        raw = self.packet(b"F", payload)
        with socket.create_connection((SERVER, TCP_PORT), timeout=min(3, self.remaining())) as peer:
            send_tcp(peer, raw)
            before_fin = time.monotonic()
            peer.shutdown(socket.SHUT_WR)
            reply = receive_tcp(peer)
            elapsed = time.monotonic() - before_fin
            require(peer.recv(1) == b"", "fin-response-did-not-end")
            require(elapsed >= 0.1, "fin-response-delay-not-observed")
        self.report["checks"].append({"name": "tcp-fin-delayed-reply", **echo_reply(self.config, raw, reply), "elapsed_after_fin_ms": round(elapsed * 1000, 3)})

    def test_udp_boundaries(self, primary):
        require(self.udp_exchange(primary, b"") == b"", "empty-udp-mismatch")
        self.report["checks"].append({"name": "udp-empty", "payload_bytes": 0, "payload_sha256": sha(b"")})
        raw = self.packet(b"P", secrets.token_bytes(UDP_MAX - OVERHEAD))
        self.report["checks"].append({"name": "udp-maximum-1169", **echo_reply(self.config, raw, self.udp_exchange(primary, raw))})
        with udp_socket() as other:
            other.connect((SERVER, UDP_PORT))
            hello = self.packet(b"H", secrets.token_bytes(32))
            self.status(hello, self.udp_exchange(other, hello))
            other_packet = self.packet(b"P", b"secondary-visitor:" + secrets.token_bytes(32))
            self.report["checks"].append({"name": "udp-second-visitor", **echo_reply(self.config, other_packet, self.udp_exchange(other, other_packet))})
            primary.settimeout(0.2)
            try:
                primary.recv(65535)
                raise CheckFailed("secondary-reply-leaked-to-primary")
            except socket.timeout:
                pass
        for wire_size in (1170, 60000):
            raw = self.packet(b"P", secrets.token_bytes(wire_size - OVERHEAD))
            reply_seen = False
            try:
                self.udp_exchange(primary, raw, timeout=0.6)
                reply_seen = True
            except socket.timeout:
                pass
            require(not reply_seen, "oversize-udp-reply-observed")
            self.report["checks"].append({"name": "udp-oversize-no-reply", "wire_bytes": wire_size,
                                          "sequence": self.sequence, "payload_sha256": sha(raw[OVERHEAD:]),
                                          "requires_target_oversize_count_zero": True})
            legal = self.packet(b"P", b"after-oversize:" + secrets.token_bytes(32))
            self.report["checks"].append({"name": "udp-legal-after-oversize", **echo_reply(self.config, legal, self.udp_exchange(primary, legal))})

    def steady(self, peer):
        started = time.monotonic()
        frames = 0
        while time.monotonic() - started < self.config["steady_seconds"]:
            raw = self.packet(b"P", secrets.token_bytes(128))
            echo_reply(self.config, raw, self.exchange(peer, raw))
            frames += 1
            time.sleep(min(0.75, self.remaining()))
        self.report["checks"].append({"name": "continuous-owned-data", "seconds": round(time.monotonic() - started, 3),
                                      "protocol": self.config["protocol"], "frames": frames,
                                      "product_lease_renewal_verified": False})

    def arm_stop(self, peer):
        marker = secrets.token_hex(16)
        self.report["stop_marker"] = marker
        self.marker("ready-to-stop", stop_marker=marker,
                    next_action="operator-arms-HL-helper-only; wait-stop-armed-marker-before-stopping-product")
        limit = min(self.deadline, time.monotonic() + 120)
        while time.monotonic() < limit:
            raw = self.packet(b"Q", secrets.token_bytes(32))
            value = self.status(raw, self.exchange(peer, raw))
            if value["phase"] == "stop-arm" and value["stop_marker"] == marker:
                self.marker("stop-armed", stop_marker=marker, next_action="operator-stops-selected-actual-publication")
                return
            time.sleep(min(1, self.remaining()))
        raise CheckFailed("authenticated-stop-arm-not-observed")

    def observe_withdrawal(self, peer):
        limit = min(self.deadline, time.monotonic() + 60)
        lost = False
        while time.monotonic() < limit:
            raw = self.packet(b"P", b"await-stop:" + secrets.token_bytes(32))
            try:
                echo_reply(self.config, raw, self.exchange(peer, raw, timeout=1))
            except OSError:
                lost = True
            except CheckFailed as error:
                require(self.config["protocol"] == "tcp" and str(error) == "tcp-early-eof", "corruption-during-withdrawal")
                lost = True
            if lost:
                break
            time.sleep(min(0.5, self.remaining()))
        require(lost, "selected-publication-did-not-withdraw")
        self.report["post_stop_nonce_hashes"] = []
        for attempt in range(3):
            fresh = b"new-after-stop:" + secrets.token_bytes(32)
            self.report["post_stop_nonce_hashes"].append(sha(fresh))
            after = None
            try:
                after = self.connect_peer()
                require(self.config["protocol"] != "tcp", "new-tcp-connection-succeeded-after-stop")
                raw = self.packet(b"H", fresh)
                self.exchange(after, raw, timeout=1)
                raise CheckFailed("new-udp-reply-after-stop")
            except OSError:
                pass
            finally:
                if after is not None:
                    after.close()
            self.report["checks"].append({"name": "fresh-after-stop-no-response", "attempt": attempt + 1,
                                          "fresh_nonce_sha256": sha(fresh), "unix_ms": int(time.time() * 1000)})
            time.sleep(min(0.5, self.remaining()))

    def run(self):
        try:
            self.wait_for_source()
            with self.wait_for_start() as primary:
                if self.config["protocol"] == "tcp":
                    self.test_fin()
                else:
                    self.test_udp_boundaries(primary)
                self.steady(primary)
                self.arm_stop(primary)
                self.observe_withdrawal(primary)
            self.report["tool_data_checks_passed"] = True
        except CheckFailed as error:
            self.report["failure"] = str(error)
        except Exception:
            self.report["failure"] = "transport-or-unexpected-visitor-failure"
        finally:
            self.report["finished_unix_ms"] = int(time.time() * 1000)
            self.report["done_marker"] = secrets.token_hex(16)
            write_json(self.output / "visitor-result.json", self.report)
            self.marker("visitor-done", done_marker=self.report["done_marker"], tool_data_checks_passed=self.report["tool_data_checks_passed"],
                        report_file_sha256=sha((self.output / "visitor-result.json").read_bytes()))
        return self.report["tool_data_checks_passed"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    output = new_output(args.output)
    raise SystemExit(0 if Visitor(config, output).run() else 1)


if __name__ == "__main__":
    main()
