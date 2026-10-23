"""Pure protocol/fake-stream tests. Real socket creation is forbidden in tests."""
import copy
import io
import socket
import struct
import time
import tempfile
import json
import re
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

import common
from compare_results import compare
from responder import ResponderCore
from visitor import Visitor
from source_observer import source_reply, require_no_listener, observe, wait_for_visitor_close


def config(protocol="udp"):
    return {"run": "029c4c7c-b4c2-4515-aeb5-8081592a6fd0", "nonce_hex": "11" * 32,
            "server": common.SERVER, "tcp_port": common.TCP_PORT, "udp_port": common.UDP_PORT,
            "steady_seconds": 30, "duration_seconds": 600, "protocol": protocol}


def gates(core):
    run = core.config["run"]
    return [{"run": run, "sequence": 1, "phase": "start", "source_ip": "8.8.8.8", "operator_evidence": "fixture-acl-receipt"},
            {"run": run, "sequence": 2, "phase": "stop-arm", "stop_marker": "a" * 32},
            {"run": run, "sequence": 3, "phase": "stopped", "operator_evidence": "fixture-stop-receipt"},
            {"run": run, "sequence": 4, "phase": "finish", "visitor_done_marker": "b" * 32}]


class FakeStream:
    def __init__(self, raw):
        self.raw = io.BytesIO(raw)
        self.written = bytearray()

    def recv(self, size):
        return self.raw.read(min(size, 3))

    def sendall(self, raw):
        self.written.extend(raw)


class OfflineTests(unittest.TestCase):
    def setUp(self):
        self.forbid_socket = patch.object(socket, "socket", side_effect=AssertionError("Network forbidden in offline tests"))
        self.forbid_connect = patch.object(socket, "create_connection", side_effect=AssertionError("Network forbidden in offline tests"))
        self.forbid_socket.start()
        self.forbid_connect.start()

    def tearDown(self):
        self.forbid_connect.stop()
        self.forbid_socket.stop()

    def test_only_fixed_public_endpoints_and_bounded_durations(self):
        common.validate_config(config())
        for key, value in (("server", "127.0.0.1"), ("tcp_port", 443), ("udp_port", 3478),
                           ("duration_seconds", 601), ("steady_seconds", 1)):
            with self.subTest(key=key):
                changed = config()
                changed[key] = value
                with self.assertRaises(common.CheckFailed):
                    common.validate_config(changed)

    def test_hmac_binds_run_sequence_and_payload(self):
        cfg = config()
        raw = common.frame(cfg, b"P", 4, b"owned-test")
        self.assertEqual(common.unframe(cfg, raw), (b"P", 4, b"owned-test"))
        for offset in (0, 10, common.HEADER.size, len(raw) - 1):
            changed = bytearray(raw)
            changed[offset] ^= 1
            with self.assertRaises(common.CheckFailed):
                common.unframe(cfg, bytes(changed))

    def test_tcp_frame_partial_reads_and_oversize_header(self):
        raw = common.frame(config(), b"F", 1, b"after-FIN")
        stream = FakeStream(struct.pack("!I", len(raw)) + raw)
        self.assertEqual(common.receive_tcp(stream), raw)
        common.send_tcp(stream, raw)
        self.assertEqual(bytes(stream.written), struct.pack("!I", len(raw)) + raw)
        with self.assertRaises(common.CheckFailed):
            common.receive_tcp(FakeStream(struct.pack("!I", common.TCP_MAX + 1)))

    def test_fin_is_required_before_owned_reply(self):
        core = ResponderCore(config("tcp"))
        raw = common.frame(config(), b"F", 1, b"fixed-test")
        with self.assertRaisesRegex(common.CheckFailed, "tcp-fin-required"):
            core.respond("tcp", "owned-peer", raw, fin=False)
        reply = core.respond("tcp", "owned-peer", raw, fin=True)
        self.assertEqual(common.echo_reply(config(), raw, reply)["payload_bytes"], 10)
        self.assertEqual(core.report["tcp_fin_received"], 1)

    def test_udp_empty_requires_own_authenticated_peer(self):
        core = ResponderCore(config())
        with self.assertRaises(common.CheckFailed):
            core.respond("udp", ("127.0.0.1", 1), b"")
        core.respond("udp", ("127.0.0.1", 1), common.frame(config(), b"H", 1, b"hello"))
        self.assertEqual(core.respond("udp", ("127.0.0.1", 1), b""), b"")
        self.assertEqual(core.report["udp_empty_received"], 1)

    def test_maximum_and_oversize_are_distinct_target_facts(self):
        core = ResponderCore(config())
        peer = ("127.0.0.1", 1)
        core.respond("udp", peer, common.frame(config(), b"H", 1, b"hello"))
        maximum = common.frame(config(), b"P", 2, b"m" * (1169 - common.OVERHEAD))
        self.assertEqual(len(core.respond("udp", peer, maximum)), 1169)
        for sequence, size in ((3, 1170), (4, 60000)):
            raw = common.frame(config(), b"P", sequence, b"x" * (size - common.OVERHEAD))
            self.assertIsNone(core.respond("udp", peer, raw))
        self.assertEqual(core.report["udp_maximum_received"], 1)
        self.assertEqual(core.report["udp_authenticated_oversize_received"], 2)

    def test_sequence_replay_and_other_peer_require_handshake(self):
        core = ResponderCore(config())
        raw = common.frame(config(), b"H", 1, b"hello")
        core.respond("udp", "first", raw)
        with self.assertRaisesRegex(common.CheckFailed, "replayed"):
            core.respond("udp", "first", raw)
        with self.assertRaisesRegex(common.CheckFailed, "handshake"):
            core.respond("udp", "second", common.frame(config(), b"P", 2, b"echo"))

    def test_stopped_gate_does_not_disable_target_and_fake_withdrawal(self):
        core = ResponderCore(config("tcp"))
        for command in gates(core)[:3]:
            core.change_gate(command)
        raw = common.frame(config(), b"F", 1, b"new-after-stop:owned-nonce")
        self.assertIsNotNone(core.respond("tcp", "late-peer", raw, fin=True))
        self.assertEqual(core.report["events"][-1]["payload_sha256"], common.sha(b"new-after-stop:owned-nonce"))
        self.assertEqual(core.report["public_tunnel_acceptance"], "not_assessed")

    def test_gate_cannot_skip_and_rejects_nonpublic_acl_or_extra_fields(self):
        core = ResponderCore(config())
        with self.assertRaises(common.CheckFailed):
            core.change_gate(gates(core)[1])
        command = gates(core)[0]
        command["source_ip"] = "127.0.0.1"
        with self.assertRaises(common.CheckFailed):
            core.change_gate(command)
        command = gates(core)[0]
        command["password"] = "never-a-valid-field"
        with self.assertRaises(common.CheckFailed):
            core.change_gate(command)

    def test_protocol_corruption_is_not_successful_withdrawal(self):
        visitor = Visitor.__new__(Visitor)
        visitor.config = config("tcp")
        visitor.sequence = 0
        visitor.deadline = time.monotonic() + 5
        with patch.object(visitor, "tcp_exchange", side_effect=common.CheckFailed("echo-mismatch")):
            with self.assertRaisesRegex(common.CheckFailed, "corruption-during-withdrawal"):
                visitor.observe_withdrawal(object())

    def test_source_observer_authentication_phase_and_actual_peer(self):
        cfg = config()
        raw = common.frame(cfg, b"H", 1, b"probe")
        reply, value = source_reply(cfg, raw, "8.8.4.4", 1234)
        self.assertEqual(value["phase"], "source-only")
        self.assertEqual(value["source_ip"], "8.8.4.4")
        self.assertEqual(common.unframe(cfg, reply)[0], b"A")
        altered = bytearray(raw)
        altered[-1] ^= 1
        with self.assertRaises(common.CheckFailed):
            source_reply(cfg, bytes(altered), "8.8.4.4", 1234)
        with patch("source_observer.subprocess.run") as run:
            run.return_value.stdout = "existing listener"
            with self.assertRaisesRegex(common.CheckFailed, "existing-listener"):
                require_no_listener("udp", 29102)

    def test_observer_receipt_only_after_owned_port_is_closed(self):
        cfg = config()
        raw = common.frame(cfg, b"H", 1, b"source")
        class FakeDatagram:
            closed = False
            def __enter__(self): return self
            def __exit__(self, *args): self.closed = True
            def bind(self, address): self.address = address
            def settimeout(self, timeout): pass
            def recvfrom(self, limit): return raw, ("8.8.4.4", 12345)
            def sendto(self, reply, peer): pass
        owned = FakeDatagram()
        def receipt(path, value):
            self.assertTrue(owned.closed)
            self.assertTrue(value["observer_port_released"])
            self.assertEqual(value["source_ip"], "8.8.4.4")
            self.assertNotIn("probe_sha256", value)
        with tempfile.TemporaryDirectory() as scratch:
            with patch("source_observer.require_no_listener"), patch("source_observer.socket.socket", return_value=owned), patch("source_observer.write_json", side_effect=receipt):
                observe(cfg, str(Path(scratch) / "source.json"))
        self.assertEqual(owned.address, ("0.0.0.0", common.UDP_PORT))
        class FailedRebind(FakeDatagram):
            def bind(self, address): raise OSError("port still held")
        with tempfile.TemporaryDirectory() as scratch:
            with patch("source_observer.require_no_listener"), patch("source_observer.socket.socket", side_effect=[FakeDatagram(), FailedRebind()]), patch("source_observer.write_json") as write:
                with self.assertRaises(OSError):
                    observe(cfg, str(Path(scratch) / "source.json"))
                write.assert_not_called()


    def test_tcp_observer_requires_visitor_eof_before_handoff(self):
        wait_for_visitor_close(FakeStream(b""))
        with self.assertRaisesRegex(RuntimeError, "did-not-close-cleanly"):
            wait_for_visitor_close(FakeStream(b"unexpected-tail"))
        class TimedOut:
            def recv(self, size): raise socket.timeout()
        with self.assertRaisesRegex(RuntimeError, "did-not-close-cleanly"):
            wait_for_visitor_close(TimedOut())

    def test_workflow_marker_commands_are_accepted_by_real_cli(self):
        script = Path(__file__).resolve().with_name("wait_marker.py")
        workflow = script.parents[3] / ".github" / "workflows" / "public-tunnel-acceptance.yml"
        markers = set(re.findall(r"--marker ([a-z-]+)", workflow.read_text()))
        self.assertIn("source-observed", markers)
        self.assertEqual(len(markers), 5)
        with tempfile.TemporaryDirectory() as scratch:
            output = Path(scratch)
            (output / "markers").mkdir()
            (output / "visitor-result.json").write_text(json.dumps({"tool_data_checks_passed": True}))
            for marker in markers:
                (output / "markers" / (marker + ".json")).write_text(json.dumps({"marker": marker}))
                result = subprocess.run([sys.executable, "-B", str(script), "--output", str(output),
                                         "--marker", marker, "--timeout", "1"], capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_single_protocol_enforced(self):
        core = ResponderCore(config("tcp"))
        with self.assertRaisesRegex(common.CheckFailed, "target-protocol"):
            core.respond("udp", "peer", common.frame(config("tcp"), b"H", 1, b"hello"))
        bad = config()
        bad["protocol"] = "both"
        with self.assertRaises(common.CheckFailed):
            common.validate_config(bad)

    def test_comparison_cannot_turn_helper_results_into_product_acceptance(self):
        for protocol in ("tcp", "udp"):
            cfg = config(protocol)
            core = ResponderCore(cfg)
            checks = []
            rows = [(1, "tcp-fin-delayed-reply", "tcp-one", b"F", b"after-FIN")] if protocol == "tcp" else [
                (2, None, "udp-one", b"H", b"hello"),
                (3, "udp-maximum-1169", "udp-one", b"P", b"m" * (1169 - common.OVERHEAD)),
                (4, None, "udp-two", b"H", b"hello-two"),
                (5, "udp-second-visitor", "udp-two", b"P", b"second-peer"),
                (6, "udp-legal-after-oversize", "udp-one", b"P", b"legal-one"),
                (7, "udp-legal-after-oversize", "udp-one", b"P", b"legal-two")]
            for sequence, name, peer, kind, payload in rows:
                raw = common.frame(cfg, kind, sequence, payload)
                reply = core.respond(protocol, peer, raw, fin=kind == b"F")
                if name:
                    checks.append({"name": name, **common.echo_reply(cfg, raw, reply)})
            if protocol == "udp":
                core.respond("udp", "udp-one", b"")
                checks.append({"name": "udp-empty", "payload_bytes": 0, "payload_sha256": common.sha(b"")})
                checks.extend({"name": "udp-oversize-no-reply", "wire_bytes": size} for size in (1170, 60000))
            checks.append({"name": "continuous-owned-data", "seconds": 30.1, "protocol": protocol, "frames": 30})
            fresh = ["c" * 64, "d" * 64, "e" * 64]
            checks.extend({"name": "fresh-after-stop-no-response", "fresh_nonce_sha256": value} for value in fresh)
            for command in gates(core):
                core.change_gate(command)
            host = core.snapshot()
            base = host["started_unix_ms"]
            host.update(lifecycle="ended", ended_reason="operator-finish", ended_unix_ms=base + 5000, tcp_fin_replies=1)
            visitor = {"run": host["run"], "protocol": protocol, "nonce_sha256": host["nonce_sha256"],
                       "tool_data_checks_passed": True, "failure": None, "stop_marker": "a" * 32,
                       "done_marker": "b" * 32, "checks": checks, "operator_start_gate": host["gate_history"][0],
                       "source_observation": {"phase": "source-only", "protocol": protocol,
                           "nonce_sha256": host["nonce_sha256"], "source_ip": "8.8.8.8", "observed_unix_ms": base},
                       "host_clock_offset_ms_bounds": [0, 10], "post_stop_nonce_hashes": fresh,
                       "finished_unix_ms": base + 4000}
            observer = {**visitor["source_observation"], "run": visitor["run"], "observer_port_released": True, "release_check": "exclusive_rebind"}
            compared = compare(visitor, host, observer)
            self.assertTrue(compared["paired_tool_checks_passed"])
            self.assertEqual(compared["public_tunnel_acceptance"], "not_assessed")
            for field, value in (("ended_unix_ms", base + 3000), ("rejected_frames", 1)):
                failed = copy.deepcopy(host)
                failed[field] = value
                with self.assertRaises(common.CheckFailed):
                    compare(visitor, failed, observer)
            failed = copy.deepcopy(host)
            next(event for event in failed["events"] if event["kind"] in ("F", "P"))["payload_sha256"] = "f" * 64
            with self.assertRaises(common.CheckFailed):
                compare(visitor, failed, observer)
            unreleased = {**observer, "observer_port_released": False}
            with self.assertRaises(common.CheckFailed):
                compare(visitor, host, unreleased)
            failed = copy.deepcopy(visitor)
            failed["source_observation"]["source_ip"] = "8.8.4.4"
            with self.assertRaises(common.CheckFailed):
                compare(failed, host, observer)


if __name__ == "__main__":
    unittest.main()
