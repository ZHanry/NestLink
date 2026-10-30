"""Capture evidence must reject truncation, wrong NAT tuples and oversized UDP."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
if sys.platform == "linux":
    SPEC = importlib.util.spec_from_file_location("routed_evidence", ROOT / "scripts/network-rewrite-routed.py")
    ROUTED = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(ROUTED)


def pcap(payload=None, fragment=0):
    if payload is None:
        payload = b"\xc0\x00\x00\x00\x01" + bytes(1195)
    udp = struct.pack("!HHHH", 55001, 4433, len(payload) + 8, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, fragment, 64, 17, 0,
                     bytes((10, 211, 1, 2)), bytes((10, 211, 1, 1))) + udp
    frame = bytes(12) + b"\x08\x00" + ip
    return (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
            + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)


@unittest.skipUnless(sys.platform == "linux", "Linux namespace experiment parser")
class RoutedCaptureTests(unittest.TestCase):
    def facts(self, data, source="10.211.1.2"):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.pcap"
            path.write_bytes(data)
            return ROUTED.capture_facts(path, source, "10.211.1.1", 55001, 4433)

    def test_complete_initial_binds_actual_translated_port_and_size(self):
        facts = self.facts(pcap())
        self.assertEqual(facts["full_outer_quic_initials"], 1)
        self.assertEqual(facts["maximum_udp_payload_bytes"], 1200)
        self.assertEqual(facts["expected_forward_flow"], ["10.211.1.2", "10.211.1.1", 55001, 4433])

    def test_partial_headers_frames_and_udp_never_count(self):
        data = pcap()
        for end in (0, 23, 30, len(data) - 1):
            with self.subTest(end=end), self.assertRaises(RuntimeError):
                self.facts(data[:end])
        corrupt = bytearray(data)
        corrupt[24 + 16 + 14 + 20 + 4:24 + 16 + 14 + 20 + 6] = (1209).to_bytes(2, "big")
        with self.assertRaises(RuntimeError):
            self.facts(corrupt)

    def test_wrong_nat_source_outer_oversize_fragmentation_and_plaintext_fail(self):
        with self.assertRaises(RuntimeError):
            self.facts(pcap(), "10.210.1.2")
        for data in (pcap(bytes(1201)), pcap(fragment=0x2000), pcap(ROUTED.MARKER + bytes(1200 - len(ROUTED.MARKER))),
                     pcap(b"\x40" + bytes(1199))):
            with self.subTest(length=len(data)), self.assertRaises(RuntimeError):
                self.facts(data)


if __name__ == "__main__":
    unittest.main()
