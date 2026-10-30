"""Actions-only native ICE evidence boundaries; no namespaces are created here."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
if sys.platform == "linux":
    SPEC = importlib.util.spec_from_file_location("native_ice_evidence", ROOT / "scripts/network-rewrite-native-ice.py")
    ICE = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(ICE)

TRANSACTION = bytes(range(12))
COOKIE = b"\x21\x12\xa4\x42"
REQUEST = b"\x00\x01\x00\x00" + COOKIE + TRANSACTION
INITIAL = b"\xc0\x00\x00\x00\x01" + bytes(1195)
SHA256 = hashlib.sha256(b"owned payload").hexdigest()


def response(address=(10, 221, 1, 2), port=46001):
    mapped = b"\x00\x01" + struct.pack("!H", port ^ 0x2112) + bytes(a ^ b for a, b in zip(address, COOKIE))
    return b"\x01\x01\x00\x0c" + COOKIE + TRANSACTION + b"\x00\x20\x00\x08" + mapped


def pcap(payload=INITIAL, fragment=0):
    udp = struct.pack("!HHHH", 46001, 46002, len(payload) + 8, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, fragment, 64, 17, 0,
                     bytes((10, 220, 1, 2)), bytes((10, 221, 2, 2))) + udp
    frame = bytes(12) + b"\x08\x00" + ip
    return (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
            + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)


def roles():
    return {role:{"role":role,"passed":True,"explicit_close_completed":True,
                  "rebound_udp_addresses":[f"10.220.{index}.2:{45000+index}",f"10.220.{index}.2:{46000+index}"],
                  "released_udp_sockets":2,"uses_bilateral_ice":True,"input_rejected":True,
                  "input_rejection_code":"permission_required",
                  "payload_verified":True,"file_bytes":262144,"payload_sha256":list(bytes.fromhex(SHA256)),
                  "selected_peer":f"10.221.{3-index}.2:{46000+3-index}","pending_read_cancelled":role == "controller"}
            for role,index in (("controller",1),("host",2))}


def packet(source, destination, source_port, destination_port, payload):
    return {"source":source,"destination":destination,"source_port":source_port,
            "destination_port":destination_port,"payload":payload}


@unittest.skipUnless(sys.platform == "linux", "Linux native ICE namespace evidence")
class NativeIceEvidenceTests(unittest.TestCase):
    def parse(self, data):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "owned.pcap"
            path.write_bytes(data)
            return ICE.packets(path)

    def test_complete_initial_and_real_xor_mapping(self):
        self.assertTrue(ICE.initial(self.parse(pcap())[0]["payload"]))
        self.assertEqual(ICE.xor_mapped(response(), TRANSACTION), ("10.221.1.2", 46001))

    def test_truncation_fragmentation_and_oversize_fail(self):
        data = pcap()
        for size in (0,23,30,len(data)-1):
            with self.subTest(size=size), self.assertRaises(RuntimeError):
                self.parse(data[:size])
        for data in (pcap(bytes(1201)),pcap(fragment=0x2000)):
            with self.assertRaises(RuntimeError):
                self.parse(data)
        corrupt = bytearray(pcap())
        corrupt[24+16+14+20+4:24+16+14+20+6] = (1209).to_bytes(2,"big")
        with self.assertRaises(RuntimeError):
            self.parse(corrupt)

    def test_wrong_stun_transaction_missing_and_truncated_mapping_fail(self):
        for value, transaction in ((response(),bytes(12)),(response()[:-1],TRANSACTION),(REQUEST,TRANSACTION)):
            with self.assertRaises(RuntimeError):
                ICE.xor_mapped(value,transaction)

    def test_legacy_success_partial_file_input_or_cleanup_cannot_pass(self):
        ICE.validate_role_receipts("success",roles(),SHA256)
        ICE.validate_role_receipts("cancel",roles(),SHA256)
        for field,value in (("uses_bilateral_ice",False),("input_rejected",False),("input_rejection_code","stopped"),("file_bytes",262143),
                            ("explicit_close_completed",False),("released_udp_sockets",1),
                            ("payload_sha256",list(bytes(32))),("selected_peer","10.220.2.2:46002")):
            facts = roles()
            facts["controller"][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                ICE.validate_role_receipts("success",facts,SHA256)
        facts = roles()
        facts["host"]["rebound_udp_addresses"] *= 2
        with self.assertRaises(RuntimeError):
            ICE.validate_role_receipts("success",facts,SHA256)
        facts = roles()
        facts["controller"]["pending_read_cancelled"] = False
        with self.assertRaises(RuntimeError):
            ICE.validate_role_receipts("cancel",facts,SHA256)

    def test_blackhole_cannot_be_reported_as_success_or_transfer(self):
        facts = roles()
        for role in facts.values():
            role.update(setup_rejected=True,uses_bilateral_ice=False,payload_verified=False,file_bytes=0)
        ICE.validate_role_receipts("blackhole",facts,SHA256)
        facts["host"]["file_bytes"] = 1
        with self.assertRaises(RuntimeError):
            ICE.validate_role_receipts("blackhole",facts,SHA256)

    def mapping_inputs(self):
        local = [packet("10.220.1.2",ICE.STUN[0],46001,3478,REQUEST),
                 packet(ICE.STUN[0],"10.220.1.2",3478,46001,response()),
                 packet("10.220.1.2","10.221.2.2",46001,46002,REQUEST),
                 packet("10.220.1.2","10.221.2.2",46001,46002,INITIAL)]
        wan = [packet("10.221.1.2",ICE.STUN[0],46001,3478,REQUEST),
               packet("10.221.1.2","10.221.2.2",46001,46002,REQUEST),
               packet("10.221.1.2","10.221.2.2",46001,46002,INITIAL)]
        observations = [{"transaction":list(TRANSACTION),"observed_source":"10.221.1.2:46001"}]
        return local,wan,roles()["controller"],roles()["host"],observations

    def test_same_physical_socket_stun_mapping_and_quinn_initial_are_required(self):
        inputs = self.mapping_inputs()
        facts = ICE.prove_mapping("controller","success",*inputs)
        self.assertEqual(facts["original_socket"],["10.220.1.2",46001])
        self.assertEqual(facts["same_socket_quic_initials"],1)
        for index,field,value in ((0,"source_port",46003),(1,"source_port",46003)):
            corrupted = copy.deepcopy(inputs)
            corrupted[index][-1][field] = value
            with self.assertRaises(RuntimeError):
                ICE.prove_mapping("controller","success",*corrupted)
        corrupted = copy.deepcopy(inputs)
        corrupted[1][-1]["payload"] = b"\xc0\x00\x00\x00\x01" + bytes(1194) + b"x"
        with self.assertRaises(RuntimeError):
            ICE.prove_mapping("controller","success",*corrupted)
        corrupted = copy.deepcopy(inputs)
        corrupted[0][1]["payload"] = response(port=46003)
        with self.assertRaises(RuntimeError):
            ICE.prove_mapping("controller","success",*corrupted)


if __name__ == "__main__":
    unittest.main()
