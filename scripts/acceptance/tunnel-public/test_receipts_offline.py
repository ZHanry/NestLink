"""Authored offline tests; fixtures are synthetic issuer-signed test data, not receipts."""
import base64
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from collect_lease import collect, observation_valid, plan_valid
from server_claims import LEASE_DOMAIN, ENVELOPE_DOMAIN, capture, pair, verify_one


def uid(n):
    return f"{n:08x}-1111-4111-8111-111111111111"


def fixture():
    key = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
    root = Ed25519PrivateKey.from_private_bytes(bytes([8]) * 32)
    public = list(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    root_public = list(root.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    p = dict(source_sha="5" * 40, run=uid(1), nonce_sha256="a" * 64, protocol="tcp", runtime_id=uid(2), runtime_generation=2, service_id=uid(3), approved_revision=4, choice_revision=3, publication_id=uid(4), publication_generation=1, definition_sha256=[1] * 32, target_sha256=[2] * 32, service_issuer_ed25519=public, origin="https://owned.example", deployment_id=uid(5), approval_receipt_sha256="b" * 64, windows_binary_sha256="c" * 64, trusted_node_policy_issuer=root_public)
    delegation = dict(schema_version=1, deployment_id=p["deployment_id"], security_epoch=1, policy_revision=2, service_issuer=public, issued_at_unix_ms=1000, expires_at_unix_ms=90000)
    delegation_raw = json.dumps(delegation, separators=(",", ":")).encode()
    issuer = dict(source_sha=p["source_sha"], deployment_id=p["deployment_id"], service_issuer_ed25519=public, provenance="synthetic test only", issuer=dict(claims=list(delegation_raw), signature=list(root.sign(b"NestLink/v15/service-issuer-delegation/v1\0" + delegation_raw))))
    issuer_bytes = json.dumps(issuer).encode()
    observations, rows = [], []
    for sequence, at in ((1, 10000), (2, 20000)):
        c = dict(schema_version=1, deployment_id=p["deployment_id"], security_epoch=1, policy_revision=2, publication_id=p["publication_id"], publication_generation=1, service_id=p["service_id"], service_revision=4, choice_revision=3, definition_sha256=p["definition_sha256"], target_sha256=p["target_sha256"], definition={"requested_ingress": {"protocol": "tcp"}}, lease_sequence=sequence, issued_at_unix_ms=at - 1000, expires_at_unix_ms=at + 2000)
        # Preserve non-canonical spacing deliberately: verifier must use exact DB bytes.
        raw = json.dumps(c, separators=(", ", ": ")).encode()
        sig = key.sign(LEASE_DOMAIN + raw)
        envelope = ENVELOPE_DOMAIN + len(raw).to_bytes(8, "big") + raw + len(sig).to_bytes(8, "big") + sig
        o = {k: c[k] for k in ("publication_id", "publication_generation", "service_id", "service_revision", "choice_revision", "definition_sha256", "target_sha256", "lease_sequence", "issued_at_unix_ms", "expires_at_unix_ms")}
        o.update(schema_version=1, runtime_generation=2, issuer_delegation=dict(verified_policy_issuer_ed25519=root_public, claims=issuer["issuer"]["claims"], signature=issuer["issuer"]["signature"]), verified_issuer_ed25519=public, lease_claims_sha256=list(hashlib.sha256(raw).digest()), signed_lease_envelope_sha256=list(hashlib.sha256(envelope).digest()), issuer_signature_base64url=base64.urlsafe_b64encode(sig).decode().rstrip("="), sample_started_unix_ms=at, sample_finished_unix_ms=at + 1, opened_connections=1, closed_connections=0, admitted_bytes=sequence * 100, cleanup_pending=False, counters_non_atomic=True)
        observations.append(o)
        rows.append(dict(state=0, claims_utf8_base64=base64.b64encode(raw).decode(), claims_sha256=hashlib.sha256(raw).hexdigest(), lease_sequence=sequence))
    common = dict(source_sha=p["source_sha"], run=p["run"], nonce_sha256=p["nonce_sha256"], publication_id=p["publication_id"], complete=True)
    local = dict(common, runtime_id=p["runtime_id"], runtime_generation=2, phase="traffic", observations=observations)
    captured = dict(common, rows=rows)
    visitor = dict(run=p["run"], nonce_sha256=p["nonce_sha256"], protocol="tcp", tool_data_checks_passed=True, failure=None, host_clock_offset_ms_bounds=[-10, 10], checks=[dict(name="continuous-owned-data", seconds=30, frames=10, phase_started_unix_ms=5000, phase_finished_unix_ms=35000)])
    return p, captured, local, visitor, issuer_bytes


class ReceiptTests(unittest.TestCase):
    def test_real_signature_pair_progress_and_no_raw_export(self):
        p, c, local, visitor, issuer = fixture()
        receipt = pair(p, c, local, visitor)
        self.assertTrue(receipt["product_lease_renewal_verified"])
        self.assertEqual(receipt["public_tunnel_acceptance"], "not_assessed")
        self.assertNotIn("claims_utf8_base64", json.dumps(receipt))
        self.assertNotIn("issuer_signature_base64url", json.dumps(receipt))

    def test_exact_bytes_required_and_signature_tampering_fails(self):
        p, c, local, _, _ = fixture()
        raw = base64.b64decode(c["rows"][0]["claims_utf8_base64"])
        verify_one(local["observations"][0], raw, p)
        with self.assertRaises(Exception):
            verify_one(local["observations"][0], json.dumps(json.loads(raw), separators=(",", ":")).encode(), p)
        changed = copy.deepcopy(local["observations"][0])
        changed["issuer_signature_base64url"] = base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
        with self.assertRaises(Exception):
            verify_one(changed, raw, p)

    def test_missing_sequence_does_not_manufacture_progress(self):
        p, c, local, visitor, issuer = fixture()
        c["rows"] = c["rows"][:1]
        receipt = pair(p, c, local, visitor)
        self.assertFalse(receipt["product_lease_renewal_verified"])
        self.assertEqual(len(receipt["failed_unmatched_samples"]), 1)

    def test_wrong_root_or_publication_or_expired_sample_rejects(self):
        p, c, local, visitor, issuer = fixture()
        bad = copy.deepcopy(p)
        bad["trusted_node_policy_issuer"] = [0] * 32
        with self.assertRaises(Exception):
            pair(bad, c, local, visitor)
        bad = copy.deepcopy(local["observations"][0])
        bad["publication_id"] = uid(99)
        with self.assertRaises(ValueError):
            observation_valid(bad, p, p["publication_id"])
        bad = copy.deepcopy(local["observations"][0])
        bad["sample_finished_unix_ms"] = bad["expires_at_unix_ms"]
        with self.assertRaises(ValueError):
            observation_valid(bad, p, p["publication_id"])

    def test_sample_outside_clock_bounded_traffic_window_is_not_progress(self):
        p, c, local, visitor, issuer = fixture()
        visitor["checks"][0]["phase_started_unix_ms"] = 19000
        receipt = pair(p, c, local, visitor)
        self.assertFalse(receipt["product_lease_renewal_verified"])

    def test_ipc_collection_only_reads_and_pins_discovered_publication(self):
        p, _, local, _, _ = fixture()
        p["publication_id"] = None
        p["publication_generation"] = None
        commands = []
        class FakeClient:
            runtime = p["runtime_id"]
            def request(self, command, generation):
                commands.append(copy.deepcopy(command))
                snapshot = dict(generation=2, authentication="signed_in", lifecycle="running", server={"origin": p["origin"], "deployment_id": p["deployment_id"]}, local_service_host=dict(service_id=p["service_id"], approved_revision=4, approved_from_revision=3, protocol="tcp", status="running", cleanup_failed=False))
                if command["command"] == "snapshot":
                    return {"snapshot": snapshot}
                return dict(snapshot=snapshot, result=dict(reply="local_service_lease_observation", observation=copy.deepcopy(local["observations"][len(commands) // 2 - 1])))
        with patch("collect_lease.time.sleep", return_value=None):
            result = collect(FakeClient(), p, 2, 0.5, "traffic")
        self.assertTrue(result["complete"])
        self.assertEqual([c["command"] for c in commands], ["snapshot", "get_local_service_lease_observation"] * 2)
        self.assertIsNone(commands[1]["request"]["expected_publication_id"])
        self.assertEqual(commands[3]["request"]["expected_publication_id"], uid(4))

    def test_public_delegation_size_bound_rejects(self):
        p, _, local, _, _ = fixture()
        bad = copy.deepcopy(local["observations"][0])
        bad["issuer_delegation"]["claims"] = [0] * 1025
        with self.assertRaises(ValueError):
            observation_valid(bad, p, p["publication_id"])

    def test_after_stop_receipt_records_denial_without_cleanup_claim(self):
        p, _, _, _, _ = fixture()
        commands = []
        class FakeClient:
            runtime = p["runtime_id"]
            def request(self, command, generation):
                commands.append(command["command"])
                snapshot = dict(generation=2, authentication="signed_in", lifecycle="running", server={"origin": p["origin"], "deployment_id": p["deployment_id"]}, local_service_host=dict(service_id=p["service_id"], approved_revision=4, approved_from_revision=3, protocol="tcp", status="stopped", cleanup_failed=False))
                return dict(snapshot=snapshot, result=dict(reply="rejected", reason="stopped"))
        with patch("collect_lease.time.sleep", return_value=None):
            receipt = collect(FakeClient(), p, 2, 0.5, "after-stop")
        self.assertTrue(receipt["complete"])
        self.assertEqual(len(receipt["rejections"]), 2)
        self.assertFalse(receipt["observations"])
        self.assertEqual(receipt["public_tunnel_acceptance"], "not_assessed")
        self.assertEqual(commands, ["snapshot", "get_local_service_lease_observation"] * 2)

    def test_sqlite_capture_does_not_write_database_and_preserves_exact_bytes(self):
        p, c, _, _, _ = fixture()
        raw = base64.b64decode(c["rows"][0]["claims_utf8_base64"])
        with tempfile.TemporaryDirectory() as d:
            dbpath, output = Path(d) / "db.sqlite", Path(d) / "private.json"
            with closing(sqlite3.connect(dbpath)) as db:
                db.execute("CREATE TABLE service_publications(id TEXT,service_id TEXT,claims_json TEXT,state INTEGER,generation INTEGER,service_revision INTEGER,control_runtime_id TEXT,promised_until INTEGER)")
                db.execute("INSERT INTO service_publications VALUES(?,?,?,?,?,?,?,?)", (p["publication_id"], p["service_id"], raw.decode(), 0, 1, 4, uid(9), 50000))
                db.commit()
            before = dbpath.read_bytes()
            with patch("server_claims.time.sleep", return_value=None):
                capture(dbpath, p, output, 1)
            self.assertEqual(before, dbpath.read_bytes())
            saved = json.loads(output.read_text())
            self.assertTrue(saved["complete"])
            self.assertEqual(base64.b64decode(saved["rows"][0]["claims_utf8_base64"]), raw)

if __name__ == "__main__":
    unittest.main()
