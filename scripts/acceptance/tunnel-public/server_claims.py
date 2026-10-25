"""Capture exact stored claims using query-only SQLite; pair original IPC signatures offline.
No DB write, network request, token/key read, signing, or raw claim export receipt.
Private capture includes capability-bearing nested signed usage grants: keep it private.
"""
import argparse
from contextlib import closing
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from collect_lease import load, require, octets, plan_valid, observation_valid, verify_delegation

LEASE_DOMAIN = b"NestLink/v15/service-publication-lease/v1\0"
ENVELOPE_DOMAIN = b"NestLink/v15/service-signed-lease-observation/v1\0"

def sha(raw):
    return hashlib.sha256(raw).digest()

def private_output(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8")

def capture(database, plan, output, seconds):
    plan_valid(plan)
    require(plan["publication_id"] is not None and plan["publication_generation"] is not None and plan["service_issuer_ed25519"] is not None and 1 <= seconds <= 90, "capture-pinned-publication-budget")
    database = Path(database).resolve(strict=True)
    require(database.is_file(), "database-file")
    result = {"schema_version": 1, "source_sha": plan["source_sha"], "run": plan["run"], "nonce_sha256": plan["nonce_sha256"], "service_id": plan["service_id"], "publication_id": plan["publication_id"], "complete": False, "rows": []}
    seen = set()
    deadline = time.monotonic() + seconds
    with private_output(output) as out:
        try:
            # mode=ro preserves live WAL visibility; immutable=1 would ignore live updates.
            with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=0.2)) as db:
                db.execute("PRAGMA query_only=ON")
                require(db.execute("PRAGMA query_only").fetchone()[0] == 1, "query-only-required")
                for _ in range(360):
                    if time.monotonic() >= deadline:
                        break
                    row = db.execute("SELECT claims_json,state,generation,service_revision,control_runtime_id,promised_until FROM service_publications WHERE id=? AND service_id=?", (plan["publication_id"], plan["service_id"])).fetchone()
                    if row is not None:
                        raw = row[0].encode("utf-8")
                        require(0 < len(raw) <= 32768, "stored-claim-bound")
                        # Parsing checks scope only. Preserve original exact bytes; never dump parsed claims.
                        claims = json.loads(raw)
                        require(claims["publication_id"] == plan["publication_id"] and claims["service_id"] == plan["service_id"] and claims["service_revision"] == plan["approved_revision"], "stored-scope-changed")
                        require(all(claims[k] == plan[k] for k in ("publication_generation", "choice_revision", "definition_sha256", "target_sha256", "deployment_id")), "stored-approved-binding")
                        require(type(claims["lease_sequence"]) is int and 0 < claims["lease_sequence"] < 2**63, "stored-sequence-bound")
                        require(row[2] == claims["publication_generation"] and row[3] == claims["service_revision"], "stored-row-binding")
                        fingerprint = (sha(raw).hex(), row[1])
                        if fingerprint not in seen:
                            seen.add(fingerprint)
                            result["rows"].append({"read_unix_ms": int(time.time() * 1000), "state": row[1], "claims_utf8_base64": base64.b64encode(raw).decode(), "claims_sha256": sha(raw).hex(), "lease_sequence": claims["lease_sequence"], "control_runtime_id": row[4], "promised_until": row[5]})
                    time.sleep(min(0.25, max(0, deadline - time.monotonic())))
            result["complete"] = True
        finally:
            json.dump(result, out, separators=(",", ":"))

def verify_one(observation, raw, plan):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    observation_valid(observation, plan, plan["publication_id"])
    require(0 < len(raw) <= 32768, "exact-claims-bound")
    signature = base64.urlsafe_b64decode(observation["issuer_signature_base64url"] + "==")
    # Use the separately pinned key, never the key asserted by the observation alone.
    delegation = verify_delegation(observation, plan)
    key = octets(delegation["service_issuer"], 32)
    Ed25519PublicKey.from_public_bytes(key).verify(signature, LEASE_DOMAIN + raw)
    envelope = ENVELOPE_DOMAIN + len(raw).to_bytes(8, "big") + raw + len(signature).to_bytes(8, "big") + signature
    require(sha(raw) == octets(observation["lease_claims_sha256"], 32) and sha(envelope) == octets(observation["signed_lease_envelope_sha256"], 32), "signed-envelope-mismatch")
    claims = json.loads(raw)
    require(claims["schema_version"] == 1 and claims["deployment_id"] == plan["deployment_id"], "claims-deployment")
    require(all(claims[key] == delegation[key] for key in ("security_epoch", "policy_revision")), "delegation-epoch-policy")
    for key in ("publication_id", "publication_generation", "service_id", "service_revision", "choice_revision", "definition_sha256", "target_sha256", "lease_sequence", "issued_at_unix_ms", "expires_at_unix_ms"):
        require(claims[key] == observation[key], "signed-claim-summary-mismatch")
    require(claims["definition"]["requested_ingress"]["protocol"] == plan["protocol"], "signed-protocol-mismatch")
    return {"lease_sequence": observation["lease_sequence"], "claims_sha256": sha(raw).hex(), "signed_envelope_sha256": sha(envelope).hex(), "sample_started_unix_ms": observation["sample_started_unix_ms"], "sample_finished_unix_ms": observation["sample_finished_unix_ms"], "signature_verified": True}

def pair(plan, capture_data, local, visitor):
    plan_valid(plan)
    require(plan["publication_id"] is not None and plan["publication_generation"] is not None and plan["service_issuer_ed25519"] is not None, "pair-pinned-publication-required")
    require(capture_data["complete"] is True and local["complete"] is True and local["phase"] == "traffic", "incomplete-input")
    require(isinstance(local["observations"], list) and 2 <= len(local["observations"]) <= 180, "insufficient-or-unbounded-actual-observations")
    rejections = local.get("rejections", [])
    require(isinstance(rejections, list) and len(rejections) + len(local["observations"]) <= 180, "rejection-record-bound")
    for rejected in rejections:
        require(set(rejected) == {"attempt", "sample_unix_ms", "reason", "interpretation"}, "rejection-record-fields")
        require(type(rejected["attempt"]) is int and 1 <= rejected["attempt"] <= 180 and type(rejected["sample_unix_ms"]) is int and 0 <= rejected["sample_unix_ms"] < 2**64, "rejection-record-time-attempt")
        require(rejected["reason"] == "stopped" and rejected["interpretation"] == "ambiguous-unavailable-not-an-observation", "fatal-rejection-not-pairable")
    for item in (capture_data, local):
        require(item["source_sha"] == plan["source_sha"] and item["run"] == plan["run"] and item["nonce_sha256"] == plan["nonce_sha256"] and item["publication_id"] == plan["publication_id"], "receipt-run-publication")
    require(local["runtime_id"] == plan["runtime_id"] and local["runtime_generation"] == plan["runtime_generation"], "receipt-runtime")
    require(visitor["run"] == plan["run"] and visitor["nonce_sha256"] == plan["nonce_sha256"] and visitor["protocol"] == plan["protocol"] and visitor["tool_data_checks_passed"] is True and visitor["failure"] is None, "visitor-run-data")
    phases = [row for row in visitor["checks"] if row["name"] == "continuous-owned-data"]
    require(len(phases) == 1 and phases[0]["seconds"] >= 30 and phases[0]["frames"] > 0, "traffic-phase")
    low, high = visitor["host_clock_offset_ms_bounds"]
    require(type(low) is int and type(high) is int and low <= high and high - low <= 3000, "clock-offset-bounds")
    start = phases[0]["phase_started_unix_ms"] + high
    finish = phases[0]["phase_finished_unix_ms"] + low
    require(start < finish, "traffic-window")
    exact = {}
    for row in capture_data["rows"]:
        if row["state"] != 0:
            continue
        raw = base64.b64decode(row["claims_utf8_base64"], validate=True)
        require(sha(raw).hex() == row["claims_sha256"], "capture-digest")
        exact[row["claims_sha256"]] = raw
    verified, missed = [], []
    last_sample = -1
    last_sequence = -1
    for o in local["observations"]:
        observation_valid(o, plan, plan["publication_id"])
        require(o["sample_started_unix_ms"] >= last_sample and o["lease_sequence"] >= last_sequence, "observation-order")
        last_sample, last_sequence = o["sample_finished_unix_ms"], o["lease_sequence"]
        digest = octets(o["lease_claims_sha256"], 32).hex()
        if digest not in exact:
            missed.append({"lease_sequence": o["lease_sequence"], "reason": "exact-stored-sequence-not-captured"})
            continue
        raw = exact[digest]
        v = verify_one(o, raw, plan)
        if start <= v["sample_started_unix_ms"] <= v["sample_finished_unix_ms"] <= finish:
            verified.append(v)
    sequences = sorted(set(row["lease_sequence"] for row in verified))
    progressed = len(sequences) >= 2 and sequences[-1] > sequences[0]
    return {"schema_version": 1, "source_sha": plan["source_sha"], "run": plan["run"], "nonce_sha256": plan["nonce_sha256"], "publication_id": plan["publication_id"], "runtime_id": plan["runtime_id"], "runtime_generation": plan["runtime_generation"], "trusted_node_policy_issuer": plan["trusted_node_policy_issuer"], "verified_samples_in_traffic_window": verified, "failed_unmatched_samples": missed, "rejected_observation_samples": rejections, "product_lease_renewal_verified": progressed, "public_tunnel_acceptance": "not_assessed", "stop_cleanup_usage_verified": False, "limits": "Node policy root is independently operator-pinned; delegation and lease signatures verify exact original bytes. This verifies original issuer signatures and exact stored bytes, not the entire Rust lease semantic validator. Raw claims remain private. Counter readings are non-atomic."}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("capture")
    c.add_argument("--db", required=True)
    c.add_argument("--seconds", type=float, default=90)
    v = sub.add_parser("pair")
    for key in ("capture", "observations", "visitor"):
        v.add_argument("--" + key, required=True)
    for s in (c, v):
        s.add_argument("--plan", required=True)
        s.add_argument("--output", required=True)
    args = parser.parse_args()
    p = load(args.plan)
    if args.command == "capture":
        capture(args.db, p, args.output, args.seconds)
    else:
        result = pair(p, load(args.capture), load(args.observations), load(args.visitor))
        with private_output(args.output) as out:
            json.dump(result, out, separators=(",", ":"))

if __name__ == "__main__":
    main()
