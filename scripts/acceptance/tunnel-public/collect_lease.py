"""Bounded read-only owned IPC evidence; never approves, starts or stops a service."""
import argparse
import base64
import json
from pathlib import Path
import time
import uuid

OBS_FIELDS = set("schema_version runtime_generation issuer_delegation publication_id publication_generation service_id service_revision choice_revision definition_sha256 target_sha256 lease_sequence issued_at_unix_ms expires_at_unix_ms verified_issuer_ed25519 lease_claims_sha256 signed_lease_envelope_sha256 issuer_signature_base64url sample_started_unix_ms sample_finished_unix_ms opened_connections closed_connections admitted_bytes cleanup_pending counters_non_atomic".split())

def require(ok, code):
    if not ok:
        raise ValueError(code)

def load(path):
    raw = Path(path).read_bytes()
    require(len(raw) <= 16 * 1024 * 1024, "input-bound")
    return json.loads(raw)

def octets(value, size):
    require(isinstance(value, list) and len(value) == size and all(type(n) is int and 0 <= n <= 255 for n in value), "byte-array")
    return bytes(value)

def plan_valid(p):
    require(set(p) == set("source_sha run nonce_sha256 protocol runtime_id runtime_generation service_id approved_revision choice_revision publication_id publication_generation definition_sha256 target_sha256 service_issuer_ed25519 origin deployment_id approval_receipt_sha256 windows_binary_sha256 trusted_node_policy_issuer".split()), "plan-fields")
    for key in ("run", "runtime_id", "service_id", "deployment_id"):
        require(str(uuid.UUID(p[key])) == p[key], "plan-uuid")
    require(p["publication_id"] is None or str(uuid.UUID(p["publication_id"])) == p["publication_id"], "plan-publication")
    require(p["protocol"] in ("tcp", "udp") and p["origin"].startswith("https://"), "plan-origin-protocol")
    for key in ("source_sha", "nonce_sha256", "approval_receipt_sha256", "windows_binary_sha256"):
        require(isinstance(p[key], str) and len(p[key]) == (40 if key == "source_sha" else 64) and all(c in "0123456789abcdef" for c in p[key]), "plan-digest")
    for key in ("runtime_generation", "approved_revision", "choice_revision"):
        require(type(p[key]) is int and 0 < p[key] < 2**63, "plan-revision")
    require(p["approved_revision"] == p["choice_revision"] + 1, "approval-revision")
    require(p["publication_generation"] is None or type(p["publication_generation"]) is int and 0 < p["publication_generation"] < 2**63, "plan-publication-generation")
    if p["service_issuer_ed25519"] is not None:
        octets(p["service_issuer_ed25519"], 32)
    for key in ("definition_sha256", "target_sha256", "trusted_node_policy_issuer"):
        octets(p[key], 32)

def observation_valid(o, p, publication):
    require(set(o) == OBS_FIELDS and o["schema_version"] == 1, "observation-fields")
    for key in ("runtime_generation", "service_id", "choice_revision", "definition_sha256", "target_sha256"):
        require(o[key] == p[key], "observation-scope")
    require(o["service_revision"] == p["approved_revision"], "observation-revision")
    require(p["service_issuer_ed25519"] is None or o["verified_issuer_ed25519"] == p["service_issuer_ed25519"], "observation-issuer-pin")
    require(isinstance(o["issuer_delegation"], dict) and set(o["issuer_delegation"]) == {"verified_policy_issuer_ed25519", "claims", "signature"}, "original-public-delegation-required")
    require(publication is None or o["publication_id"] == publication, "publication-changed")
    require(str(uuid.UUID(o["publication_id"])) == o["publication_id"], "publication-id")
    require(p["publication_generation"] is None or o["publication_generation"] == p["publication_generation"], "publication-generation")
    for key in ("lease_sequence", "publication_generation", "issued_at_unix_ms", "expires_at_unix_ms", "sample_started_unix_ms", "sample_finished_unix_ms", "opened_connections", "closed_connections", "admitted_bytes"):
        require(type(o[key]) is int and 0 <= o[key] < 2**64, "observation-number")
    require(o["issued_at_unix_ms"] <= o["sample_started_unix_ms"] <= o["sample_finished_unix_ms"] < o["expires_at_unix_ms"], "sample-not-live")
    require(o["cleanup_pending"] is False and o["counters_non_atomic"] is True, "observation-state")
    for key in ("lease_claims_sha256", "signed_lease_envelope_sha256", "verified_issuer_ed25519"):
        octets(o[key], 32)
    verify_delegation(o, p)
    sig = base64.urlsafe_b64decode(o["issuer_signature_base64url"] + "==")
    require(len(sig) == 64 and base64.urlsafe_b64encode(sig).decode().rstrip("=") == o["issuer_signature_base64url"], "signature-encoding")

def verify_delegation(o, p):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    proof = o["issuer_delegation"]
    require(proof["verified_policy_issuer_ed25519"] == p["trusted_node_policy_issuer"], "delegation-root-pin")
    raw = octets(proof["claims"], len(proof["claims"]))
    require(0 < len(raw) <= 1024, "public-delegation-bound")
    signature = octets(proof["signature"], 64)
    Ed25519PublicKey.from_public_bytes(octets(p["trusted_node_policy_issuer"], 32)).verify(signature, b"NestLink/v15/service-issuer-delegation/v1\0" + raw)
    d = json.loads(raw)
    require(set(d) == set("schema_version deployment_id security_epoch policy_revision service_issuer issued_at_unix_ms expires_at_unix_ms".split()), "delegation-fields")
    require(d["schema_version"] == 1 and d["deployment_id"] == p["deployment_id"] and d["service_issuer"] == o["verified_issuer_ed25519"], "delegation-binding")
    require(0 < d["expires_at_unix_ms"] - d["issued_at_unix_ms"] <= 3600000, "delegation-validity-bound")
    require(d["issued_at_unix_ms"] <= o["issued_at_unix_ms"] <= o["sample_started_unix_ms"] <= o["sample_finished_unix_ms"] < o["expires_at_unix_ms"] <= d["expires_at_unix_ms"], "delegation-sample-validity")
    return d

def checked_host(snapshot, p, generation, phase):
    require(snapshot["generation"] == generation and snapshot["authentication"] == "signed_in" and snapshot["lifecycle"] == "running", "runtime-session-changed")
    server = snapshot.get("server") or {}
    require(server.get("origin") == p["origin"] and server.get("deployment_id") == p["deployment_id"], "deployment-changed")
    host = snapshot.get("local_service_host")
    if host is not None:
        require(host["service_id"] == p["service_id"] and host["approved_revision"] == p["approved_revision"] and host["approved_from_revision"] == p["choice_revision"] and host["protocol"] == p["protocol"], "approved-host-changed")
    if phase == "traffic":
        require(host is not None and host["status"] == "running" and host["cleanup_failed"] is False, "host-not-running")
    return host

class CollectionFailed(ValueError):
    def __init__(self, receipt):
        super().__init__("collection-failed-no-acceptance")
        self.receipt = receipt


def collect(client, p, samples, interval, phase):
    plan_valid(p)
    require(client.runtime == p["runtime_id"], "approved-runtime-changed")
    receipt = {"schema_version": 1, "source_sha": p["source_sha"], "run": p["run"], "nonce_sha256": p["nonce_sha256"], "protocol": p["protocol"], "runtime_id": client.runtime, "runtime_generation": p["runtime_generation"], "phase": phase, "observations": [], "rejections": [], "host_states": [], "complete": False, "signature_verification": "not_performed", "public_tunnel_acceptance": "not_assessed"}
    p = dict(p)
    publication = p["publication_id"]
    generation = p["runtime_generation"]
    deadline = min(time.monotonic() + 90, getattr(client, "overall_deadline", float("inf")))
    try:
        for index in range(samples):
            require(time.monotonic() < deadline, "collection-total-budget")
            snapshot = client.request({"command": "snapshot"}, generation)["snapshot"]
            host = checked_host(snapshot, p, generation, phase)
            receipt["host_states"].append({"sample_unix_ms": int(time.time() * 1000), "owner_present": host is not None, "status": host["status"] if host else None, "cleanup_failed": host["cleanup_failed"] if host else None})
            response = client.request({"command": "get_local_service_lease_observation", "request": {"service_id": p["service_id"], "approved_revision": p["approved_revision"], "expected_publication_id": publication}}, generation)
            result = response["result"]
            rejected = None
            if result["reply"] == "rejected":
                reason = result.get("reason")
                rejected = {"attempt": index + 1, "sample_unix_ms": int(time.time() * 1000), "reason": reason if reason in ("stopped", "invalid", "stale_generation", "capacity") else "unknown", "interpretation": "rejected-not-an-observation"}
                receipt["rejections"].append(rejected)
            post_host = checked_host(response["snapshot"], p, generation, phase)
            if phase == "traffic":
                require(post_host == host, "approved-host-changed-during-read")
            require(time.monotonic() < deadline, "collection-total-budget")
            if result["reply"] == "rejected":
                if phase == "traffic":
                    # The product maps any SDK sampling failure to stopped, including
                    # race/fence/expiry. Do not claim to distinguish these causes.
                    require(result["reason"] == "stopped", "fatal-observation-rejection")
                    interpretation = "ambiguous-unavailable-not-an-observation"
                else:
                    require(result["reason"] in ("stopped", "invalid"), "unexpected-observation-rejection")
                    interpretation = "read-denied-not-cleanup-proof"
                rejected["interpretation"] = interpretation
            else:
                require(phase == "traffic" and result["reply"] == "local_service_lease_observation", "unexpected-live-after-stop")
                require(host is not None and host["status"] == "running" and host["cleanup_failed"] is False, "host-not-running")
                observation = result["observation"]
                observation_valid(observation, p, publication)
                publication = observation["publication_id"]
                p["service_issuer_ed25519"] = observation["verified_issuer_ed25519"]
                if receipt["observations"]:
                    require(observation["publication_generation"] == receipt["observations"][0]["publication_generation"], "publication-generation-changed")
                receipt["observations"].append(observation)
            if index + 1 < samples:
                time.sleep(min(interval, max(0, deadline - time.monotonic())))
    except Exception:
        receipt["publication_id"] = publication
        receipt["failure"] = "collection-failed-no-acceptance"
        raise CollectionFailed(receipt) from None
    receipt["publication_id"] = publication
    receipt["complete"] = phase == "after-stop" or len(receipt["observations"]) >= 2
    if not receipt["complete"]:
        receipt["failure"] = "insufficient-actual-lease-observations"
    return receipt

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--phase", choices=("traffic", "after-stop"), required=True)
    parser.add_argument("--samples", type=int, default=60)
    parser.add_argument("--interval", type=float, default=0.5)
    args = parser.parse_args()
    require(2 <= args.samples <= 180 and 0.5 <= args.interval <= 5 and args.samples * args.interval <= 90, "collection-budget")
    p = load(args.plan)
    plan_valid(p)
    require(args.phase != "after-stop" or p["publication_id"] is not None, "stop-requires-pinned-publication")
    from ipc_readonly import PinnedIpcClient
    # Exclusive creation prevents silently replacing evidence. Never persist raw snapshots.
    with open(args.output, "x", encoding="utf-8") as output:
        try:
            with PinnedIpcClient() as client:
                receipt = collect(client, p, args.samples, args.interval, args.phase)
        except CollectionFailed as failure:
            json.dump(failure.receipt, output, separators=(",", ":"))
            raise SystemExit("collection-failed-no-acceptance") from None
        except Exception:
            json.dump({"schema_version": 1, "run": p["run"], "complete": False, "failure": "collection-failed-no-acceptance", "public_tunnel_acceptance": "not_assessed"}, output)
            raise SystemExit("collection-failed-no-acceptance") from None
        json.dump(receipt, output, separators=(",", ":"))
        if not receipt["complete"]:
            raise SystemExit("insufficient-actual-lease-observations")

if __name__ == "__main__":
    main()
