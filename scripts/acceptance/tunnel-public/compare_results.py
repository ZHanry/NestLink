"""Pair owned data facts; external product receipts still require review."""
import argparse
import json
from pathlib import Path

from common import CheckFailed, require, write_json


def compare(visitor, host, observer):
    require(visitor["protocol"] == host["protocol"] and visitor["protocol"] in ("tcp", "udp"), "protocol-mismatch")
    protocol = visitor["protocol"]
    require(visitor["run"] == host["run"] and visitor["nonce_sha256"] == host["nonce_sha256"], "run-or-nonce-evidence-mismatch")
    require(visitor["tool_data_checks_passed"] is True and visitor["failure"] is None, "visitor-data-checks-failed")
    require(host["lifecycle"] == "ended" and host["ended_reason"] == "operator-finish", "host-not-explicitly-finished-after-probes")
    source = visitor["source_observation"]
    require(source["phase"] == "source-only" and source["protocol"] == protocol
            and source["nonce_sha256"] == visitor["nonce_sha256"]
            and source["source_ip"] == visitor["operator_start_gate"]["source_ip"], "source-observation-mismatch")
    require(set(observer) == {"run", "protocol", "phase", "source_ip", "observed_unix_ms", "nonce_sha256", "observer_port_released", "release_check"}, "observer-receipt-fields")
    require(observer["observer_port_released"] is True and observer["release_check"] == "exclusive_rebind" and observer["run"] == visitor["run"], "observer-not-released-or-wrong-run")
    require(all(observer[field] == source[field] for field in ("protocol", "phase", "source_ip", "observed_unix_ms", "nonce_sha256")), "observer-receipt-mismatch")
    phases = host["gate_history"]
    require([row["phase"] for row in phases] == ["start", "stop-arm", "stopped", "finish"], "host-gate-lifecycle-incomplete")
    times = [host["started_unix_ms"], *[row["observed_unix_ms"] for row in phases], host["ended_unix_ms"]]
    require(times == sorted(times), "host-lifecycle-timestamps-inconsistent")
    require(phases[1]["stop_marker"] == visitor["stop_marker"], "stop-arm-marker-mismatch")
    require(phases[-1]["visitor_done_marker"] == visitor["done_marker"], "visitor-done-marker-mismatch")
    for field in ("source_ip", "acl_prefix", "operator_evidence"):
        require(phases[0][field] == visitor["operator_start_gate"][field], "start-gate-identity-mismatch")
    if protocol == "tcp":
        require(host["tcp_fin_received"] >= 1 and host["tcp_fin_replies"] >= 1, "host-fin-evidence-missing")
    else:
        require(host["udp_empty_received"] >= 1 and host["udp_maximum_received"] >= 1 and host["udp_peer_count"] >= 2, "host-udp-boundaries-missing")
        require(host["udp_authenticated_oversize_received"] == 0, "over-limit-udp-reached-host-target")
    require(host["rejected_frames"] == 0, "host-rejected-frames-require-review")
    checks = visitor["checks"]
    expected = {"continuous-owned-data": 1, "fresh-after-stop-no-response": 3}
    expected.update({"tcp-fin-delayed-reply": 1} if protocol == "tcp" else {
        "udp-empty": 1, "udp-maximum-1169": 1, "udp-second-visitor": 1,
        "udp-oversize-no-reply": 2, "udp-legal-after-oversize": 2})
    require(len(checks) == sum(expected.values()), "visitor-check-count")
    for name, count in expected.items():
        require(sum(row["name"] == name for row in checks) == count, "visitor-check-kind-count")
    positive = {"tcp-fin-delayed-reply": ("tcp", "F"), "udp-maximum-1169": ("udp", "P"),
                "udp-second-visitor": ("udp", "P"), "udp-legal-after-oversize": ("udp", "P")}
    for row in checks:
        if row["name"] in positive:
            protocol, kind = positive[row["name"]]
            require(any(event["protocol"] == protocol and event["kind"] == kind
                        and all(event[field] == row[field] for field in ("sequence", "payload_bytes", "payload_sha256"))
                        for event in host["events"]), "positive-payload-missing-from-host")
        elif row["name"] == "continuous-owned-data":
            require(row["seconds"] >= 30 and row["protocol"] == protocol and row["frames"] > 0,
                    "continuous-phase-evidence-missing")
    if protocol == "udp":
        require({row["wire_bytes"] for row in checks if row["name"] == "udp-oversize-no-reply"} == {1170, 60000},
            "oversize-boundaries-missing")
    fresh = set(visitor["post_stop_nonce_hashes"])
    require(len(fresh) == 3, "fresh-stop-probes-missing")
    require({row["fresh_nonce_sha256"] for row in checks if row["name"] == "fresh-after-stop-no-response"} == fresh,
            "fresh-stop-probe-checks-mismatch")
    require(not any(event["payload_sha256"] in fresh for event in host["events"]), "post-stop-probe-reached-host-target")
    offset_low, offset_high = visitor["host_clock_offset_ms_bounds"]
    require(offset_low <= offset_high and offset_high - offset_low <= 3000, "host-clock-correlation-too-wide")
    require(host["ended_unix_ms"] - offset_high >= visitor["finished_unix_ms"], "host-ended-before-visitor-finished")
    return {"schema_version": 1, "protocol": protocol, "run": visitor["run"], "paired_tool_checks_passed": True,
            "public_tunnel_acceptance": "not_assessed", "product_lease_renewal_verified": False,
            "remaining_required_evidence": ["same-run server-observed source IPs and exact production ACLs",
                                             "Windows product target consent/start/stop and exact publication identities",
                                             "actual signed lease sequence progress during the continuous data phase",
                                             "edge listener/flow cleanup and usage acknowledgement or explicit pending state"],
            "limits": "Matched helper data and declared operator gates are not management authorization receipts."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--visitor", required=True)
    parser.add_argument("--responder", required=True)
    parser.add_argument("--source-observer", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = compare(json.loads(Path(args.visitor).read_text()), json.loads(Path(args.responder).read_text()), json.loads(Path(args.source_observer).read_text()))
    write_json(Path(args.output).absolute(), result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except CheckFailed as error:
        print(json.dumps({"paired_tool_checks_passed": False, "reason": str(error)}))
        raise SystemExit(1) from None
