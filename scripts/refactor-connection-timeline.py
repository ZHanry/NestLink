"""Join redacted observations by identity and signal sequence, never by clock subtraction."""
import argparse
import json
from pathlib import Path
import re

HASH = re.compile(r"[0-9a-f]{64}\Z")
SIGNAL_FIELDS = ("network_generation", "sequence", "description_sequence", "lease_sequence")
STAGES = {"peer_created", "local_description_set", "signal_submitted", "signal_consumed",
          "remote_description_set", "local_candidates", "remote_candidates", "gather_complete",
          "path_checking", "turn_binding_expired", "turn_binding_ready",
          "path_verified", "endpoint_proved", "running_authorized", "display_selected",
          "first_packet_observed", "first_decoded_frame_observed", "first_video_progress_observed",
          "ice_restart", "stopped"}
PREFLIGHT_STAGES = {"request_started", "identity_ready", "request_submitting", "request_submitted",
                    "await_approval", "approval_granted", "await_host_readiness", "host_ready",
                    "permit_received", "peer_creating", "peer_created", "stopped"}
FAILURES = {"unclassified", "invalid_configuration", "invalid_authorization", "authorization_expired",
            "startup_authorization_expired", "endpoint_mismatch", "codec_unavailable", "track_not_authorized",
            "path_not_permitted", "relay_unavailable", "no_selected_pair", "selected_pair_rejected",
            "signaling_rejected", "answer_not_consumed", "ice_check_timeout", "proof_timeout",
            "first_frame_timeout", "operation_timeout", "browser_unavailable", "browser_operation", "cancelled",
            "management_transport", "management_rejected", "sign_in_required", "authorization_revoked",
            "invalid_response", "identity_storage_unavailable", "identity_invalid", "approval_timeout",
            "approval_rejected", "host_readiness_timeout"}
HOST_STAGES = ("offer_received_ms", "answer_published_ms", "first_local_candidate_ms",
               "first_remote_candidate_ms", "gather_complete_ms", "selected_pair_ms",
               "endpoint_proved_ms", "running_authorized_ms", "first_encoded_ms", "first_rtp_write_ms")


def integer(value):
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def fingerprint(value):
    if isinstance(value, list) and len(value) == 32 and all(type(x) is int and 0 <= x <= 255 for x in value):
        value = bytes(value).hex()
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise ValueError("missing or invalid redacted fingerprint")
    return value


def signal_key(sender, signal):
    if not isinstance(signal, dict) or not all(integer(signal.get(key)) and signal[key] > 0 for key in SIGNAL_FIELDS):
        raise ValueError("invalid signal sequence binding")
    return (fingerprint(sender), *(signal[key] for key in SIGNAL_FIELDS))


def failure_observation(event, stages):
    if event is None:
        return None
    if (not isinstance(event, dict) or not integer(event.get('elapsed_ms'))
            or event.get('stage') not in stages or event.get('failure') not in FAILURES):
        raise ValueError('invalid fixed failure observation')
    return {key: event[key] for key in ('elapsed_ms', 'stage', 'failure')}


def preflight_observations(trace):
    if not isinstance(trace, dict) or not isinstance(trace.get('events'), list) or len(trace['events']) > 128:
        raise ValueError('invalid preflight observation budget')
    result = {'request_sha256': fingerprint(trace.get('request_sha256')),
              'connection_generation': trace.get('connection_generation'),
              'first_failure': failure_observation(trace.get('first_failure'), PREFLIGHT_STAGES),
              'stage_elapsed_ms': {}}
    if not integer(result['connection_generation']):
        raise ValueError('invalid preflight generation')
    for key in ('local_device_sha256', 'remote_device_sha256'):
        result[key] = fingerprint(trace[key]) if trace.get(key) is not None else None
    previous = 0
    for event in trace['events']:
        if (not isinstance(event, dict) or not integer(event.get('elapsed_ms'))
                or event['elapsed_ms'] < previous or event.get('stage') not in PREFLIGHT_STAGES):
            raise ValueError('invalid preflight observation or clock order')
        previous = event['elapsed_ms']
        result['stage_elapsed_ms'].setdefault(event['stage'], previous)
        if event.get('failure') is not None:
            failure_observation(event, PREFLIGHT_STAGES)
    return result


def correlate(controller, host_records, server_records):
    if not isinstance(controller, dict) or not isinstance(host_records, list) or not isinstance(server_records, list):
        raise ValueError("expected controller object and log record arrays")
    preflight = preflight_observations(controller['controller_preflight_timeline']) if controller.get('controller_preflight_timeline') is not None else None
    trace = controller.get("controller_timeline", controller)
    if trace is None and preflight is not None:
        if len(host_records) > 10000 or len(server_records) > 10000:
            raise ValueError('observation budget exceeded')
        return {'schema_version': 1, 'request_sha256': preflight['request_sha256'],
                'connection_generation': preflight['connection_generation'], 'controller_preflight': preflight,
                'peer_observations_available': False, 'signals': [], 'cross_clock_latencies_computed': False,
                'limitations': ['No owned peer timeline was recorded; this does not prove ICE or media failure.']}
    if not isinstance(trace, dict) or not isinstance(trace.get("events"), list):
        raise ValueError("missing controller timeline events")
    request = fingerprint(trace.get("request_sha256"))
    generation = trace.get("connection_generation")
    if not integer(generation) or generation == 0:
        raise ValueError("invalid connection generation")
    if len(trace.get("events", [])) > 128 or len(host_records) > 10000 or len(server_records) > 10000:
        raise ValueError("observation budget exceeded")
    local, remote = (fingerprint(trace.get(key)) for key in ("local_device_sha256", "remote_device_sha256"))
    if preflight is not None:
        if (preflight['request_sha256'] != request or preflight['connection_generation'] != generation
                or preflight['local_device_sha256'] != local or preflight['remote_device_sha256'] != remote):
            raise ValueError('preflight and peer authority bindings differ')
    joined = {}
    durations = {}
    previous = 0

    def note(sender, signal, observation):
        key = signal_key(sender, signal)
        joined.setdefault(key, set()).add(observation)

    for event in trace.get("events", []):
        if not isinstance(event, dict):
            raise ValueError("invalid controller observation")
        elapsed, stage = event.get("elapsed_ms"), event.get("stage")
        if not integer(elapsed) or elapsed < previous or stage not in STAGES:
            raise ValueError("invalid controller observation or clock order")
        previous = elapsed
        durations.setdefault(stage, elapsed)
        if event.get("signal") and stage in ("signal_submitted", "signal_consumed"):
            note(local if stage == "signal_submitted" else remote, event["signal"],
                 "controller_submitted" if stage == "signal_submitted" else "controller_consumed")
    host_stages = {}
    matched_hosts = matched_server = 0
    for record in host_records:
        if not isinstance(record, dict):
            raise ValueError("invalid host record")
        if not integer(record.get("connection_generation")):
            raise ValueError("invalid host connection generation")
        if record.get("request_sha256") != request or record.get("connection_generation") != generation:
            continue
        peer = record.get("peer_timeline")
        if not isinstance(peer, dict):
            continue
        if fingerprint(peer.get("local_device_sha256")) != remote or fingerprint(peer.get("remote_device_sha256")) != local:
            raise ValueError("host endpoint binding differs")
        matched_hosts += 1
        for key in HOST_STAGES:
            value = peer.get(key)
            if value is not None:
                if not integer(value):
                    raise ValueError("invalid host timing")
                host_stages[key] = value
        for sender, key, stage in ((remote, "last_local_signal", "host_submitted"),
                                   (local, "last_remote_signal", "host_consumed")):
            if peer.get(key):
                note(sender, peer[key], stage)
    for record in server_records:
        if not isinstance(record, dict):
            raise ValueError("invalid server record")
        fields = record.get("fields", record)
        if not isinstance(fields, dict):
            raise ValueError("invalid server fields")
        if (fields.get("event") != "connection_timeline" or fields.get("request_sha256") != request
                or fields.get("connection_generation") != generation):
            continue
        if not integer(fields.get("connection_generation")):
            raise ValueError("invalid server connection generation")
        stage = {"SignalAccepted": "server_accepted", "SignalResponsePrepared": "server_response_prepared"}.get(fields.get("stage"))
        if not stage:
            continue
        sender = fingerprint(fields.get("sender_device_sha256"))
        if sender not in (local, remote):
            raise ValueError("server endpoint binding differs")
        note(sender, fields, stage)
        matched_server += 1

    def duration(start, end):
        if start not in durations or end not in durations or durations[end] < durations[start]:
            return None
        return durations[end] - durations[start]

    signals = []
    for key, observations in sorted(joined.items()):
        sender, *sequences = key
        consumed = "host_consumed" if sender == local else "controller_consumed"
        signals.append({"sender_device_sha256": sender, **dict(zip(SIGNAL_FIELDS, sequences)),
                        "observations": sorted(observations), "recipient_consumption_observed": consumed in observations,
                        "accepted_without_consumption_observation": "server_accepted" in observations and consumed not in observations})
    return {"schema_version": 1, "request_sha256": request, "connection_generation": generation,
            "controller_preflight": preflight, "peer_observations_available": True,
            "controller_first_failure": failure_observation(trace.get('first_failure'), STAGES),
            "matched_host_records": matched_hosts, "matched_server_records": matched_server,
            "controller_stage_elapsed_ms": durations, "host_stage_elapsed_ms": host_stages,
            "controller_local_durations_ms": {
                "offer_to_remote_description": duration("signal_submitted", "remote_description_set"),
                "offer_to_verified_path": duration("signal_submitted", "path_verified"),
                "proof_to_first_decode_observation": duration("endpoint_proved", "first_decoded_frame_observed")},
            "signals": signals, "cross_clock_latencies_computed": False,
            "limitations": ["Missing observations do not prove failure or non-consumption; rings and logs may be incomplete.",
                            "Server response preparation does not prove delivery or client consumption.",
                            "First decode/video progress are sampled observations, not input-to-display latency or compositor presentation."]}


def read(path):
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("input exceeds 16 MiB")
    return path.read_text(encoding="utf-8-sig")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("controller", "host", "server", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    controller = json.loads(read(args.controller))
    host = [json.loads(line) for line in read(args.host).splitlines() if line.strip()]
    server = [json.loads(line) for line in read(args.server).splitlines() if line.strip()]
    report = correlate(controller, host, server)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
