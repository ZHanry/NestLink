#!/usr/bin/env python3
"""Inspect bounded actual product DXGI-submit cadence, never qualify scanout.

Use the product's copied GPU diagnostic JSON after stopping the original owner.
The exact Actions-built executable and its independently retained SHA256 are
required. This associates supplied files; it does not attest which file ran.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


def unsigned(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= 2**64 - 1:
        raise ValueError(f"invalid {name}")
    return value


def inspect(report: dict) -> dict:
    if (report.get("scope") != "receiver-only-live-product"
            or report.get("latest_terminal_origin") != "observed-in-this-recorder"
            or report.get("scanout_verified") is not False):
        raise ValueError("requires original live product receiver terminal, not a probe or disk history")
    terminal = report["latest_terminal"]
    receiver = terminal["receiver"]
    for field in ("worker_started", "decoder_opened", "worker_joined", "revoked"):
        if receiver.get(field) is not True:
            raise ValueError(f"original receiver has not completed {field}")
    for field in ("failed", "worker_panicked", "terminal_write_failed", "terminal_write_pending"):
        if receiver.get(field) is not False:
            raise ValueError(f"receiver reports incomplete or failed {field}")
    if (receiver.get("width"), receiver.get("height")) != (1920, 1080):
        raise ValueError("AC54 cadence collection requires actual configured 1920x1080")
    for field in ("generation", "accepted", "decoded", "converted", "submitted"):
        unsigned(receiver[field], field)
    if not (receiver["generation"] > 0 and receiver["accepted"] >= receiver["decoded"]
            >= receiver["submitted"] > 1 and receiver["converted"] >= receiver["submitted"]):
        raise ValueError("inconsistent actual owner output counts")
    frequency = unsigned(receiver["qpc_frequency"], "qpc_frequency")
    if frequency == 0:
        raise ValueError("missing actual QPC frequency")
    cadence = receiver["submission_cadence"]
    count = unsigned(cadence["frame_count"], "frame_count")
    if count != receiver["submitted"] or unsigned(cadence["invalid_timestamps"], "invalid_timestamps") != 0:
        raise ValueError("actual submission clock is incomplete or nonmonotonic")
    first = unsigned(cadence["first_qpc"], "first_qpc")
    last = unsigned(cadence["last_qpc"], "last_qpc")
    recent = [unsigned(qpc, "recent_qpc") for qpc in cadence["recent_qpc"]]
    if (len(recent) != min(count, 512) or len(recent) < 2
            or first > recent[0] or recent[-1] != last or last <= first
            or any(b <= a for a, b in zip(recent, recent[1:]))
            or (count <= 512 and recent[0] != first)):
        raise ValueError("invalid bounded original QPC window")
    intervals = sorted(b - a for a, b in zip(recent, recent[1:]))
    p95_ticks = intervals[(95 * len(intervals) + 99) // 100 - 1]
    duration = last - first
    return {
        "boundary": "successfully returned DXGI submissions, not physical scanout",
        "lifetime_submissions": count,
        "lifetime_duration_seconds": duration / frequency,
        "lifetime_fps": (count - 1) * frequency / duration,
        "recent_qpc_count": len(recent),
        "recent_interval_p95_ms": p95_ticks * 1000 / frequency,
        "recent_interval_max_ms": intervals[-1] * 1000 / frequency,
        "recent_window_seconds": (recent[-1] - recent[0]) / frequency,
        "lifetime_at_least_60_seconds": duration >= 60 * frequency,
        "lifetime_at_least_58_fps": (count - 1) * frequency >= 58 * duration,
        "recent_interval_p95_at_most_25_ms": p95_ticks * 1000 <= 25 * frequency,
        "full_lifetime_p95_available": count <= 512,
        "scanout_verified": False,
        "physical_gpu_target_verified": False,
        "product_execution_identity_verified": False,
        "AC54_passed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--diagnostics", required=True, type=Path)
    parser.add_argument("--product", required=True, type=Path)
    parser.add_argument("--product-sha256", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not re.fullmatch("[0-9a-f]{40}", args.source_revision):
        raise ValueError("requires exact Actions source revision")
    if not re.fullmatch("[0-9a-f]{64}", args.product_sha256):
        raise ValueError("requires independently retained Actions product SHA256")
    with args.product.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != args.product_sha256:
        raise ValueError("supplied product differs from the selected Actions artifact")
    encoded = args.diagnostics.read_bytes()
    if len(encoded) > 65_536:
        raise ValueError("product diagnostic report exceeds its original budget")
    result = inspect(json.loads(encoded))
    result.update({"source_revision": args.source_revision, "product_sha256": digest,
                   "diagnostics_sha256": hashlib.sha256(encoded).hexdigest(),
                   "build_provenance_supplied_by_operator": True})
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
