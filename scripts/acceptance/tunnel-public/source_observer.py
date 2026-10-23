"""Short-lived server-side source observer; never a NestLink data path."""
import argparse
import json
import socket
import subprocess
import time
from pathlib import Path

from common import (CheckFailed, SERVER, TCP_PORT, UDP_PORT, canonical, frame,
                    load_config, public_ip, receive_tcp, require, send_tcp, sha, unframe, write_json)


def source_reply(config, raw, peer_ip, observed_ms):
    kind, sequence, payload = unframe(config, raw)
    require(kind == (b"O" if config["protocol"] == "tcp" else b"H"), "source-probe-kind")
    value = {"phase": "source-only", "protocol": config["protocol"], "source_ip": public_ip(peer_ip),
             "observed_unix_ms": observed_ms, "nonce_sha256": sha(bytes.fromhex(config["nonce_hex"])),
             "probe_sha256": sha(payload)}
    return frame(config, b"A", sequence, canonical(value)), value


def wait_for_visitor_close(peer):
    # The visitor must actively close first so this fixed server port does not
    # enter TIME_WAIT before the edge takes ownership. Never enable address reuse.
    try:
        require(peer.recv(1) == b"", "source-observer-unexpected-tail")
    except (OSError, CheckFailed) as error:
        # Fatal after sending a reply: do not retry and later claim the port was
        # cleanly handed off while an earlier actively closed socket may linger.
        raise RuntimeError("source-observer-peer-did-not-close-cleanly") from error


def require_no_listener(protocol, port):
    # Read the actual server socket table immediately before the exclusive bind.
    # No SO_REUSEADDR/SO_REUSEPORT is set: a race is rejected by bind as well.
    result = subprocess.run(["ss", "-H", "-ln" + ("t" if protocol == "tcp" else "u"), "sport = :" + str(port)],
                            check=True, capture_output=True, text=True, timeout=5)
    require(not result.stdout.strip(), "existing-listener-do-not-replace")


def observe(config, output):
    require(not Path(output).exists() and not Path(output).is_symlink(), "new-source-receipt-required")
    protocol = config["protocol"]
    port = TCP_PORT if protocol == "tcp" else UDP_PORT
    require_no_listener(protocol, port)
    deadline = time.monotonic() + min(90, config["duration_seconds"])
    evidence = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", port))
        listener.settimeout(1)
        if protocol == "tcp":
            listener.listen(2)
        while time.monotonic() < deadline:
            try:
                if protocol == "tcp":
                    peer, address = listener.accept()
                    with peer:
                        peer.settimeout(2)
                        raw = receive_tcp(peer)
                        reply, value = source_reply(config, raw, address[0], int(time.time() * 1000))
                        send_tcp(peer, reply)
                        wait_for_visitor_close(peer)
                else:
                    raw, address = listener.recvfrom(2048)
                    reply, value = source_reply(config, raw, address[0], int(time.time() * 1000))
                    listener.sendto(reply, address)
                evidence = {"run": config["run"], "protocol": protocol, "phase": "source-only",
                            "source_ip": value["source_ip"], "observed_unix_ms": value["observed_unix_ms"],
                            "nonce_sha256": value["nonce_sha256"]}
                break
            except (OSError, CheckFailed):
                continue
    # Verify the fixed endpoint can actually be handed to a fresh exclusive owner.
    # A closed listener alone is insufficient when accepted TCP sockets linger.
    require(time.monotonic() < deadline, "source-observer-cleanup-deadline")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM) as release:
        release.bind(("0.0.0.0", port))
    require(time.monotonic() < deadline, "source-observer-cleanup-deadline")
    # The owned sockets are closed before this receipt permits edge publication.
    require(evidence is not None, "no-authenticated-source-before-deadline")
    write_json(Path(output).absolute(), {**evidence, "observer_port_released": True, "release_check": "exclusive_rebind"})
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    observe(load_config(args.config), args.output)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "failed", "reason": "source-observer-failed"}))
        raise SystemExit(1) from None
