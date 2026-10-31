"""Actual distribution dnsmasq client through a controlled LAN adapter.

This checks real DNS response parsing, source identity and UDP/broadcast paths.
It is mechanism evidence only, never a game or target-site acceptance result.
"""
import argparse
import ipaddress
import json
import secrets
import socket
import struct
import time


def skip_name(data, cursor):
    start = cursor
    while True:
        if cursor >= len(data):
            raise ValueError("truncated DNS name")
        length = data[cursor]
        cursor += 1
        if length & 0xC0 == 0xC0:
            if cursor >= len(data):
                raise ValueError("truncated DNS pointer")
            return cursor + 1
        if length & 0xC0 or length > 63:
            raise ValueError("invalid DNS label")
        if length == 0:
            return cursor
        cursor += length
        if cursor > len(data) or cursor - start > 255:
            raise ValueError("oversized or truncated DNS name")


def addresses(data, transaction):
    if len(data) < 12:
        raise ValueError("truncated DNS response")
    ident, flags, questions, answers, _, _ = struct.unpack("!6H", data[:12])
    if ident != transaction or flags & 0x800F != 0x8000 or questions != 1 or answers > 32:
        raise ValueError("wrong DNS response header")
    cursor = skip_name(data, 12) + 4
    result = []
    for _ in range(answers):
        cursor = skip_name(data, cursor)
        kind, family, _, length = struct.unpack("!HHIH", data[cursor:cursor + 10])
        cursor += 10
        if cursor + length > len(data):
            raise ValueError("truncated DNS answer")
        if kind == 1 and family == 1 and length == 4:
            result.append(socket.inet_ntoa(data[cursor:cursor + 4]))
        cursor += length
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--expected", required=True)
    args = parser.parse_args()
    gateway = str(ipaddress.IPv4Address(args.gateway))
    expected = str(ipaddress.IPv4Address(args.expected))
    subnet = ipaddress.ip_network(gateway + "/24", strict=False)
    results = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.settimeout(0.2)
        client.bind(("0.0.0.0", 0))
        for discovery in [True, False]:
            transaction = secrets.randbits(16)
            question = b"\x07remote" + (b"b" if expected.endswith("2") else b"a") + b"\x0dnestlink-test\x00"
            payload = struct.pack("!6H", transaction, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)
            destination = str(subnet.broadcast_address) if discovery else gateway
            deadline = time.monotonic() + 5
            started = time.monotonic()
            success = False
            sends = 0
            while time.monotonic() < deadline and not success:
                client.sendto(payload, (destination, args.port))
                sends += 1
                receive_until = min(deadline, time.monotonic() + 0.35)
                while time.monotonic() < receive_until:
                    try:
                        data, source = client.recvfrom(65536)
                    except TimeoutError:
                        continue
                    if source != (gateway, args.port):
                        continue
                    if expected not in addresses(data, transaction):
                        raise ValueError("actual remote DNS answer mismatch")
                    success = True
                    break
            if not success:
                raise TimeoutError("original LAN adapter did not return the actual remote DNS response")
            results.append({"mode": "broadcast-discovery" if discovery else "unicast-followup", "actual_dns_source": [gateway, args.port], "actual_remote_a_answer": expected, "elapsed_seconds": time.monotonic() - started, "requests": sends})
    print(json.dumps({"passed": True, "actual_protocol": "DNS over UDP to distribution dnsmasq", "cases": results, "game_evidence": False}))


if __name__ == "__main__":
    main()
