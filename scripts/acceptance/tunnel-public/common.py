"""Bounded protocol shared by the owned responder and the external visitor."""
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import uuid

SERVER = "158.180.81.141"
TCP_PORT = 29101
UDP_PORT = 29102
UDP_MAX = 1169
TCP_MAX = 8192
MAGIC = b"NL070T1"
HEADER = struct.Struct("!7s16sIc")
OVERHEAD = HEADER.size + 32
MAX_REPORT_EVENTS = 512


class CheckFailed(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise CheckFailed(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_config(path):
    value = json.loads(Path(path).read_text())
    return validate_config(value)


def validate_config(value):
    require(set(value) == {"run", "nonce_hex", "server", "tcp_port", "udp_port", "steady_seconds", "duration_seconds", "protocol"}, "config-fields")
    require(value["protocol"] in ("tcp", "udp"), "single-protocol-required")
    require(str(uuid.UUID(value["run"])) == value["run"], "canonical-run-required")
    require(type(value["nonce_hex"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["nonce_hex"]), "32-byte-test-nonce-required")
    require((value["server"], value["tcp_port"], value["udp_port"]) == (SERVER, TCP_PORT, UDP_PORT), "unapproved-endpoint")
    require(type(value["steady_seconds"]) is int and 30 <= value["steady_seconds"] <= 90, "steady-duration-bound")
    require(type(value["duration_seconds"]) is int and 180 <= value["duration_seconds"] <= 600, "run-duration-bound")
    return value


def public_ip(value):
    parsed = ipaddress.ip_address(value)
    require(parsed.version == 4 and parsed.is_global and str(parsed) == value, "exact-public-ipv4-required")
    return value


def frame(config, kind, sequence, payload=b""):
    require(type(sequence) is int and 1 <= sequence <= 0xffffffff, "sequence-bound")
    require(kind in (b"H", b"O", b"Q", b"P", b"F", b"C", b"A", b"R"), "frame-kind")
    require(len(payload) + OVERHEAD <= 60000, "frame-size-bound")
    header = HEADER.pack(MAGIC, uuid.UUID(config["run"]).bytes, sequence, kind)
    signed = header + payload
    return header + hmac.digest(bytes.fromhex(config["nonce_hex"]), signed, "sha256") + payload


def unframe(config, raw):
    require(OVERHEAD <= len(raw) <= 60000, "frame-size")
    header, tag, payload = raw[:HEADER.size], raw[HEADER.size:OVERHEAD], raw[OVERHEAD:]
    magic, run, sequence, kind = HEADER.unpack(header)
    require(magic == MAGIC and run == uuid.UUID(config["run"]).bytes, "frame-run")
    require(sequence > 0, "frame-sequence")
    expected = hmac.digest(bytes.fromhex(config["nonce_hex"]), header + payload, "sha256")
    require(hmac.compare_digest(tag, expected), "frame-authentication")
    return kind, sequence, payload


def echo_reply(config, sent, received):
    kind, sequence, payload = unframe(config, sent)
    actual_kind, actual_sequence, actual_payload = unframe(config, received)
    require(kind in (b"P", b"F") and actual_kind == b"R" and actual_sequence == sequence and actual_payload == payload, "echo-mismatch")
    return {"sequence": sequence, "payload_bytes": len(payload), "payload_sha256": sha(payload), "wire_bytes": len(received)}


def recv_exact(stream, size):
    require(0 <= size <= TCP_MAX, "tcp-read-bound")
    result = bytearray()
    while len(result) < size:
        block = stream.recv(size - len(result))
        require(block, "tcp-early-eof")
        result.extend(block)
    return bytes(result)


def receive_tcp(stream):
    size = struct.unpack("!I", recv_exact(stream, 4))[0]
    require(OVERHEAD <= size <= TCP_MAX, "tcp-frame-bound")
    return recv_exact(stream, size)


def send_tcp(stream, raw):
    require(OVERHEAD <= len(raw) <= TCP_MAX, "tcp-frame-bound")
    stream.sendall(struct.pack("!I", len(raw)) + raw)


def write_json(path, value):
    path = Path(path)
    require(path.parent.resolve(strict=True) == path.parent and not path.is_symlink(), "unsafe-output-path")
    temporary = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical(value) + b"\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def new_output(path):
    path = Path(path).absolute()
    require(path.parent.resolve(strict=True) == path.parent and not path.exists() and not path.is_symlink(), "new-owned-output-required")
    path.mkdir(mode=0o700)
    return path
