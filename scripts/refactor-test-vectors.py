"""Independently encode the permit protobuf and sign a PUBLIC TEST seed.

Requires Python cryptography 46.0.3. This is a development-only test tool,
never imported by the Rust product or used to create deployment keys.
"""
import hashlib
import json
from pathlib import Path
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def varint(value):
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def scalar(field, value):
    return varint(field << 3) + varint(value)


def binary(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value


def identifier(value):
    return f"{value:08x}-1111-4111-8111-111111111111".encode()


def public(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def main():
    if cryptography.__version__ != "46.0.3":
        raise SystemExit("Use the recorded independent cryptography 46.0.3 implementation")
    claims = b"".join([
        scalar(1, 1), binary(2, identifier(1)), scalar(3, 1),
        binary(4, identifier(2)), binary(5, identifier(3)),
        binary(6, identifier(4)), binary(7, identifier(5)),
        binary(8, hashlib.sha256(public(2)).digest()),
        binary(9, hashlib.sha256(public(3)).digest()),
        binary(10, identifier(6)), binary(11, varint(1) + varint(2)),
        binary(12, varint(1)), scalar(13, 1), scalar(14, 1), scalar(15, 1),
        scalar(16, 1_000_000), scalar(17, 1_015_000),
        binary(18, bytes([7]) * 32), binary(19, b"vp8"),
    ])
    domain = b"NestLink/v15/session-permit/v1\0"
    signature = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32).sign(domain + claims)
    result = {
        "schema_version": 1,
        "purpose": "public, deterministic TEST vector; seeds 01/02/03 repeated 32 bytes are not deployment keys",
        "reference": "manual protobuf encoding + Python cryptography 46.0.3 Ed25519",
        "issuer_public_key_hex": public(1).hex(),
        "claims_hex": claims.hex(),
        "signature_hex": signature.hex(),
        "envelope_hex": (binary(1, claims) + binary(2, signature)).hex(),
    }
    path = Path(__file__).resolve().parents[1] / "tests/vectors/session-permit-v1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("generated", path)
    input_prefix = b"".join(scalar(field, value) for field, value in [(1, 1), (2, 1), (3, 1), (4, 9), (5, 1)])
    text = "中文提交"
    pointer = scalar(1, 1) + scalar(2, 1) + scalar(3, 9) + scalar(4, 20)  # sint32 -5 -> 9; +10 -> 20
    input_result = {
        "schema_version": 1,
        "reference": "manual protobuf varint, UTF-8 and sint32 zigzag encoding; no generated Rust encoder",
        "input_epoch": 1, "layout_epoch": 1, "connection_generation": 9, "sequence": 1,
        "text": text, "text_hex": (input_prefix + binary(8, text.encode("utf-8"))).hex(),
        "pointer_x": -5, "pointer_y": 10, "pointer_button": 1,
        "pointer_hex": (input_prefix + binary(7, pointer)).hex(),
    }
    input_path = path.with_name("input-v1.json")
    input_path.write_text(json.dumps(input_result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("generated", input_path)


if __name__ == "__main__":
    main()
