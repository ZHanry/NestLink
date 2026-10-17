"""Check the ABI and 16 KiB LOAD-segment alignment of an Android ELF library."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


MACHINES = {"arm64-v8a": 183, "x86_64": 62}
PAGE_SIZE = 16 * 1024


def verify(path: Path, abi: str) -> dict:
    data = path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01":
        raise ValueError("shared library must be little-endian ELF64")
    machine = struct.unpack_from("<H", data, 18)[0]
    expected_machine = MACHINES[abi]
    if machine != expected_machine:
        raise ValueError(f"ELF machine {machine} does not match {abi}")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phentsize < 56 or phnum == 0 or phoff + phentsize * phnum > len(data):
        raise ValueError("invalid or truncated ELF program-header table")
    loads = []
    for index in range(phnum):
        at = phoff + index * phentsize
        p_type, p_flags = struct.unpack_from("<II", data, at)
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, at + 8)
        p_align = struct.unpack_from("<Q", data, at + 48)[0]
        if p_align < PAGE_SIZE or p_align & (p_align - 1):
            raise ValueError(f"LOAD segment {index} has invalid 16 KiB alignment: {p_align}")
        if p_offset % p_align != p_vaddr % p_align:
            raise ValueError(f"LOAD segment {index} offset and virtual address are incongruent")
        loads.append({"index": index, "offset": p_offset, "virtual_address": p_vaddr, "alignment": p_align, "flags": p_flags})
    if not loads:
        raise ValueError("shared library has no LOAD segments")
    return {
        "path": str(path),
        "abi": abi,
        "machine": machine,
        "sha256": hashlib.sha256(data).hexdigest(),
        "page_size_bytes": PAGE_SIZE,
        "load_segments": loads,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--abi", required=True, choices=sorted(MACHINES))
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.library, args.abi), indent=2))
    except (OSError, ValueError) as error:
        print(f"Android ELF validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
