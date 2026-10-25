"""Create one new private test nonce configuration without using the network."""
import argparse
import json
import os
from pathlib import Path
import secrets
import uuid

from common import SERVER, TCP_PORT, UDP_PORT, canonical, require, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    args = parser.parse_args()
    path = Path(args.output).absolute()
    require(path.parent.resolve(strict=True) == path.parent and not path.exists() and not path.is_symlink(), "new-config-file-required")
    value = {"run": str(uuid.uuid4()), "nonce_hex": secrets.token_hex(32), "server": SERVER,
             "tcp_port": TCP_PORT, "udp_port": UDP_PORT, "steady_seconds": 60, "duration_seconds": 600, "protocol": args.protocol}
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(canonical(value) + b"\n")
    print(json.dumps({"run": value["run"], "nonce_sha256": sha(bytes.fromhex(value["nonce_hex"])), "config_file": str(path)}))


if __name__ == "__main__":
    main()
