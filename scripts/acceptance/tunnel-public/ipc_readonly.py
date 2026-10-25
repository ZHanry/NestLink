"""Owned local evidence transport; only Snapshot and lease observation are allowed.
Derived from the existing work/tunnel_operator_ipc.py authenticated client.
Reads only the existing DPAPI local IPC secret; no management token is loaded.
"""
import datetime
import json
import os
from pathlib import Path
import select
import socket
import struct
import time
import ipc_crypto as crypto_helpers


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


class PinnedIpcClient:
    def __init__(self):
        self.raw = self.connection = None
        self.sequence = 0
        self.failed = False
        self.runtime = None
        self.overall_deadline = time.monotonic() + 90
        self.deadline = min(time.monotonic() + 20, self.overall_deadline)

    def perform(self, operation):
        while True:
            try:
                return operation()
            except (crypto_helpers.SSL.WantReadError, crypto_helpers.SSL.WantWriteError) as error:
                remaining = self.deadline - time.monotonic()
                require(remaining > 0, "local-ipc-operation-timeout")
                select.select([self.raw] if isinstance(error, crypto_helpers.SSL.WantReadError) else [],
                              [self.raw] if isinstance(error, crypto_helpers.SSL.WantWriteError) else [],
                              [], remaining)

    def receive_json(self):
        def exact(size):
            value = bytearray()
            while len(value) < size:
                block = self.perform(lambda: self.connection.recv(size - len(value)))
                require(bool(block), "local-ipc-closed")
                value.extend(block)
            return value
        size = struct.unpack("!I", exact(4))[0]
        require(0 < size <= 1048576, "local-ipc-frame-bound")
        return json.loads(exact(size))

    def __enter__(self):
        h = crypto_helpers
        state = Path(os.environ["LOCALAPPDATA"]) / "NestLink-RC"
        endpoint = json.loads((state / "daemon-endpoint.json").read_bytes())
        host, port = endpoint["address"].rsplit(":", 1)
        require(endpoint["version"] == 1 and host == "127.0.0.1" and 0 < int(port) <= 65535,
                "unexpected-local-ipc-endpoint")
        master = h.unprotect((state / "local-ipc.key").read_bytes())
        def derived(purpose):
            return h.HKDF(algorithm=h.hashes.SHA256(), length=32,
                          salt=b"NestLink/v15/local-ipc/keys/v1\0", info=purpose).derive(master)
        try:
            private = h.Ed25519PrivateKey.from_private_bytes(derived(b"desktop-ui"))
            expected = h.Ed25519PrivateKey.from_private_bytes(derived(b"daemon")).public_key().public_bytes_raw()
        finally:
            master[:] = b"\0" * len(master)
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = h.x509.Name([h.x509.NameAttribute(h.NameOID.COMMON_NAME, "peer.nestlink.invalid")])
        cert = (h.x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(private.public_key()).serial_number(h.x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(h.x509.SubjectAlternativeName([h.x509.DNSName("peer.nestlink.invalid")]), False)
                .sign(private, None))
        context = h.SSL.Context(h.SSL.TLS_CLIENT_METHOD)
        context.set_min_proto_version(h.SSL.TLS1_3_VERSION)
        context.set_max_proto_version(h.SSL.TLS1_3_VERSION)
        context.set_alpn_protos([b"nestlink-ipc/15"])
        context.use_certificate(h.crypto.X509.from_cryptography(cert))
        context.use_privatekey(h.crypto.load_privatekey(h.crypto.FILETYPE_PEM, private.private_bytes(
            h.serialization.Encoding.PEM, h.serialization.PrivateFormat.PKCS8, h.serialization.NoEncryption())))
        pinned = {"matched": False}
        def verify(_connection, peer, _errno, depth, _preverified):
            if depth != 0:
                return False
            matched = peer.to_cryptography().public_key().public_bytes_raw() == expected
            pinned["matched"] = matched
            return matched
        context.set_verify(h.SSL.VERIFY_PEER, verify)
        try:
            self.raw = socket.create_connection((host, int(port)), timeout=3)
            self.raw.setblocking(False)
            self.connection = h.SSL.Connection(context, self.raw)
            self.connection.set_connect_state()
            self.connection.set_tlsext_host_name(b"peer.nestlink.invalid")
            self.perform(self.connection.do_handshake)
            require(pinned["matched"] and self.connection.get_alpn_proto_negotiated() == b"nestlink-ipc/15",
                    "local-ipc-peer-not-authenticated")
            hello = self.receive_json()
            require(hello["version"] == 1 and hello["runtime_id"] == endpoint["runtime_id"],
                    "local-ipc-runtime-differs")
            self.runtime = hello["runtime_id"]
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.connection is not None:
            self.connection.close()
        if self.raw is not None:
            self.raw.close()

    def request(self, command, generation=0):
        require(not self.failed, "failed-ipc-cannot-replay")
        require(command.get("command") in ("snapshot", "get_local_service_lease_observation"), "read-only-command-required")
        self.failed = True
        self.sequence += 1
        require(time.monotonic() < self.overall_deadline, "local-ipc-total-budget")
        self.deadline = min(time.monotonic() + 20, self.overall_deadline)
        body = {"version": 1, "runtime_id": self.runtime, "sequence": self.sequence,
                "expected_generation": generation, "command": command}
        raw = json.dumps(body, separators=(",", ":")).encode()
        wire = struct.pack("!I", len(raw)) + raw
        offset = 0
        while offset < len(wire):
            count = self.perform(lambda: self.connection.send(wire[offset:]))
            require(count > 0, "local-ipc-write-closed")
            offset += count
        response = self.receive_json()
        require(response["version"] == 1 and response["runtime_id"] == self.runtime
                and response["sequence"] == self.sequence, "local-ipc-response-differs")
        self.failed = False
        return response
