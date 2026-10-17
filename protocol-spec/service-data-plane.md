# Service publication authority and data-plane kernel

This layer follows `service-registry.md`. Creating or approving registry records
still does not publish an endpoint. Remote-control session permits, relay grants,
TURN credentials and service-publication leases have independent purposes.

## Durable lifetime accounting and restored snapshots

Schema 20 charges admitted service bytes against account, device, node and
resource lifetime ledgers and retains every unsealed grant's remaining
commitment. Signed cumulative reports retry the exact persisted bytes until an
exact policy-signed ACK; only a physical drain and matching terminal seal release
the unused commitment. A reporter's bounded shutdown leaves unknown debt on
disk. A host also enforces the signed grant ceiling when below the service limit.

Restoring a snapshot rotates authority and sets a persistent quota fence: the
snapshot cannot prove usage after its own capture. Grant issuance stays closed
after the temporary publication fence expires and across quota-limit updates,
runtime replacement and restart. The administrative quota response exposes
`reconciliation_required`. There is currently no controlled reconciliation or
unseal entry point; service resumption after restore requires implementing the
trusted external cumulative-ledger reconciliation. Never clear this fence from
the restored snapshot alone. An unconfigured scope reports limit revision zero,
which is the expected revision for its first limit update.

## Signing and trust

`ServiceLeaseSigner` derives `service-publication-ed25519` with HKDF-SHA256 under
the deployment-signing-keys salt. Its public key differs from the remote permit
and node-policy issuers. Canonical domain separation uses the repository's
`domain_message` encoding, with these service-specific domains:

| Object | Domain suffix |
| --- | --- |
| Service lease | `service-publication-lease/v1` |
| Node resource query | `service-resource-query/v1` |
| Resource snapshot | `service-resource-snapshot/v1` |
| Edge open challenge | `service-edge-open/v1` |
| Installation proof | `service-host-proof/v1` |
| Immutable publication binding | `service-publication-binding/v1` |

Wire objects are bounded JSON bytes signed as encoded; do not parse and re-encode
before signature verification. Individual messages are at most 32 KiB, snapshots
at most 2 MiB and at most 32 leases. Verify before constructing the private-field
`VerifiedServiceLease` / `VerifiedServiceSnapshot` types. A verified type records
the actual issuer used for verification. It does not make an arbitrary issuer
trusted: consumers compare it with the configured/delegated trust root.

The node-policy issuer delegates the service issuer through its signed resource
snapshot. The snapshot binds the exact independently signed node query and its
digest. Installation checks compare the recorded issuer and query signer against
the actual running `NodeGate`, including realm, policy, node key, runtime and
generation, and the current node lease sequence. A stale node lease sequence is
rejected; the caller retries with the current node lease, rather than extending
authority from an outdated request.

## Authority lifetime and local choice

A publication lease is at most 10 seconds; resource freshness and edge open
challenges are at most 2 seconds. Remaining wall-clock validity is anchored to
the monotonic time recorded before the exact request. Network delay and replay
cannot extend the deadline. Active flow I/O waits separately on revocation,
node/resource/publication expiry and shared bidirectional idle timeout.

The immutable binding covers all lease fields except lease sequence and the
issuance/expiry timestamps. Renewals must keep the same binding and issuer and
strictly increase sequence. An identical lease does not extend its original
deadline. Binding changes, an expired owner or explicit revocation are terminal.
The resource set remembers terminal publication IDs (at most 4096 per runtime),
so replaying a signed lease after omission or freshness loss cannot recreate it.

Local target consent is selected at registry revision **N**. Approval advances
the registry to **N+1**. The target owner retains the original N view, target ID,
protocol and fixed `SocketAddr`; its digest is never recomputed from N+1. A lease
names both `choice_revision = N` and `service_revision = N+1`, the full definition
and digest, account, independent creator/approver logins, host key and target
digest. A trusted service issuer must have checked both logins and current
registry/target/node policy before issuing the lease. This kernel is not a
substitute for those server-side checks.

`LocalTargetOwner` and prepared target connections cannot deserialize from IPC,
cannot clone authorization and stop dependent flows on Drop. Target network I/O
uses the retained socket address directly. No stream content, hostname, remote
Host header or caller-provided URL can select a different backend. HTTPS backend
targets are rejected until an explicit TLS backend adapter is installed.

## Ingress and per-flow proof

Operator configuration fixes the edge node, managed service suffix, management
hostname and at most 1024 public ports. HTTP and HTTPS share a unique hostname
key; TCP and UDP have separate port keys. Low ports and 28743–29055 are excluded.
This is process-local ownership and actual OS TCP binding, not a DNS proof or a
persistent/global port allocator; those facts must be checked before signing an
ingress claim. RAII tokens prevent a stale owner from releasing another claim.

An actual accepted visitor socket supplies the source peer. The independent
`NodeEdge` lease must permit server forwarding and public ingress. The service
ACL must separately allow that IP; an empty ACL denies every visitor. Forwarded
HTTP headers do not supply peer authority. Node aggregate and publication meters
commit together; connection slots and publication bytes are shared by all flows.

The edge signs a unique nonce/stream ID, exact lease digest, peer, stream/native
datagram transport and short deadline. The target checks the leased edge key and
the original local choice, consumes the challenge once and signs an installation
proof over that exact challenge and lease. The edge pending owner is consumed by
proof acceptance. Dropping negotiation state releases the exact flow. Production
negotiation must select its bounded I/O against `wait_stopped()` and own both the
visitor socket and encrypted carrier throughout cleanup.

The TCP copier has two fixed 16 KiB buffers and preserves half-close: visitor
EOF shuts down backend writes while backend responses remain readable. All read,
write, connect and rate waits are cancellable. Rate-limit retry is bounded by
authority and idle deadlines; no unbounded application queue exists.

## Native UDP

Each native carrier datagram is one service datagram. The packet is:

```
NSD1 (4) | direction (1) | mapping UUID (16) | sequence BE u64 (8)
          | payload length BE u16 (2) | payload (0..1169)
```

The complete packet is at most 1200 bytes. Sequence is in 1..=i64::MAX. Ingress
and reply directions decode separately. A 64-packet window permits bounded
reordering and rejects duplication/old packets. One connected local UDP socket
pins each mapping to its original fixed target and filters foreign return peers.
Zero-length payloads remain valid datagrams and charge one quota/rate unit. An
extra receive byte detects truncation/oversize; refused packets are dropped and
never placed into a reliable stream or reassembly queue.

This layer supplies target-side UDP mapping and codec. Public UDP listener,
visitor-to-mapping lifetime, bounded edge worker and pinned QUIC DATAGRAM adapter
must still be wired. TCP generic carrier traits also do not themselves provide
encryption: production must use an existing pinned encrypted transport with this
service-specific proof, and cannot reuse a remote-control permit as authority.

## Validation status

The isolated delivery includes real loopback I/O and signature test source.
Rustfmt and patch applicability checks have run without Cargo. Type checking,
Clippy, execution of those tests, production carrier integration, persistent
allocation/quota issuance and cross-network release acceptance remain separate
work in the parent task.
