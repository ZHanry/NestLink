# Signed native relay cleanup receipts

The allocated node may release one durable capacity promise only after its
committed endpoint resources and their owned I/O have ended. A receipt is a
terminal fact. It cannot issue a lease, authorize data, revive an allocation,
reopen a role, or change a session's permission or path set.

## Wire and signing contract

`RelayCloseClaims` in `nestlink.proto` binds schema, deployment/security epoch,
node, runtime/generation, allocation UUID and the stable allocation binding,
last observed grant sequence, opened/closed endpoint counts, admitted bytes and
the final I/O-close wall-clock sample. UUIDs and counters are bounded by the
shared protocol validation. Opened endpoints must be one or two, all must be
closed, and admitted bytes cannot exceed the exact grant's cumulative limit.
The grant binding includes the allocated endpoints, keys, session, node,
runtime, generations, paths and quotas; grant sequence and issuance/expiry
times are excluded so a concurrent renewal cannot invalidate genuine cleanup.

The raw Protobuf claim bytes are Ed25519 signed with the allocated node key:

```text
NestLink/v15/node-relay-close/v1\0
```

`POST /api/v3/nodes/{id}/close` accepts `SignedRelayClose`. The path must match
the claim's node. Management bearer credentials cannot replace this proof.
The existing bounded JSON body middleware applies; claim bytes additionally
have the 4096-byte `relay_close_message_bytes` limit. A separate bounded IP
bucket allows 8192 requests per minute and shares the existing 2048-key cache.

Control signs `RelayCloseAckClaims` with the pinned node-policy key and the
independent `NestLink/v15/node-relay-close-ack/v1\0` purpose. The ACK binds the
raw close-claim digest and all allocation/runtime/deployment identities, the
immutable acceptance time, and either two released endpoint slots or zero
when the promise was already expired. Nodes verify the signature, exact
request bindings and acceptance time before removing a pending receipt.

## Durable transaction and retries

Schema 15 adds `relay_close_receipts`, keyed by the exact allocation UUID. It
retains the claim bytes, signature, digest, original acceptance time and ACK
claim bytes. After node verification, one SQLite transaction retires that
reservation, shortens its promise to at most the current time, saves the
receipt and records `node_relay_closed` with the verified node actor. An audit
failure rolls back all three changes. It never updates another allocation or
uses cumulative node usage reports as substitutes for allocation cleanup.

A previously acknowledged exact payload returns the original ACK and does
not release twice or add an audit entry. Changed payloads for that UUID are
rejected. Exact persisted ACKs survive a control restart in the same security
epoch, even during the restart capacity fence. New cleanup facts must match
the current control runtime that issued their promise and pass its original
clock/fence checks. Restore rotates the epoch and rejects old receipts.

The precise stored grant and runtime key are checked without requiring current
business authority. A revoked node, retired runtime, revoked session or old
endpoint configuration may close its own original promise; it gains no new
business authority. An observed sequence at or below the latest stable grant
is accepted. If close commits before renewal, renewal rejects the closed UUID;
if renewal commits first, the old observed sequence can still retire that
exact stable allocation. Unknown, mismatched or future-sequence facts fail.

## Actual I/O lifetime and node queue bounds

Destroying a bare `RelayResourceReservation` stops that resource and accounts
its closure, but cannot produce a receipt. WSS owns its socket halves,
registration and outgoing queue with the reservation; cancellation and every
error path drop these first, then confirm I/O closure. The first resource
closure wakes the peer and permanently retires the allocation locally. A
receipt is retained only after the last committed resource and every cleanup
witness have confirmed closure. Closed counters do not imply data delivery;
previously transmitted packets cannot be recalled.

Quinn 0.11.12 can retain a buffered socket transmit after `Connection::close()`.
QUIC therefore closes both registrations/carriers and immediately retires the
resource, then holds a separate cleanup witness while awaiting the shared
endpoint's public `wait_idle()` drain. This wait is bounded by the shared
2000-ms `node_relay_close_io_drain_ms`. If another allocation keeps the shared
endpoint active, timeout/cancellation does **not** confirm closure, and the
old capacity promise expires normally. This conservative shared-endpoint
limitation remains explicit; a connection-close notification alone is not
used as proof of driver drain.

Active allocations, delayed I/O witnesses and pending receipts together have
the 256-entry `node_relay_close_pending` bound. New UUID admission reserves its
future close slot and fails when this total is full. Moving the last closed
pair into the pending queue preserves the bound. Failed ACKs retain the same
signed bytes, including the original close time, and rotate through the queue
so one unavailable ACK does not starve other completed allocations. The seen
UUID tombstone remains after an ACK; same-UUID reuse is still rejected.

The close reporter holds no forwarding authority and remains separate from
the lease/resource pumps. Business stop wakes it for a fixed 5000-ms final
drain (`node_relay_close_drain_ms`), allowing the last WSS or drained QUIC
resources to report after authorization has ended. Failed delivery, invalid
ACKs, control loss, process exit or crash retain the original promise's expiry.
Node receipts are not persisted across a node process crash.

## Development verification boundary

Fixtures cover purpose separation, tampering/partial facts, wrong keys and
bindings, both renew/close orders, exact ACK retry, audit rollback, SQLite
reopen/restore, queue capacity and delayed/cancelled I/O witnesses. Actual
loopback HTTP/WSS and outer/inner QUIC verify synthetic business bytes followed
by resource shutdown, signed release, lost-response recovery, corrupt ACK
retention, rejected old UUIDs and a fresh allocation. Separate tests exercise
the reporter after node business stop. Current verification reports identify
the source bytes and platform scope; these fixtures do not constitute
installed-product, company/mobile-network, 72-hour or formal acceptance.
