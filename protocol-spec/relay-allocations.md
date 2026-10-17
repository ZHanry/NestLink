# Durable relay capacity reservations

Schema 12 adds a shared control-side reservation ledger for the existing combined
WSS relay and independent relay nodes. The independent WSS service using it is
described in [independent-wss-relay.md](independent-wss-relay.md).

`POST /api/v3/remote/{id}/relay/allocation` accepts
`RelayAllocationRequest { allocation_id, node_id, device_id, signature }` and
returns a base64url Protobuf `SignedRelayAllocation`. The SDK verifies it against
the deployment's existing permit issuer. The allocation signature has its own
`NestLink/v15/relay-allocation/v1\0` domain. It cannot substitute for a remote
permit, node policy, endpoint proof or usage acknowledgement.

The device request signs the complete current permit digest, both canonical
allocation/node UUIDs, account, endpoint and session. The control process checks
the live access token, original controller login when applicable, current approved
relay path and device key, current node runtime/generation/role/policy lease, and
persistent quota revision before committing a grant and its device actor audit.
An account login or a node's global policy alone cannot obtain this grant.

The signed grant binds deployment/security epoch, allocation/session/node/runtime,
runtime generation and node key, both endpoint IDs/keys/accounts, connection and
policy/quota revisions, grant sequence, allowed native transports, rate and byte
limits, and a session binding digest. That digest retains every permit field except
lease sequence and issuance/expiry times. Permit renewal preserves the approved
session binding; a changed permission, resource, capability or identity does not.
Matching also checks the repeated identity and generation fields explicitly.

Grants expire at the earliest of the remote permit deadline, node policy deadline
and ten seconds from issuance. An identical valid request with at least five
seconds remaining returns the same signed claims. In the renewal window, only
current extended leases can advance the grant sequence/deadline. Checking unchanged
leases never extends the promise. An expired allocation UUID cannot be revived.

## Capacity and cleanup

Both relay paths share `RelayQuota.max_allocations` and the account endpoint
limit. Each allocation reserves both account slots before either peer forwards;
two endpoints belonging to one account consume two slots. An independent grant
also reserves two of the registered node's connection slots. Multiple transports
are alternatives within that allocation, not additional capacity grants.

Capacity remains held through the signed expiry plus a one-second clock margin.
Revoking the session, node or policy, changing quota or replacing a node runtime
stops new grants but does not refund already promised capacity. Independent
allocations currently expire conservatively; signed reliable close receipts are
part of the forthcoming independent data service.

For the combined WSS service, each role has a unique connection token. Joining
the second endpoint shares the allocation and its reserved account slots. A
service-owned guard is created inside the DB action before its cancellable result
boundary. Handshake failure, a lost DB response and cancelled connection futures
therefore retain cleanup ownership. It releases a role only after the service's
I/O ends. The last actual close releases the allocation; stale cleanup cannot
delete a replacement token or refund twice. Failed cleanup retains the original
bounded promise. The 250-ms supervisor checks persistent authorization and quota
with a 700-ms DB budget and the original monotonic deadline. A higher remote
lease sequence extends the connection and its capacity promise together.

The ledger retains at most 65,536 allocation identities. At exhaustion it denies
new allocations instead of evicting replay tombstones. This bound is not a
long-duration capacity acceptance result or a completed retention policy.

## Restart, restore and clock changes

AppState creates and persistently registers a new control runtime. Existing
unclosed reservations cause a cold restart fence. Offline restore always sets
the fence, including an empty or older snapshot, because post-snapshot promises
are unknown. New allocation and renewal methods must pass the lifecycle check.
An older control runtime cannot resume allocation after replacement.

The barrier waits fifteen seconds plus the one-second margin on a monotonic
clock. Only then may the new runtime retire old promises and resume admission.
Wall-clock rollback or drift beyond the margin latches allocation/renewal closed
until a new runtime is created; a wall-clock jump cannot skip the wait. The
existing combined supervisor stops on a lifecycle failure. This is conservative
availability behavior and does not claim completion of production clock alerts.

Administrator-only `GET /api/v3/relay/reservations` and
`Sdk::relay_reservations` report held allocations, reserved endpoint slots,
combined/independent counts, epoch and restart/restore fence. These counts include
signed promises whose clients might never have connected. They are not usage
reports, byte delivery receipts or proof of physical relay connections.

## Verification and remaining integration

Development fixtures exercise shared limits, waiting peers and same-account
slots, runtime takeover, idempotence/renewal, expired identities, stale cleanup,
audit rollback, SQLite reopen, restore/migration and simulated monotonic/wall
clock changes. A real HTTP/SDK/WSS fixture observes a pending combined allocation,
cancels its client future, checks cleanup, then reserves independent capacity
and rejects a real combined connection. Existing inner TLS relay fixtures verify
actual opaque transfer, revocation and eventual durable release of both roles.

Signed current resource snapshots, endpoint admission proofs and per-resource
guards are described in [node-resources.md](node-resources.md). They enforce
original monotonic grant deadlines, shared pair budgets and online revocation.
Independent WSS and QUIC datagram forwarding now use these guards; the latter is described in [independent-quic-relay.md](independent-quic-relay.md).
Node/global leases and
reservation tickets are never sufficient business authorization. TURN,
edge/tunnels, device/resource aggregate byte budgets, quota UI, sustained load
and installed product acceptance remain open.
