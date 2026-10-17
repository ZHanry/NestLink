# Independent node resource authority

Independent data services require three separate facts: a live signed node policy
lease, a current signed resource snapshot, and an allocated endpoint's challenge
signature. A global forwarding policy or account bearer alone authorizes no
business data. These admission guards are used by the
[independent WSS service](independent-wss-relay.md) and
[QUIC datagram service](independent-quic-relay.md).

`POST /api/v3/nodes/{id}/resources` accepts `SignedNodeResourceQuery` JSON and
returns `SignedNodeResourceSnapshot` JSON. The request is signed by the registered
node installation key. Management credentials cannot replace that signature.
It binds deployment/epoch, node/runtime/generation, policy and lease sequence,
request UUID/sequence and a positive interval of at most 1000 ms. A query from an
earlier still-live lease sequence is allowed when the WSS lease renewal completes
between query construction and the HTTP transaction; the runtime, generation and
policy must still match. A new runtime cannot reuse the old query.

The approved node policy key signs the response under the separate
`NestLink/v15/node-resource-snapshot/v1\0` domain. Query signatures use
`NestLink/v15/node-resource-query/v1\0`. The response repeats the exact query and
its encoded-claims digest, and delegates the control center's allocation issuer
key. Nodes need no unauthenticated new trust anchor. Policy, permit, allocation,
resource-query and resource-snapshot signatures cannot substitute for each other.

The response contains at most 128 unique allocations sorted by canonical UUID.
Its encoded claims are bounded to 262144 bytes. Each allocation must match the
query's deployment/epoch, node/runtime/generation and policy, the current quota
revision, and the response's issuance interval. SQLite reads current approved
session, original controller login, device/account/key, trust/password and policy
facts in one transaction. Expired or revoked business authority is omitted.
Polling neither renews grants nor refunds capacity. Database restore and control
runtime fencing also apply to resource queries.

## Admission and stop

`NodeControl` polls resources every 250 ms with a 700 ms request/body budget and
rejects redirects and oversized responses. The independently authenticated WSS
lease and usage-report channel continue to govern the node's global authority.
A resource request failure immediately stops existing resource guards without
granting new business authority through the global lease.

`NodeControl::prepare_relay_endpoint` verifies the original signed allocation,
its issuer delegated by the current snapshot, the endpoint key digest and a
`NodeRelayConnect` device-action signature over the complete allocation, selected
transport and service-generated 32-byte socket challenge. The data service must
generate a fresh unpredictable challenge for each socket, bound its handshake,
and never let the client choose/reuse it. An older still-valid ticket may join
only when its stable allocation binding matches the current snapshot; the proof
always signs that complete presented ticket.

The non-cloneable candidate grants no forwarding and consumes no meter slot.
It pins the delegated issuer and the minimum original ticket/observed grant
monotonic deadline at preparation. `reserve()` rechecks both bindings and all
current node/resource authority before committing. A newer grant cannot extend
the pending ticket, and issuer change, revocation or expiry prevents commit.
Its detached validity waiter observes global stop and rechecks current facts at
most every 25 ms, with an independent timer at the original deadline. It does
not itself grant permission. `reserve_relay_endpoint` remains the immediate
prepare-and-reserve convenience API. Independent data services use the shared
[carrier selector](relay-selection.md) so racing protocols do not split roles.

Only one connection per role can occupy an allocation, across both transports.
Both roles share one rate bucket and lifetime admitted-byte budget. They also
consume the node's common connection and byte meter. The enqueue callback must
be synchronous, bounded and must not reenter node control. Failed enqueue charges
neither meter. Counts represent accepted queue bytes, not confirmed delivery.

The non-cloneable `RelayResourceReservation` owns a unique connection token.
Dropping either role signals both roles to stop. Only its exact token closes its
slot and decrements the node connection counter; duplicate or stale cleanup
cannot release a different connection. Closed allocation UUIDs cannot reconnect
and reset cumulative bytes. At 65536 seen identities the runtime denies new
identities; production retention and sustained capacity acceptance remain open.

Every reader, writer and idle wait must select `wait_stopped()`. That future
observes both resource and node stop, including control-owner destruction.
The guard's own timer stops I/O at the earliest node/resource/allocation
monotonic deadline, including when no control watchdog is running. The 100 ms
watchdog provides an additional control check. Fresh live updates refresh the
timer; they do not themselves signal stop. Writers call `check_live()` before
sending already-admitted frames without charging them twice. The snapshot
deadline never exceeds its request start plus the short
signed interval. Repeating a grant sequence cannot recalculate its deadline.
A higher sequence extends a still-live pair only if all stable fields match;
lost, expired or closed guards cannot be revived by a later response. Missing
allocations and issuer/quota changes stop existing guards.

## Development checks and remaining data service

Unit fixtures verify purpose-separated signatures, request correlation, bounds,
shared budgets, failed enqueue, replay/runtime/key rejection, grant renewal,
monotonic expiration, closed identities and idle stop notifications. SQLite
fixtures exercise actual management/session/device/node/policy/quota/trust/password
revocation, restore and concurrent lease-sequence renewal. The HTTP/SDK fixture
obtains both endpoint proofs, creates two guards and observes actual closure of
an idle loopback socket within two seconds of node revocation.

The original raw socket fixture exercises the cancellation contract. Actual
independent WSS forwarding has since been added and checked separately; see
[independent-wss-relay.md](independent-wss-relay.md). QUIC datagrams/virtual UDP
are now implemented and loopback-tested separately in
[independent-quic-relay.md](independent-quic-relay.md). Reliable close receipts,
TURN/edge/tunnels and installed product acceptance remain
to be implemented.
