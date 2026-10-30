# Atomic authority reservation for an ordered two-relay route

Status: source implementation; exact-source Actions validation pending.

The existing SQLite immediate transaction, stored business/member/path chain,
device action signatures, relay lifecycle fence, global quota and account/node
capacity view remain the owners. A separate quota pool would allow multiple
relay protocols to overcommit the same nodes. Sequential public single-relay
requests would expose a partial promise and cannot authorize the inter-relay
neighbors; they are not used to construct a chain.

The separate NRD2 reservation endpoint accepts exactly two distinct registered
node identities. The device signs the complete ordered request under a new
domain, including business digest, space, route ID, all four grant IDs, both
membership IDs, original expiry and both current advertisement digests. The
server authenticates the actor and participating device, verifies current
business consent and membership, and revalidates both durable topology heads,
space publisher grants, runtime incarnations, endpoint revisions and reciprocal
live adjacency. The original grant lifetime cannot exceed either observation
or node lease. Replaced/withdrawn advertisements cannot be revived by a digest.

Migration 34 adds a chain header and exactly positioned hop promises; it leaves
existing one-hop tables and credentials intact. Each hop consumes one original
global allocation, both endpoint account slots and two slots on its node. The
first insert is visible to the second admission in the same transaction. Any
second-hop failure, stale proof, signature error or audit failure rolls back
both promises and the complete path credential set. No new quota or refund
semantics are introduced. Revocation terminates the stored path and both hop
grants while retaining the original expiry plus the existing hold margin.
Restart/restore fences and legacy/TURN collision checks include the new holds.

Readback returns original signed credentials while the same business, member,
topology, node, lifecycle and quota facts remain current. It never signs a new
credential, changes the order, extends a lease or replenishes bytes. A topology
change therefore ends this immutable reservation; route replacement and session
migration remain separate work. The HTTP revoke uses the existing reserved
revocation worker lane. Typed SDK methods sign and call this separate API.

Actions regressions cover exact persistence, canonical forward/reverse neighbor
bindings, tampering, independent topology invalidation, first/second/global
capacity and audit rollback, and revocation without early refunds. This slice
does not yet export NRD2 allocations in node resource snapshots, admit the three
production adjacencies or expose product UI for chain selection. The actual
four-node SessionPermit/FileRead production case remains required before W12 or
AC18/AC19 can be qualified. No complete release claim follows from this slice.
