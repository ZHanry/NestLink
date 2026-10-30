# Delegate the complete chain through the existing node resource owner

Status: source implementation; exact-source Actions validation pending.

The current signed, exact-query node resource snapshot, current SQLite business
and topology checks, original allocation deadlines, resource continuity tokens,
Pair slots, cumulative byte meters and node-global capacity remain the owners.
Building an independent NRD2 resource pool would permit duplicate admissions and
separate quota refunds. Treating one TransitGrant as a complete route would lose
the authorized relay order and let endpoints replace inter-relay neighbors.

Schema 1 remains the original NRD1 resource. Explicit schema 2 uses a new protobuf
field containing the complete original ordered chain and leaves the old bundle
empty. Each version rejects the other version's bundle. Old readers therefore
fail closed. The node-policy signature authenticates the original business
permit, network trust anchor, both membership and transit credentials, both node
endpoint views and original topology references. The Store revalidates both
current topology heads and every original member/business/runtime/quota fact
inside the same snapshot transaction. One stale or revoked hop omits the chain
from both nodes without refunding either original capacity promise.

Each node's allocation ID is its original transit grant ID, while both resources
carry the same full-chain binding. Its original business endpoint/account claims
remain unchanged. Admission separately assigns slot zero to the previous peer
and slot one to the next peer. TLS pins and a new NRD2 possession transcript bind
the exact adjacent public key, receiving relay, chain digest, allocation and fresh
socket challenge. Both installation and registered node identities can prove
possession, but an unrelated key or the opposite business endpoint cannot fill
the inter-relay slot. NRD1 admission cannot consume a schema 2 resource.

All candidates, reservations, counters, snapshot omission/expiry, continuous
byte checks and pending-candidate fences reuse the existing owner. No schema 2
resource can produce a legacy close receipt or replenish its cumulative bytes.
The existing identical-live-credential cache also requires the original complete
resource digest and the same live exact-query snapshot trust context.

New source regressions exercise both policy-signed node snapshots, complete
credential equality, ordered transit tampering, wrong purpose/version/business
proof, exact neighbor possession, both shared slots and cumulative bytes,
snapshot omission and stale candidate revival. The production listener/dialer,
continuous real adjacency reports and four-node SessionPermit/FileRead still
require implementation and independent Actions evidence. This slice does not
complete W12 or qualify AC18/AC19 or the release.

Independent Actions failures also exposed three existing integration issues:
the chain HTTP handlers were absent from the actual router; a complete full
topology snapshot at the same cursor could not supersede pagination; and a
healthy node reporter test waited forever for a still-running lease pump. Their
repairs preserve the original assertions and timeout budgets. SQLite concurrency
setup now starts its monotonic lifecycle after disk setup and samples actual
elapsed time. Logout quota observation uses a separate authenticated login so
the original login's revocation is preserved.
