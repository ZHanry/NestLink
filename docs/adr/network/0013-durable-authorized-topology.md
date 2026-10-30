# Space-authorized topology journal

W12 first production slice; AC18 and AC19 remain incomplete.

Topology observations use an independent version 1 canonical JSON contract and
four separate Ed25519 domains: publisher capability, node report, authority
advertisement and query-bound update. This reuses serde, ed25519-dalek and SQLite;
it does not extend the meaning of v15 permits or network-datagram v1.

The alternative of accepting every globally registered relay into every space
would let deployment infrastructure change a product space's graph without a
space manager's decision. Instead, an owner/admin explicitly delegates a node's
current management-accepted runtime and its allowed neighbors. A legacy space
requires deployment administration. Nodes authenticate reports with their own
registered key; no account bearer token grants the right to sign a node report.

An IMMEDIATE transaction reads the current space authority, policy epoch, node
runtime, node lease and endpoint revisions. It verifies the publisher and report
before committing a signed advertisement. The advertisement expiry is the
minimum of the report, publisher, live node lease and ten-second observation
budget. This information is a routing observation; allocation, forwarding,
business admission and NetworkAccess remain independent checks. The first Store
entry point grants no prefixes and rejects report prefixes. The identity layer
requires exact current RouteExport proofs for nonempty publisher prefixes; the
future prefix-management entry point must supply those stored proofs.

The alternative of an in-memory last-sequence cache loses replay and revocation
fences on restart. SQLite therefore keeps one node head, its original accepted
report and sequence after withdrawal or expiry. An identical retry returns the
original still-live advertisement without extending its TTL. A changed report
with the same sequence, an old sequence, or a publisher reissue attempting to
reset the same runtime is rejected. A new incarnation is accepted only after the
existing node-control protocol has admitted it. Reports are limited to one new
acceptance per 100 ms; neighbor count, claim bytes and publisher history are
bounded independently.

Full snapshots replace the consumer graph atomically. Delta entries explicitly
upsert or withdraw, carry monotonically increasing cursors and are signed as one
nonce-bound response. Absence from a delta means no change. Revocation, lease or
advertisement expiry, runtime replacement and endpoint revision change remove
the affected observation and produce a withdrawal. The journal retains 4096
changes and returns at most 256 per delta; an obsolete cursor must obtain a full
snapshot. A policy-epoch transition discards old-epoch journal contents while
preserving the cursor and node high watermarks, so a new policy cannot re-sign
an old-epoch upsert into a fresh batch.

Production HTTP routes issue/read/revoke publisher capabilities, authenticate
node reports and return bounded full/delta updates. Dedicated Actions tests use
real SQLite and registered node challenge proofs. Source is not compiled or
tested locally. This slice does not yet implement the endpoint graph consumer,
node adjacency reporter, atomic two-relay reservation or NRD2 carrier. In
particular, two independent one-hop routes do not prove a four-node chain.
