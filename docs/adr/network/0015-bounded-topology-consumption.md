# Bounded topology consumption and node report ownership

Status: source implementation; exact-source Actions validation pending.

The durable authority journal from ADR 0013 needs a consumer that can suggest
an authorized relay chain and a node client that can publish observations.
Neither observation may grant forwarding, business or prefix access.

## Alternatives and decision

Reuse petgraph 0.8.3, already present in both dependency locks and selected in
components.json C06, for shortest-path computation. A bespoke Dijkstra/BFS
implementation would duplicate a mature algorithm. NestLink only constructs a
bounded layered graph, filters by the current PathGrant, and resolves equal
hop counts by PeerId. Unknown RTT is not a zero-cost observation.

One shared mutable partial graph could expose an old relay before processing
its withdrawal on a later journal page. The selected consumer instead records
`has_more` and withholds candidates until the last page or a complete snapshot.
Batch contents commit atomically. Trusted time, expiry and grant revocation
are terminal observations and survive a rejected batch; clock rollback cannot
revive a removed observation. Publisher replay fences are retained and bounded,
including after expiry, omission and withdrawal.

Only exact verified live envelopes populate the graph. Expired historical
journal records can advance replay fences without becoming live publishers.
Edges require two live reports whose endpoint revisions match in both
directions. The bounded PathGrant relay set and hop count filter every path,
and the final candidate is checked again against the original verified chain.
This is discovery only. Atomic authority reservations, transit checks and real
NRD2 carrier admission remain required before any packet can be forwarded.

Reporter objects could own sequence counters, but reconstruction or re-signing
would then reuse a sequence in one boot incarnation. The selected sequence
owner is NodeControl's runtime, with 64 non-evicted space watermarks. Timeout,
cancellation and ambiguous HTTP outcomes consume the sequence. The reporter
reuses existing NodeConfig origin rules and NodeGate leases, publishes only
caller-owned neighbor observations and leaves prefixes empty.

Report expiry is bounded by the original node lease, publisher and one-second
report lifetime. The 700 ms HTTP budget includes the complete bounded response
body. Redirects are disabled. A reply must acknowledge the exact original
report bytes, signature, digest, sequence and expiry. Current node identity,
incarnation, policy, stop state, sequence, wall expiry and the original
monotonic cutoff are checked before returning. Renewal never extends an
in-flight report. Trusted time is never lowered to an earlier local clock.

## Validation and remaining work

New regressions cover graph lifecycle, pagination, failed batch time fences,
deterministic selection, graph budgets, mismatched revisions and grants. Node
tests use actual loopback HTTP for cancellation, timeout, redirects, oversized
responses, exact receipts and concurrent sequence ownership. Both NRD wire
versions have separate ALPN/magic and malformed-fragment coverage.

All compilation, formatting, lock generation and execution occur on GitHub
hosted Actions. No local project toolchain is run. These tests are component
qualification; they cannot establish two-relay business acceptance or complete
W12/AC18/AC19. The real adjacency owner and authority consumer must still call
the new components before this slice is a complete product path.
