# Complete two-relay carrier binding

Status: source implementation; exact-source Actions experiments pending.

## Decision

Extend the existing routed carrier, virtual UDP reassembly, Quinn endpoint,
mutual TLS adjacency and physical cleanup owners. A separate two-relay socket
or forwarding implementation would duplicate lifecycle and quota logic. NRD2
has separate ALPN and wire magic; NRD1 retains its original binding domain and
one-relay bytes. Both peers explicitly choose the new ALPN.

Each NRD2 participant receives the full original verified business, membership,
connectivity, PathGrant and ordered two TransitGrant chain. Each transit must
name the same route, transport group and canonical peer pair, with a unique
grant ID, fixed previous/next peer and exact forward position. The path must
allow both distinct relays, in order, within its signed hop limit. Every child
lifetime stays inside the original PathGrant and business lifetime. Endpoint
budget and expiry are the minimum across both transits. A route binding hashes
both ordered grant digests, the transport group, connectivity, business digest,
business generation and fixed path epoch under the new NRD2 domain.

Forward and reverse hop counts are derived from the verified relay position.
Incoming bytes cannot choose that position or a neighbor. Both the complete
fragment and its expected position are validated before the authenticated hop
is consumed. Existing bounded duplicate/age checks and the original cumulative
two-direction byte budget apply at each forwarding owner. No relay receives
inner QUIC keys or parses business payloads. A failed adjacency terminates its
fixed chain; this change does not promise route migration or replay requests.

## Validation and integration boundary

New tests run real outer QUIC on three fixed adjacencies between four logical
nodes, then one endpoint-pinned inner QUIC connection through both relays.
They cover a complete 1280-byte IPv6 packet, reverse packets, inner streams,
opaque relay captures, independent relay revocation propagation and release
of all six original physical socket addresses. Negative tests cross grants,
neighbors, ordering, hop positions, quotas and wire versions. Retained NRD1
carrier tests run alongside them.

These tests use actual transport owners and signed component fixtures. They
are not complete product business acceptance: atomic authority reservations,
node-runtime admission and resource snapshots, the real adjacency reporter,
SDK/UI control and four-node SessionPermit/FileRead remain required. Generic
inner streams qualify only transport; product callers must still complete
their original business authorization before opening data channels.

All compilation and execution occur in GitHub-hosted Actions. No local project
toolchain is used. No W12/AC18/AC19 completion or release is claimed by this ADR.
