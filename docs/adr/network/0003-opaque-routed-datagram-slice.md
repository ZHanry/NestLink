# ADR 0003: a bounded, independently negotiated opaque one-hop carrier

Status: implementation slice; requires exact-source Actions results and product integration.
Date: 2026-10-30, Asia/Shanghai. Scope: part of W07 / AC10 / AC11.

## Choice and compatibility

We compared enlarging the existing v15 relay packet constants with a separate
network datagram contract. We retain the legacy ALPN, 1200-byte inner packet and
1000-byte fragment. `nestlink/network-datagram/1` is a separate mutually pinned
TLS 1.3/Quinn adjacency. An ALPN or identity failure cannot become a legacy
downgrade. Both inner endpoints continue to authenticate each other's device
keys with existing rustls/Quinn code. Remote business streams still require the
existing SessionPermit proof; a transport or an IPv6 packet is not raw IP access.

We compared a new reliable packet protocol with reusing Quinn DATAGRAM and the
existing bounded virtual UDP assembly. We use Quinn DATAGRAM, share the existing
assembler with the legacy adapter, and add only the NestLink route envelope and
admission. No EasyTier source, new encryption, application retransmission,
alternative path scheduler or general TCP/IP stack is introduced.

## Binding and admission

There is no unchecked public RouteAuthorization constructor. Construction takes
a complete `VerifiedNetworkPath`, its exact verified ConnectivityGrant, a
verified TransitGrant and the actual `VerifiedPermit`. It checks current scope,
authority, space and epoch, the exact connectivity and business digests, both
business endpoint fingerprints, relay membership in PathPolicy, canonical
previous/next endpoint identities, one hop, group and contained lifetimes.

The binding hash covers a new domain, verified transport group, connectivity
reference, transit reference, actual permit digest, signed business generation
and fixed path epoch one. The verified grant reference already binds issuer,
deployment, space, both endpoints, purpose, route ID, adjacency, hops and quota.
Changing even a valid signed route ID produces a different packet binding.
No packet field can choose a physical address. The relay receives two unique
adjacency owners whose mutual TLS pins must match the signed neighbors.

Every fragment carries the binding digest, authenticated direction, remaining
hop count, packet sequence, original length and fragment index. Mutual TLS
protects the entire envelope on each adjacency. The relay checks its incoming
neighbor, exact binding and direction before decrementing the only hop. Endpoints
require the reverse direction and exhausted hop count. Replay tracking is
bounded to 65 packet IDs per direction and a two-bit fragment mask; old or
duplicate fragments do not forward or consume another quota allocation.

All new forwards consume one cumulative TransitGrant byte budget across both
directions, including the route headers and congestion drops. The relay cannot
identify business channels or selectively prioritize encrypted media frames.
Endpoint business QoS remains in the existing remote runtime. Reuse of one grant
across independently admitted route instances still requires the authoritative
control-plane reservation/meter; this transport-local counter is not a durable
accounting service.

## Exact packet budgets

| Layer | Independent limit or overhead |
| --- | --- |
| Configured physical QUIC UDP payload | 1200 bytes; discovery disabled for this initial carrier |
| UDP and IP headers below that value | IPv4 28 bytes / IPv6 48 bytes without options/extensions; separate from QUIC UDP payload |
| Outer QUIC protected packet overhead | Quinn accounts for negotiated connection-ID/header/packet-number/AEAD and DATAGRAM framing; never estimated by subtracting a fixed constant |
| Actual outer DATAGRAM availability | Checked with `Connection::max_datagram_size`; refuse if below 952 bytes |
| Network route fragment header | 52 bytes |
| Opaque fragment payload | At most 900 bytes; largest outer DATAGRAM is 952 bytes |
| Inner virtual UDP packet | 1 through 1400 bytes, at most two fragments; no IP implicit fragmentation |
| Inner QUIC configured UDP payload | 1400 bytes; independent from the physical outer 1200 bytes |
| IPv6 acceptance packet | 1280 complete bytes carried as an inner QUIC DATAGRAM; no OS injection |
| Partial assembly | At most 32 packets, at most 1400 stored payload bytes per packet plus metadata |
| Assembly/replay fragment age | 250 milliseconds from the first observed fragment; no renewal from duplicates |
| Completed packet handoff queue | 32 packets; packets older than the original assembly timestamp are discarded |

The 952-byte check uses Quinn's actual DATAGRAM budget, so variable TLS/QUIC
overhead is not disguised as a fixed available payload. PMTU below legal QUIC
minimum remains an explicit reachability failure. Quinn's bounded congestion
buffer remains subject to the short route lease; this slice does not establish
a per-datagram wire deadline or qualify dynamic PMTU changes.

## Lease, revocation and physical ownership

Construction checks a trusted current grant snapshot and current wall time, then
freezes a monotonic deadline no later than the signed transit/path/business
expiry and at most 30 seconds. It returns an explicit RouteRevocation handle.
The business/policy owner must retain it and revoke on any business stop,
membership/key/policy change or authority revocation. Dropping the last handle
also stops the route. A snapshot is not a background revocation service.

The sole outer reader checks stop/deadline before and after receive; all endpoint
send/receive and relay admission paths check again. Idle loops race the same
nonrenewable deadline and revocation signal. Cancellation of a borrowed relay
run also closes its original adjacencies. Transport cleanup retains the original
TaskOwner and physical socket/poller receipts and the first absolute close budget
across cancelled waits. Returning clean completion requires actual task joins
and physical receipt completion, not merely endpoint idle or abort requested.
Discarding a setup future still uses explicit Drop cancellation; it is not a
universal awaited setup-cleanup receipt.

## Actions evidence and remaining work

The new `transport-quic::routed::tests` are source for GitHub-hosted checks, not
locally executed evidence. They cover three real device/relay socket identities,
actual inner QUIC Initial metadata of at least 1200 bytes over smaller outer
fragments, an exact 1280-byte IPv6 packet, reverse packet boundaries, bounded
test-only relay ciphertext capture, physical UDP rebind, wrong relay TLS key,
crossed grants/permit/generation/peers/space/next hop, changed route ID, malformed
envelopes, reflection, hop replay, duplicate suppression, bidirectional cumulative
quota, reordering, expiry, bounded floods and idle revoke/sender-drop behavior.
The marker/ciphertext observation is limited to the retained bounded test capture;
it is not a security proof or a claim that real business authorization ran.

The SDK adapter must run real business proof and attach this owner to the
existing channel lifecycle. Management/UI enablement and the complete target
acceptance matrix still require explicit integration and evidence. The node
integration described below is source implementation awaiting its own Actions
checks. This transport intentionally supports a single relay, remote-control
purpose and fixed epoch one. Transit/path switching, authorized old-epoch drain,
multi-hop, TLS/WSS packet framing, full PMTU-blackhole experiments, raw IP ACL/TUN
injection, physical NAT, target devices and complete AC10/AC11 remain open. No
path-migration capability is advertised and no legacy semantic is reinterpreted.

The only added Cargo edge is the already locked `prost` crate for a test fixture
using its mature protobuf encoder. Its transport-quic lock dependency entry was
edited manually under R02; GitHub Actions `--locked` must verify or correct it.

## Current node adapter and compatibility boundary

The production NodeRelay command now negotiates the independent network ALPN
and the existing native relay ALPN on its registered QUIC endpoint. The network
ALPN requires TLS 1.3 mutual authentication, strict Ed25519 certificate parsing,
the real TLS transcript signature, and a current device fingerprint from the
existing node resource poll. Existing native QUIC clients already supply their
installation certificate; no network credential becomes a legacy relay ticket.
A newly issued allocation can require the next 250 ms resource poll before its
TLS pin is available. Admission fails closed during that interval.

The existing policy-key-signed NodeResourceSnapshotClaims adds field 8,
network_routes. Each resource has network_schema_version 1, internal allocation
facts, a network authority key, the exact signed network chain, and the complete
SignedPermit envelope. The existing signature covers every credential byte and
authority pin and remains bound to the exact fresh node-signed query. The server
signs the current stored permit using the actual business signer, verifies the
outgoing envelope, and includes those exact bytes. No signature is reconstructed
from an unchecked claim. The server checks the current business generation,
membership epochs, grant references/revocation, node runtime/generation/key,
endpoint revision, policy, quota and original reservation in the same database
transaction. The node independently verifies the full chain and business
envelope. Credential contents are never included in logs or audit payloads.

Old nodes ignore field 8 and therefore cannot install network routes. New nodes
default an absent field 8 to an empty set for an older control plane, reject
unknown per-resource versions, and refuse stale or replayed query sequences.
The independent ALPN and versioned challenge/hello/ready messages prevent an old
datagram endpoint from being mistaken for a new one. A fresh nonce signature
binds allocation UUID, complete route digest, device UUID, public key and socket
challenge under a dedicated domain. Its typed signing API cannot sign arbitrary
payloads. The one control stream remains open until termination; EOF, reset,
extra bytes or extra streams terminate forwarding.

Network entries reserve through the mature RelayEndpointCandidate, selector,
Pair, aggregate and allocation meters, slot guards, and terminal seen set. Both
directions charge actual admitted outer fragment bytes including route headers;
bounded congestion drops are charged too. Snapshots do not replenish the
per-allocation budget or its original monotonic deadline. Completed IDs cannot
be replaced/reused, and legacy admission explicitly rejects network entries.
Network reservations retain the original capacity hold until expiry; this slice
does not issue an incompatible legacy early-close/refund receipt.

NetworkNodeListener retains the original tracked physical UDP socket/poller
receipt. Main requests shutdown, joins the original service tasks, and closes
the listener using one absolute deadline. The QUIC service aborts and joins its
original accepted tasks before returning. Endpoint idle alone is not reported
as physical socket release, and an expired/canceled close wait retains the
original listener receipt. The source regressions cover signed snapshot byte
integrity, authority/version/query substitution, revocation omission, shared
bidirectional counters, duplicate roles, terminal reuse and unchanged capacity
promises. These regressions and the real SDK/business proof path still need
their matching GitHub-hosted run evidence.
