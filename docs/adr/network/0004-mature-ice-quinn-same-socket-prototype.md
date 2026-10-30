# ADR 0004: reuse mature ICE for Quinn on the selected candidate socket

Status: feasibility prototype implemented; exact-source GitHub Actions execution
pending. This is part of W09 / AC13 / AC14 and does not complete those tasks.
Date: 2026-10-30, Asia/Shanghai.

## Choice and sources

We compare adapting the existing mature ICE connection with copying its checks,
transaction state, role-conflict handling, STUN demultiplexing and candidate
socket management into a separate NestLink punching engine. We choose a thin
Quinn AsyncUdpSocket adaptation of the already locked ICE dependency. No ICE
algorithm, cryptography, STUN transaction engine, retransmission scheduler or
packet encryption is newly implemented. Production authorized signaling is a
separate next step; this prototype exchanges only its own candidates in process.

The actual dependency reviewed is `webrtc-ice` 0.14.0 in
`ZHanry/NestLink-dependencies` at
`c4cf95eda3c244eff429c73b0d933ff2f18745b4`, matching Cargo.lock and the existing
fork inventory. Reviewed interfaces are `webrtc-ice/src/agent/mod.rs`,
`agent/agent_transport.rs`, `agent/agent_internal.rs`, and `udp_network.rs`.
`Agent.dial/accept` performs the mature controlling/controlled checks and returns
its existing AgentConn. AgentConn.recv reads the mature application buffer after
ICE's original socket reader demultiplexes STUN. AgentConn.send writes through
the selected CandidatePair. It does not bind a replacement physical UDP socket.
The adapter reuses existing pinned TLS 1.3 configuration, Quinn, task receipts,
SessionPermit proofs, and remote business channels from this repository.

## Prototype boundaries and bounded adaptation

The new `crates/sdk/tests/ice_quic.rs` gathers exactly one IPv4 loopback host
candidate per endpoint with the existing EphemeralUDP socket factory. It freezes
those candidates before checks, exchanges their actual ICE credentials and
candidates, and uses one controlling and one controlled Agent. A socket-factory
counter must remain exactly two through ICE, Quinn, business and cleanup. Both
Quinn local addresses must equal the original ICE candidate addresses.

The adapter in `tests/ice_quic/socket.rs` opens no socket. It has one AgentConn
reader, one writer, and bounded Tokio MPSC queues of 32 packets per direction.
Writable notification uses AtomicWaker and rechecks queue capacity after
registering, so backpressure does not require a polling timer. Full ingress
queues drop a datagram; full egress queues return WouldBlock. Queue packets age
out after 250 ms. Each packet is between 1 and 1200 bytes, GSO is refused and the
reported transmit/receive segment limits are one. Arbitrary destinations and
source-address substitutions are refused. Metadata supplies the fixed selected
peer address without inventing another virtual physical path. ECN markings are
not conveyed by the mature Conn API; ingress reports no ECN and Quinn must use
its normal lack-of-ECN-feedback behavior. The adapter retains Quinn's conservative
`may_fragment=true` default because this Conn API cannot set a physical socket's
don't-fragment option. Dynamic PMTU, physical fragmentation and ECN are unqualified.

The selected local/remote tuple is checked before and after each ICE application
I/O and on selected-pair notifications. A changed tuple terminates the adapter;
this prototype never accepts new candidates after the initial exchange. Quinn
server migration is disabled. A general production migration fence still needs
review: the mature AgentConn API selects its current pair internally, so a
check before send cannot atomically pin a concurrently changing pair. Exactly
one frozen candidate per endpoint makes that race inapplicable to this experiment.
This prototype therefore establishes no claim about dynamic ICE nomination,
multi-interface selection, authenticated path epochs or seamless migration.

## Real application and negative cases

After ICE selects the original pair, Quinn performs existing pinned mutual TLS.
Both endpoints then run the existing bidirectional SessionPermit business proof,
native channel profile and stream binding. The test transfers eight actual
32-KiB FileRead channel payloads and compares every byte; it separately verifies
that connectivity cannot authorize Input. ICE byte counters alone cannot pass
the business assertion. The test retains the complete business/channel owners
until explicit stop and awaited cleanup.

Separate cases require certificate refusal for a wrong server key and a wrong
client key, without accepting a handshake timeout as proof. Cancellation tests
cover an ICE check with no usable peer and a pending Quinn handshake after an
actual ICE pair has already selected. Malformed adapter transmissions exercise
wrong destination, overlong payload and GSO refusal before enqueueing.

AgentConn.close is a no-op in the reviewed dependency. It is insufficient for
cleanup. The fixture retains the actual Agent, closes Quinn, waits for endpoint
idle, aborts and joins the original reader/writer via existing TaskOwner receipts,
then awaits Agent.close under one absolute cleanup deadline. Passing cases must
physically rebind both original UDP ports; endpoint idle and abort requests alone
cannot pass. Failed setup/assertion Drop paths request cancellation and schedule
bounded Agent cleanup, but are never counted as successful cleanup evidence.

## Evidence and decisions still open

Only GitHub-hosted Actions may compile or execute the prototype under R02. The
Rust core workflow explicitly runs this test target on Linux and with the
ordinary Windows token before fmt, retains the full output, and propagates its
failure independently of the earlier routed tests. Source implementation is not
recorded as a passed experiment until the matching SHA's run is reviewed.

Loopback host candidates prove the composition and ownership hypothesis only.
They do not prove public NAT traversal, simultaneous public reflexive checks,
same-socket external observed mappings, peer-reflexive behavior, advanced NAT,
IPv6, TCP coordination, consent expiry, loss/reordering, device-network change,
authorized candidate signaling or product fallback. No public-NAT success rate,
direct-only policy integration, complete W09 result or release qualification is
claimed. The next product slice must bind candidate generations/credentials to
the current signed network and business authority, enforce local address policy,
and use exact-source Actions NAT experiments and target evidence as applicable.
