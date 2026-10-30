# First network slice: source integration audit

Reviewed on 2026-10-30 (Asia/Shanghai) against NestLink
`82f1c8dfb31bdf0872ea7430b5608e205c1cbb08`. This is manual source review for
W02/W04–W09/W14. It is not L1/L2 execution evidence and does not establish that
any new network feature or target-platform acceptance case has passed.
No formatter, compiler, dependency installer, project script or test was run
locally. R01/R02 apply to the changes recommended here.

## Existing production chain to retain

| Boundary | Existing implementation at the reviewed revision | Integration consequence |
| --- | --- | --- |
| Product start | `crates/app-core/src/runtime.rs:5440` checks the local endpoint role, obtains the signed permit, validates local session options, fetches the peer key, constructs a monitored native endpoint, then calls `native_recovery::prove_endpoint` at line 5500 | Put the new peer connection facade on this path; a standalone example or a second disconnected network service is insufficient |
| Endpoint identity and discovery | `crates/sdk/src/native.rs:764` compares both installation public-key digests against the permit before constructing a UDP endpoint; relay-only permits create no direct UDP endpoint | Preserve endpoint-key binding and relay-only behavior when introducing SpaceId or a HostAdapter |
| Signaling and initial connection | `crates/sdk/src/native.rs:883` gathers actual local candidates, publishes a signed signal, obtains peer candidates, and chooses controller dial versus host accept-or-relay at lines 1077–1103 | Reuse the existing control-plane consent and signed discovery; do not turn candidate discovery into dial permission |
| Pure scheduling | `crates/connectivity/src/lib.rs:28` owns bounded candidate race state; lines 122–160 reserve capacity for relay/WSS; lines 192–199 stop at the first timely success | Extend this policy owner rather than create another production initial-connection scheduler |
| Real transport adapter | `crates/sdk/src/native.rs:511` already represents QUIC, direct TLS/TCP and inner TLS/WSS in `NativeTransport`; `NativeConnection::authorize` at line 623 consumes it | This is the smallest existing real legacy-carrier seam |
| Business authorization | `crates/sdk/src/native.rs:643` calls `nestlink_remote::quic::authorize`; lines 657–661 call `authorize_stream`; lines 718–745 prove both endpoints and construct `AuthorizedConnection` | A transport adapter must never expose business channels before these proof and permission checks |
| Business runtime | `crates/remote/src/queues.rs:471` owns bounded channel queues, I/O tasks, QUIC connection and retained endpoint; `NativeSession::shutdown` delegates to its real cleanup | Keep the channel runtime and media/file/input owners; replacing transport does not replace business cleanup |
| Native recovery | `crates/app-core/src/runtime/native_recovery.rs:7` permits recovery only after an eligible transport/network stop and completed cleanup; `retain_source` preserves the original deadline and local consent | Use this as the conservative recovery fallback until safe connection continuity is demonstrated |
| Services | `crates/sdk/src/services/publication.rs:48` retains service lease, approved local target, connection and cleanup monitor; `wait_stopped` at line 118 reports cleanup pending separately | W16 needs a carrier facade around this existing service lifecycle; do not reuse remote-desktop permits for services |

`nestlink-connectivity` currently depends only on protocol, policy and serde.
Keep its policy state free of sockets, Tokio tasks and system routing changes.
The native SDK and transport crates are the current host-side I/O boundary.
`HostAdapter` can formalize this boundary without making pure policy own OS
resources or moving all SDK behavior into a new crate at once.

## Authentication and authorization facts

* `crates/identity/src/lib.rs:24` uses separate existing v15 domains for session
  permits, endpoint proofs and device actions. `verify_permit` at line 133
  verifies the signature over the exact original bounded claims bytes, retains
  the original signed envelope and then decodes/validates claims. Preserve that
  exact-envelope property for every new grant.
* `crates/transport-stream/src/tls.rs:51` parses the Ed25519 certificate key and
  checks its digest against the pinned installation identity. TLS transcript
  signatures remain verified by rustls. Public HTTPS/WSS root validation at
  line 15 is separate from endpoint pinning; neither should be weakened.
* `crates/policy/src/lib.rs:153` intersects global/account/device/resource/session
  and both local endpoint path policies. Space, purpose and grant restrictions
  must narrow this intersection, never replace it with a broader policy.
* `crates/session/src/lib.rs:789` binds the permit to deployment, security epoch,
  session, account, both device IDs and keys, resource, policy revision,
  connection generation and capability digest. Lines 807–829 reject unsupported
  required capabilities, excessive permissions and forbidden paths.
* `crates/session/src/lib.rs:491` signs the permit digest, fresh challenge, both
  endpoint key digests, selected path and connection generation. Line 512
  consumes each role proof once. Active business calls at line 573 reject a
  path other than the proved path. `select_path_before_proof` at line 445 only
  permits a change before any endpoint proof is consumed.

Consequently, public version `0.8.0` cannot silently change the v15 proof or
allow an active v15 session to accept a new relay path. New capabilities require
an independent signed protocol object and explicit bilateral negotiation.
Old peers must use their current stop/reproof/reconnection behavior.

The current signed objects do not provide the complete new five-right model.
Membership, connectivity/path, business, transit/route export and raw-IP rights
must have distinct verified types. No constructor should promote a membership
certificate into `SessionPermit`, `ServiceLease` or raw socket access.

## Same-socket discovery: what is proved by source

`crates/transport-quic/src/lib.rs:66` wraps one physical UDP socket in
`DiscoverySocket`, gives that exact abstract socket to
`Endpoint::new_with_abstract_socket`, and configures both client and server QUIC.
`crates/transport-quic/src/discovery.rs:95` sends STUN using the wrapped socket;
its `poll_recv` at line 202 is the single demultiplexing receive path used by
Quinn. It consumes trusted, matching transaction replies before passing QUIC
packets onward, handles batched receive metadata and bounds work under a flood.
Generation invalidation at line 81 drains old pending transactions. Dropped
probe futures remove their own pending transaction through `Cleanup` at line 54.

This is reusable same-socket **STUN mapping discovery**, not a complete native
ICE agent. `NativeEndpoint::establish_with_media` currently makes the controller
dial and the host accept direct QUIC or dial a relay. This source path does not
show the required bilateral candidate-pair checks, authenticated ICE roles and
role conflict resolution, nomination, peer-reflexive handling or consent.

W09 should first prove a mature ICE implementation can provide a single
datagram interface to Quinn without adding another receiver on that physical
socket. If the existing webrtc-ice fork can supply the required interface,
reuse it. If not, document the exact library/API gap before adding the smallest
adapter. A successful ICE socket followed by a fresh `Endpoint::client` socket
would fail AC13 even if both addresses happen to be on the same machine.

## Existing opaque datagram carrier and MTU boundary

`crates/transport-quic/src/node.rs:149` establishes an outer QUIC connection
pinned to the control-signed node identity and allocation. Lines 207–226 prove
the endpoint against a fresh challenge and the exact signed allocation before
opening the inner carrier. Lines 229–270 give `RelaySocket` to a second Quinn
endpoint whose TLS pins the final peer. The relay does not receive inner keys.

`crates/transport-quic/src/virtual_udp.rs` is an existing thin Quinn adapter,
not a new reliable transport implementation. Reuse its bounded reassembly:

| Existing contract | Source |
| --- | --- |
| Inner UDP packet maximum 1200 bytes | `protocol-spec/contract.json:46` |
| Fragment payload maximum 1000 bytes | `protocol-spec/contract.json:47` |
| At most 32 pending packets and a 100 ms age | `protocol-spec/contract.json:48` and line 49 |
| Packet/fragment validation and bounded reassembly | `crates/transport-quic/src/virtual_udp.rs:40` |
| Outer DATAGRAM capacity checked before construction | `crates/transport-quic/src/virtual_udp.rs:147` |
| No arbitrary UDP destinations or oversized inner packets | `crates/transport-quic/src/virtual_udp.rs:258` |
| Fixed synthetic peer address, no physical loopback socket | `crates/transport-quic/src/virtual_udp.rs:156` |
| Inner MTU fixed to 1200, PMTU discovery disabled | `crates/transport-quic/src/node.rs:233` |

The adapter splits a 1200-byte inner QUIC Initial across outer DATAGRAMs, so
subtracting the fragment header from 1200 is not its current implementation.
However, source review is not proof of real damaged-network delivery. The
existing inner packet limit and lack of a raw-IP/TUN path do not establish
delivery of complete 1280-byte IPv6 packets. W07 must define separate physical
PMTU, outer secure-channel overhead, route header, fragment envelope, inner
QUIC packet, application DATAGRAM and TUN packet budgets. Do not equate
`QUIC_DATAGRAM_BYTES = 1100` (`protocol-spec/contract.json:42`) with the 1200-byte
QUIC minimum UDP payload or a TUN MTU.

The current fragment envelope is v1 and allocation-paired; it has no SpaceId,
transport-group ID, route ID, path epoch or authenticated hop limit for generic
multi-hop routing. Add a negotiated new route envelope and per-hop authorized
secure-channel binding. Preserve the v1 envelope for legacy peers. The relay
must only schedule opaque authorized transport groups; encrypted bytes do not
provide visibility into media frame priority.

## Ownership and close completion gaps for W05

The code already distinguishes attached cleanup failure and waits for owned
business I/O tasks. `ChannelRuntime::wait_stopped` at
`crates/remote/src/queues.rs:977` retains handles across cancellation, shares an
absolute two-second cleanup deadline, aborts timed-out tasks and awaits their
completion rather than reporting success.

The new unified `close_and_wait` must also cover retained carrier and endpoint
owners. Current `transport_owner` is `Option<Box<dyn Send + Sync>>` at line 480;
its lifetime retention gives no asynchronous close-completion interface.
`RelaySocket::drop` at `virtual_udp.rs:132`, `Carrier::drop` at `node.rs:126`,
and `ByteStream::drop` at `transport-wss/src/lib.rs:49` abort owned receiver or
pump tasks but do not provide a wait receipt. That is an integration gap for
the stronger W05 contract, not evidence that these tasks leak at runtime.

Reuse the stronger existing service carrier pattern:
`crates/transport-quic/src/service.rs:55` closes the connection and endpoint,
waits idle, drops retained clones and then awaits a physical-socket release
receipt. `service/socket.rs` owns that receipt. An idle endpoint alone does not
establish physical socket release.

Suggested minimal owner interface: one non-cloneable native carrier owner with
`request_close(reason)` and cancellation-safe `close_and_wait(deadline)`.
Return `Pending` or a typed failure if endpoint clones or tasks remain; retain
the owner so another wait continues the original deadline. Keep `Drop` as the
last-resort cancellation action. Do not manufacture a successful stop result
from `JoinHandle::abort` alone.

## Migration is a separate unproved capability

The current virtual socket owns one immutable outer connection, local/peer
synthetic addresses and one receiver. `node.rs:99` closes the inner connection
when the outer carrier fails; both relay and inner server configurations set
`migration(false)` at lines 47 and 242. This implementation intentionally closes
and recovers rather than keeping an inner connection across arbitrary routes.

W14 needs a real Actions prototype before promising continuity. A future
route-switching abstract socket would retain one logical end-to-end address and
one receiver owner while atomically replacing only authorized carriers after
the migration commit. Old and new path epochs must have bounded overlap and
immediate revocation priority. RTT, congestion and PMTU behavior on the new
physical route must be measured; hiding the outer change from Quinn is not
proof of correct convergence.

If the prototype cannot safely preserve the connection, keep the existing
application recovery path and report TCP disconnection explicitly. Do not
replay arbitrary TCP requests, old input, clipboard writes, audio or video.

## Recommended W02 contract freeze

The following is a recommendation for the single shared-protocol owner to
freeze after W01, not a declaration that the types or protocol are implemented.

1. Keep the existing v15 domain and ALPN behavior. Introduce explicit
   `network-v1` and `path-migration-v1` capabilities with bilateral agreement,
   exact required-capability rejection and domain-separated new signatures.
   Prefer additive new bounded objects to changing signed v15 fields in place.
2. Define SpaceId independently of deployment/account and bind PeerId to the
   existing installation public-key digest. Freeze ID encoding, length,
   canonical byte serialization and unknown-critical-field behavior. Preserve
   signed bytes; never verify a decoded/re-serialized substitute.
3. Each grant binds issuer, deployment, space, endpoint keys/IDs, purpose,
   policy/security epochs, validity and bounded resource scope. Membership
   enables only approved discovery. Connectivity/PathGrant permits only the
   enumerated carriers and relay IDs. Existing business permits remain
   mandatory. Transit/RouteExport and NetworkAccessGrant remain separate.
4. Transport-group key is `(SpaceId, ordered PeerPair, compatible PathGrant
   digest/route constraints)`, with an explicit per-pair group bound. A
   `direct_only` group and a relay-capable group cannot share a connection whose
   outer route may change together. QoS within a group is endpoint policy.
5. Expose discovered, transport-authenticated, network-authorized and
   business-authorized states as distinct types; constructors check exact
   authority, not merely `bool authenticated`. The legacy adapter may represent
   only an already-permitted legacy session, not infer a new space membership.
6. `connect_peer` carries purpose, exact verified authority, absolute deadline
   and cancellation. Stream/datagram operations carry bounded channel policy,
   deadline/expiry and explicit unsupported-capability errors. QUIC DATAGRAM
   and framed TCP/WSS semantics are distinguished, including head-of-line cost.
7. Freeze authenticated route-header fields and transit grant binding before
   generic relay forwarding: SpaceId, source/final peer, transport group, route
   ID, path epoch, bounded hop limit, expiry and permitted next hop. A relay
   cannot choose an arbitrary network address from packet contents.
8. Freeze migration proposal ID, original application generation, old/new path
   epoch, grant digest, challenge, commit deadline, replay window and collision
   rule. A total order on `(new epoch, proposer PeerId, proposal ID)` can resolve
   simultaneous proposals; both endpoints must implement the exact same order.
   A new authenticated carrier allows migration control only until commit.
9. Keep observed route facts separate from allowed route policy. Events include
   physical transport, authorized relay chain/next hop, network generation,
   path epoch, sample timestamp and unknown measurements as `None`.
10. Preserve typed security failures through transport adapters. At present
    `sdk/native.rs:1632` erases attempt failures to `()` and lines 1709–1710
    reduce them to generic direct/relay unavailability. Pins still apply on
    every attempted transport, so this review does not demonstrate an auth
    bypass, but this erasure cannot implement the specified stop-on-identity
    or authorization-failure policy or accurate diagnostics. Separate retryable
    reachability failure from terminal identity/TLS/protocol/grant failures.

## Actions verification needed for the first slice

### Implementation follow-up: typed candidate failure policy

An additive source change now carries typed errors from direct QUIC, direct TLS
and the node-relay adapter through the existing native candidate race. The
existing pure scheduler makes an admitted identity, protocol or authority
failure terminal and preserves its error code; candidate hints excluded by the
preflight policy do not terminate valid admitted attempts. Reachability errors
and generic QUIC application-close events retain fallback, including the
existing reserved WSS capacity. The v15 signed fields, proof domains, ALPN and
business permission checks are unchanged.

New source tests cover real QUIC and direct TLS handshakes with the wrong peer
key, typed wrapped errors, terminal-state retention, and reachability fallback.
The existing node-relay integration tests cover approved WSS winning after QUIC
failure and a one-endpoint UDP blackhole. A follow-up source change also retains
the mature tungstenite error as the outer WSS error source, and retains the
original inner TLS I/O error instead of labeling every TLS operation failure as
an identity failure. The classifier distinguishes certificate/protocol errors
and HTTP 401/403 rejection from ordinary refusal/reset/timeout, graceful close,
incomplete network handshake and HTTP 503. Source tests exercise an actual
untrusted outer WSS certificate, actual rejected HTTP upgrades, and a refused
TCP connection; typed classification tests assert the resulting categories.
These changes remain unverified until GitHub-hosted Actions runs against the
changed source SHA. No local automated verification was run.

| Cases | Minimum evidence from the changed SHA |
| --- | --- |
| AC03 / W02 | Independent positive and negative signed vectors for space, purpose, endpoint key, epoch, required capability and canonical envelope bytes; v15/new bilateral negotiation and downgrade rejection |
| AC05–AC07 / W04–W05 | Real native SDK entry through the new facade; membership alone fails business access; expired/revoked grants fail; cancellation at gather, race, proof and cleanup boundaries; receiver/pump/task/physical socket release receipts |
| AC08–AC09 / W06 | Actual QUIC, direct TLS and WSS peer proofs and authorized business bytes; one-way/all-UDP blackhole preserves the authorized WSS attempt; wrong TLS key is terminal; slow read, half close, frame bounds and cancellation |
| AC10–AC11 / W07 | Two endpoints and authenticated relay processes over real sockets; opaque inner encrypted bytes; tampered route/space/group/hop/next-hop rejected; 1200-byte Initial and complete 1280-byte IPv6 packet delivery with explicit MTU and fragmentation captures; bounded duplicate/reordered/expired reassembly and PMTU blackhole |
| AC12–AC14 / W08–W09 | Bilateral checks followed by actual QUIC business traffic on the same physical socket/interface; candidate generations, ICE role conflict, forged transactions, nomination and consent; NAT namespaces and source-port packet captures, plus separately recorded real external NAT execution |
| AC21–AC23 / W14 | Normal optimization and total old-path failure; simultaneous proposals, lost/repeated ACK, timeout, late control, revoke during drain; group isolation for direct-only versus relay; either preserved inner connection with measured RTT/PMTU convergence or explicit safe application recovery without replay |

Use GitHub-hosted Ubuntu network namespaces and mature `iproute2`/`tc netem`
fault injection for automatable L2, and Windows hosted runners for platform
compilation/tests. These experiments need production socket paths and business
proofs; UDP echo, loopback-only fixtures and a green build cannot satisfy the
whole acceptance group. Bind raw logs/captures and test results to source SHA,
workflow/job/run/attempt, runner image, lockfile digest and artifact checksums.
Real NAT, target GPU/driver, Android/iOS and cross-day device measurements remain
separate execution evidence even when Actions builds the measurement tools.

## Review disposition

The reviewed baseline provides substantial reusable transport, authorization,
discovery, business queue and recovery code. The shortest safe first slice is
an additive authority/connection facade wired into `NativeEndpoint` and the
AppCore production start path, plus typed carrier close completion and new
signed network objects. It should reuse the existing scheduler, pins, business
proofs and virtual UDP fragmentation. Generic multi-hop routing, bilateral ICE,
IPv6 TUN delivery and path continuity are not established by the reviewed
baseline and must remain explicit implementation/prototype work.
