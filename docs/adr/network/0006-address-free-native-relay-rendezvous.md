# ADR 0006: signed native rendezvous without a peer-supplied address

Status: implemented; matching Actions validation pending.
Date: 2026-10-30, Asia/Shanghai. Scope: W02/W05/W06, AC03/AC07/AC08/AC09.

The existing native inbox could not start an approved session when local
destination consent removed all direct candidates and the deployment's combined
WSS relay had no address suitable for peer candidate signaling. The local SDK
already knows and authenticates that relay through its configured management
origin. Requiring an unrelated direct candidate before using that relay makes
relay fallback depend on a permission it does not need.

We compared weakening candidate address validation, advertising a fabricated
address, and adding an address-free declaration to the existing signed signal.
The first two options conflate a peer assertion with authority to dial a target.
We choose an optional `rendezvous: "combined_relay"` declaration, using the
existing device signature, permit digest, endpoint keys, connection/lease/network
generations, monotonic sequence, HTTP authorization and original deadlines.
The declaration cannot coexist with candidates, browser SDP or browser ICE and
requires a permit that explicitly allows Relay. Unknown declaration values fail
deserialization. There is no URL, IP address, bearer credential or business grant
in this declaration.

The SDK emits it only when no safe candidate can be advertised and an actual
combined relay route was obtained from its own configured SDK or supplied route.
The receiver accepts the current signed declaration as a rendezvous hint. Each
endpoint still constructs its relay route from its own trusted management
origin, rechecks the current permit, and completes pinned inner TLS and mutual
business proof. A declaration cannot enable Direct, redirect DNS or grant Input,
FileWrite, network membership or raw IP access. The existing scheduler, channel
queues, cancellation and cleanup owners remain the data path.

Absence is the default and is omitted during serialization, preserving old
signed signal bytes. Existing browser offer/answer and trickle flows set None.
Peers/servers predating this extension reject a present unknown field; they
cannot support this candidate-free native fallback. They must use the existing
supported candidate flow or upgrade both endpoints and management service.
No mixed-version success or silent downgrade is claimed for this extension.

Protocol tests cover relay permission, absent/default round-trip, unknown
targets, mixed SDP/candidate payloads and stale generations. Actual AppCore
inbox tests exercise HTTP, signed wakeup, combined WebSocket, inner TLS, consent,
remote proof, stop and no-restart. A relay-only case exercises the path with no
direct socket or private dialing consent. Matching Windows/Linux Actions results
are required before recording success; no public NAT or target acceptance is
implied.

Related lifecycle repair: a successfully closed transport's failure sender is
released with its owner. `ChannelRuntime` records that successful receipt before
dropping the owner, so its ensuing empty observer closure is cleanup. A live
observer disappearing still fails closed, and any original failure value remains
authoritative even after sender closure. Recovery rechecks real revoke/protocol
facts after cleanup; a successful resource receipt cannot authorize reconnection.
Tests distinguish successful original UDP release from observer loss and an
explicit PermissionDenied failure. Existing real idle QUIC recovery covers the
complete two-party successor proof and business transfer.
