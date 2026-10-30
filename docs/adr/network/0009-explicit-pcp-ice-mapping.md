# ADR 0009: Explicit PCP mapping of the original native ICE port

Date: 2026-10-31 (Asia/Shanghai). Scope: the first W10 / F03 / F20 source
slice, contributing to AC15 and AC16. Status: implementation in progress;
Actions compilation, component integration and actual-router evidence pending.

The current native ICE dialect signs exactly one candidate per endpoint and
connects the original physical socket to the authenticated peer tuple. W10 must
not turn a gateway observation or a guessed neighboring port into authenticated
peer authority. A first useful mapping slice can preserve this dialect when a
PCP server grants the same external port as the actual local UDP port.

## Component decision

Use `crab_nat = "=0.8.1"` (MIT) for PCP request encoding, connected UDP exchange,
response validation, nonce checks and single-port deletion. The reviewed source
is commit `296cc168bb0805fe64b9378d0cc76a833e903ce0` of
<https://github.com/ryco117/crab_nat>, whose Cargo.toml is version 0.8.1.
The non-yanked crates.io publication is dated 2026-07-06 and has SHA-256
`b6571f33e3d6520c5b08e54b1202836c6ebe68b950f450951804d037a875c25c`.
Official version metadata: <https://crates.io/api/v1/crates/crab_nat/0.8.1>.
This review is a component choice, not a security or platform qualification.

Alternatives examined:

| Candidate | Relevant interface | Decision for this slice |
| --- | --- | --- |
| `portmapper` 0.20.0 | Multi-protocol service, external-address watcher, `deactivate()` | Its public client does not provide an awaited deletion/task receipt; retain as a later option rather than claim a completed cleanup from a queued deactivate message. |
| `igd-next` 0.18.0 | Async gateway discovery, add/remove ports, generic mapping enumeration | Useful UPnP component, but a separate ownership/readback design is needed before deletion can safely share this slice's nonce semantics. UPnP remains unimplemented. |
| `natpmp` 0.5.0 | Synchronous/async NAT-PMP | The reviewed core reader does not validate the received datagram length before reading its fixed buffer. Do not select this implementation for the initial slice. NAT-PMP remains unimplemented. |
| `crab_nat` 0.8.1 | Explicit `pcp::port_mapping` and `pcp::try_drop_mapping` with caller-retained nonce | Selected. No automatic protocol fallback, default-gateway guessing, scan, or all-ports operation is used. |

NestLink implements only consent, fixed budgets, lease ownership, the existing
ICE socket handoff and UI. It does not implement a replacement PCP codec.
Dependency resolution and lock generation run in GitHub Actions; the local
workspace only reviews and applies the resulting lock artifact.

## Explicit permission and physical socket

The local network setting `pcp_gateway: Option<Ipv4Addr>` defaults to `None`,
including when reading historical settings. A nonempty value is explicit local
approval of one RFC1918 gateway. Deployment `allow_pcp_mapping` is a separate
default-off administrator permission, read through authenticated
`GET /api/v3/discovery/native/pcp`. The strict historical STUN configuration
shape is unchanged. Both the Core entry and the SDK's final physical owner
require this deployment-bound policy when local consent is present. `None`
does not request the new endpoint. Effective use is their intersection; neither a
remote peer candidate nor a gateway response can enable mapping.

The production owner first binds the actual ICE socket through the existing
physical route manager. It retains that socket while requesting one UDP port.
The request names this local address and nonzero port. Only a granted IPv4 tuple
whose external port equals the original local port can be used with the mature
ICE agent's existing static server-reflexive mapping interface. A changed port
is deleted and cannot enter signaling. The ordinary local address policy still
filters the external IP. The existing endpoint signs the final ICE parameters,
and the peer uses the existing exact tuple/source restriction. No data receiver
or substitute business socket is added.

The gateway control exchange uses the component's separate connected control
socket to the one approved gateway on UDP 5351. That socket never carries
business data. PCP binds the client address in the request and checks the random
nonce in the response; a router reporting address mismatch cannot grant a
usable mapping. No third-party or wildcard-port PCP request is issued.

## Budgets, terminal state and receipts

There is one request in flight per owner. Each exchange has a one-second outer
budget and at most one retry (200 ms initial timeout, 400 ms retry ceiling).
The original signed authorization deadline never moves. Requested leases are
at most 120 seconds and reserve one second before that original deadline; a
grant longer than requested or beyond the deadline is rejected and deleted.

The owner allocates and retains its random nonce before sending a create. A
lost response, timeout or cancellation therefore still leaves the exact nonce,
gateway, local client, protocol and port available for deletion. Initial failure
cannot silently create a usable candidate. Renewal reuses the original nonce
and the original authorization deadline at half the granted lifetime. Any
external address/port change, gateway epoch rollback, renewal rejection or expiry closes the original
ICE agent. It cannot activate an unsigned alternative or prolong a permit.

Normal shutdown stops business transmission, interrupts and joins the original
renewal task, awaits the nonce-specific deletion response, and completes the
existing ICE/socket cleanup. Failed deletion is a cleanup error. A dropped
owner attempts bounded cleanup but supplies no successful cleanup receipt.
Neither a task abort request nor a queued delete counts as confirmed removal.
The component's all-ports deletion API is never called.

Ownership and the observed lease remain in the session owner in memory. This
slice does not claim a durable crash-recovery journal or immediate removal
after process/power failure: a crashed process cannot renew, and the finite
gateway lease eventually expires. Actual router behavior, deletion response
semantics, kernel NAT forwarding and crash expiry require AC16 evidence.

## Verification and remaining work

New traversal L1 tests exercise the mature component over real UDP against a
controlled PCP responder: same-nonce renewal and exact deletion, changed port,
wrong nonce, excessive lease, changed-address renewal, gateway epoch rollback,
failed deletion ACK, actual lease expiry, and canceled create followed by exact
cleanup. Failed, canceled, expired and released owners cannot be re-established.
Constructor tests reject public/loopback/link-local gateways, unspecified or
non-private client addresses, port zero and expired authorization. Local
settings tests check default-off historical decoding and explicit private
gateway validation. These are test plans/source until their exact SHA passes
GitHub Actions; a controlled protocol responder is not an actual NAT router.

W09's physical same-socket experiment remains independently required. W10
still lacks TCP coordination, bounded symmetric-NAT strategies, NAT-PMP,
UPnP, and required L2/L3/L4 router/topology evidence. This source slice cannot
close W10, AC15 or AC16 or justify a full-feature release claim.
