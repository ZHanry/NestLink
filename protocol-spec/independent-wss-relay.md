# Independent native WSS relay

`nestlink-server relay --config <node.toml> --listen 127.0.0.1:28746` runs an
independent data node with its protected installation key and pinned control
configuration. It uses authenticated node control, signed usage reports and the
current resource snapshots described in [node-resources.md](node-resources.md).
It never opens or shares the control center's SQLite file. The control process's
existing combined WSS service remains available through its original route.

The node exposes `GET /api/v3/nodes/{id}/relay/{allocation}` on its own HTTPS/WSS
entry point. Caddy terminates normal outer HTTPS and proxies WebSocket upgrades to
the loopback listener. `packaging/caddy/Caddyfile.relay` is an example; configure
the actual node hostname through `NESTLINK_RELAY_HOST`. The route inventory and
generated OpenAPI mark this operation as a `relay` role endpoint, not a control
center endpoint. Starting `relay` requires a relay role in `node.toml`. Do not run
`node-control` as a second runtime for the same registration alongside `relay`.

## Exchange and authority

1. The service sends `NodeRelayChallenge { nonce }`, a fresh random 32-byte
   challenge for that socket.
2. The endpoint sends `NodeRelayHello { device_id, public_key, allocation,
   signature }`. Binary values use base64url without padding. `allocation` is
   the original encoded `SignedRelayAllocation`. The installation signs the
   complete ticket, WSS transport and socket challenge under the existing
   `NodeRelayConnect` action.
3. The service requires the URL's canonical node/allocation UUIDs to match the
   ticket, verifies its issuer against a current authenticated resource snapshot,
   and prepares the candidate without occupying a role or node meter slot. A newly
   issued allocation may wait at most 700 ms for the next snapshot. No business
   bytes are forwarded during this wait.
4. The shared [carrier selector](relay-selection.md) waits for both roles on
   the same transport, rechecks current authority, issuer and the original
   monotonic ticket deadline, then commits guards and discards other candidates.
   Only when both endpoint guards are live does each socket receive
   `RelayReady { ready: true }`. Controller and host then establish mutually
   pinned TLS 1.3 inside the WSS carrier and perform the native session proof
   before using authorized business channels.

No account management bearer or cookie is required or sent to the data node.
Those credentials cannot substitute for endpoint proof. The node forwards opaque
binary frames; it has no endpoint TLS key, session plaintext or media decoder.
The byte/rate budgets count opaque forwarded bytes, including inner TLS/proof
overhead, rather than decoded media bytes or delivery acknowledgements.

Native `Sdk::node_relay_route` takes an administrator-approved local node origin,
the verified permit and verified allocation. It resolves at most 32 addresses
once, retains Host/SNI and normal outer TLS certificate validation, and pins
actual dialing to those literals. The route binds the full permit digest and
rejects a different permit or address. Loopback HTTP must be explicitly enabled
and stay on actual loopback addresses. Peer candidates cannot choose the node
authority. Integration with the shared native candidate
race is available through `dial_native_with_relays` and `NativeRelayRoute::Wss`.
Signed address discovery is specified in [node-discovery.md](node-discovery.md).
The explicit local entry point remains an administrator-configured route.
The same command also starts the allocation-pinned QUIC service
described in [independent-quic-relay.md](independent-quic-relay.md).

## Bounds and termination

WSS and QUIC share a bound of 256 active/pending sockets, 128 pending allocations,
256 pending candidates, 1024 peer IP rate records and 120 attempts per IP per
minute. The WSS hub bounds active pairs to 128. With a
reverse proxy this limit observes the proxy's socket IP; deployment rate policy
and capacity acceptance remain to be validated. Endpoint hello is at most 16 KiB,
business WebSocket frames at most 64 KiB, and each destination holds at most eight
frames. Challenge write and data writes are bounded to 500 ms; hello is bounded
to three seconds and peer pairing to five seconds. Client setup also has the
original signed ticket's remaining deadline as a total monotonic budget.

Both directions share the allocation's rate/lifetime bytes and the node's common
meter. Full queues wait at most 500 ms outside the authorization lock and recheck
all authority on retry; a failed enqueue consumes no quota. The writer rechecks
the guard before emitting already-admitted data without charging it twice.
`wait_stopped()` owns the minimum node/resource/allocation monotonic deadline,
observes fresh live updates without treating them as stop, and watches terminal
resource/global stop while reader, writer or queue wait is idle. It does not rely
solely on the control watchdog.

Closing one role, quota change, resource or node revocation, HTTP resource
failure, lease expiry, listener shutdown and cancellation discard both I/O
futures and close the real sockets. Exact-token hub cleanup cannot remove another
registration. The listener future owns terminal node stop even when canceled;
shared control-owner lifetime does not leave background forwarding alive.
Closed allocation identities cannot reconnect and reset admitted bytes.
An uncommitted candidate's cancellation or timeout removes only its own token;
it cannot stop a winning pair or burn an otherwise unused allocation identity.

Independent promises still retain control-side capacity until signed expiry plus
the existing clock margin. Reliable signed close receipts and final shutdown
usage accounting remain open. Local counter cleanup is not a capacity refund.

## Development verification

The actual HTTP/control/node/SDK fixture establishes two inner TLS peers, performs
native business authorization and transfers 256 KiB synthetic video-channel
bytes plus a reverse-direction frame. It tests idle remote revocation, quota
revision, HTTP resource loss and listener cancellation; both peers close within
two seconds. Other fixtures test real lifetime-byte exhaustion, wrong endpoint
key/transport, challenge replay, closed-identity rejection, foreign routes and
live renewal on the same two sockets past the original allocation deadline.
Guard unit fixtures additionally exercise timer expiry with no watchdog.

These are loopback development checks with real sockets and cryptographic
endpoints. They do not validate deployed Caddy/public certificates, company/mobile
networks, actual captured media, a 72-hour/capacity run, installed applications or
formal product acceptance. QUIC datagram relay/virtual UDP development is recorded
separately. TURN, edge/tunnels, browser media and complete platform/UI integration
remain open.
