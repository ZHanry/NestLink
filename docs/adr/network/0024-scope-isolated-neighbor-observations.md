# Isolate spaces on one authenticated neighbor observation connection

Status: source implementation; exact-source hosted validation pending.

One physical neighbor can be delegated into several spaces. Binding every probe
to the complete space neighbor list made a change to A-C invalidate an otherwise
current A-B observation. Binding a shared connection to its original whole space
list also made a space withdrawal close independent observations. A false down
report permanently retires an immutable chain under ADR 0022, so this is a
production lifecycle error rather than a cosmetic health fluctuation.

Two alternatives were considered. Independent connections or streams for every
space simplify cancellation, but multiply socket/stream owners and consume the
existing shared admission budgets. A bounded pipeline on the same pinned peer
retains the original ownership model and can give each space an explicit result.
The latter is selected; it introduces no data forwarding capability.

The physical connection freezes the registered peer key, incarnation and endpoint.
Each Work freezes only the local signed authority header and its exact intended
neighbor. Other neighbors and other spaces are not part of that Work. Current
NodeControl getters continue to enforce the original publisher's monotonic
deadline and the current resource snapshot. A new credential creates new Work;
it cannot restore an old observation or extend an old grant.

Each fixed probe now names both publisher digests, the space, endpoint revisions
and a fresh nonce. The typed reply either supplies the corresponding reversed
current bindings or rejects that bounded challenge. A rejection supplies no
publisher or up-edge proof and retires only that scope's observation. Malformed
responses, unsolicited streams/datagrams and physical peer changes still close
the connection. Previously independently verified observations remain subject to
their original freshness and current-authority checks. No TTL or failure budget
has changed. Report tasks have an explicit global cap of 128 as well as the
existing two-per-space cap.

The observation ALPN is unreleased. The request/reply format is updated together;
it is separate from NRD1, NRD2, legacy v15 and every business permit. This does
not negotiate business path migration.

The registered-node regression creates two actual spaces on the same two real
node UDP owners, revokes one space's publisher, waits until both current resource
snapshots reflect withdrawal, and reads the unaffected original chain for longer
than an advertisement lifetime. Its original grant expiry and final UDP release
remain mandatory. Source completion alone does not qualify AC18/AC19.

The Web management panel separately permits revocation by known durable node or
export ID after the node becomes unavailable. Issuance still requires a current
eligible node and lease; an entered revocation ID cannot become an issuance
target. Re-reading policy clears historical publisher/export confirmations while
retaining draft IDs for exact readback.
