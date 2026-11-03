# ADR 0082: pinned candidate control and bounded path transcript

Status: source implementation, pending exact-source GitHub-hosted validation.
Scope: W02/W14, AC22; this is not whole-work-package or target acceptance.

The existing route-set owner prepares an independent inner TLS standby. It
must not promote membership, a measured spare or a successful TLS handshake
into business permission. Old carrier failure cannot make a new path wider
than the original SessionPermit, PathGrant or transport group.

Two alternatives were compared. Carrying migration messages only on the old
business QUIC connection is simple but cannot negotiate when that carrier is
fully unavailable. Explicit control on the already pinned standby works
independently and keeps the old business runtime's streams inaccessible. The
second option is implemented as a bounded control slice, reusing Quinn TLS,
the existing capability exchange, installation Ed25519 signing and original
route-set currentness and cleanup owners.

The ordered installation peer pair elects a single proposal writer. Both local
owners may request a transition concurrently; they do not create two competing
proposal identities or reservations. The protocol signs a fixed canonical
550-byte envelope with Proposal, Accepted, Commit and Committed phases. It
binds deployment, space, session, permit, signed path projection, group, both
peers, original and candidate route binding, both connection TLS exporters,
business generation, consecutive old/new path epochs, short absolute expiry,
proposal nonce and fresh responder challenge. The new signing domain is
independent from business, reconnection and network-management signatures.

Capability exchange on this explicit standby requires both network-v1 and
path-migration-v1; legacy connections keep their original exchanges. The
leader chooses an expiry no more than two seconds ahead, capped by original
authority. Each receiver independently checks every original-scope field and
its own deadline. The monotonic I/O timeout is capped once for the entire
capability exchange and transcript. Every phase rechecks current authority;
cancellation, wrong identity, wrong transcript or trailing bytes close the
candidate. Task/socket release remains the original owner's responsibility.

Duplicate phases return byte-identical signed responses. Duplicate Commit
does not renew expiry or the receive grace. A completed receipt describes a
maximum 250 ms old-path receive grace capped by the original authority expiry;
revocation takes precedence. It grants no socket switch by itself. Timeout
after Commit is ambiguous and requires stop or safe application recovery; an
endpoint cannot silently roll back while its peer might have committed.

The current SDK entry lives on ContinuousRouteSetSession and consumes its
actual prepared standby, pinned original metadata and proved original TLS
binding. A completed opaque receipt may be consumed only by that owner, then
the existing input/media/business/carrier cleanup runs before fresh-generation
application recovery. An interrupted future fences the next attempt. New
allocations, business permits and endpoint proof still follow existing safe
recovery rules; old requests are not replayed.

Remaining work is explicit: transfer the unique raw candidate socket after
its control endpoint and every Quinn poller are released, preserve the actual
original inner connection, dynamically bind path epochs and observations,
bound old-path draining and loss holdoff, and drive both product owners while
only one side proposes. Until that is implemented and verified, this slice
does not promise in-place continuity, does not advertise migration on ordinary
active business sessions and does not close AC22. Existing independently
executed carrier-rebind feasibility remains separate laboratory evidence.

Source regressions cover canonical bounds, signature tampering, phase replay,
lost final-confirmation retry, clock rollback, terminal revocation and exact
finite grace; real mutually pinned QUIC tests cover concurrent owners, new
connection binding, scope/ALPN failures, cancellation and physical release. A
real HTTP/two-node SDK test executes the original standby owner control path,
proves business stays on its original route until explicit retirement, then
requires original business and standby socket release receipts. None of these
new tests has been run locally; R02 requires hosted Actions output.
