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

The SDK entry lives on ContinuousRouteSetSession and consumes its actual
prepared standby, pinned original metadata and proved original TLS binding.
poll_with_path_migration drives the existing scheduler and responds to a
reliable, fixed 176-byte UNI-stream wake-up on that standby. Either endpoint
may request a switch; the ordered pair still elects the sole signed proposer.
The wake-up binds the original permit, group, TLS exporter, both route bindings
and current path epoch. It is only an advisory request: both owners recheck
their own prepared state, fresh feedback, hard constraints, original authority,
cancellation and business lifetime before capability exchange and signatures.
It is separate from the BI capability/transcript streams and creates no second
scheduler or reservation. Cancellation fences another attempt; a timeout does
not authorize a new proposal identity or rollback.

An explicitly negotiated ALPN adds endpoint-only framing inside the existing
opaque routed packet. Control and Business(epoch) have separate receive queues
with one aggregate bound of 32 packets and the original packet arrival age.
This prevents a peer switching first from exposing the original business CID
to the other peer's still-running control endpoint and receiving a stateless
reset. The relay remains unaware of business CIDs and charges every framing
byte to the same original cumulative quota. Ordinary constructors retain their
old ALPN, bytes and capability exchange.

For file-only proved channels, commit transfers the actual candidate owner
into the original business owner. The candidate control endpoint, connection
and every tracked writable poller must release before its business socket view
is handed to Quinn's existing rebind_abstract. The original inner stable ID,
TLS exporter, reliable streams, business generation and group remain unchanged.
The route binding and consecutive path epoch update every cloned observer;
measurement revision tags prevent old ACK, throughput or loss windows from
being relabeled as new-path facts. Fresh counters require a new baseline and
subsequent real ACK. The initial inner MTU is conservatively fixed at 1200;
production adaptive PMTU convergence is not claimed by this slice.

The explicit migratable SDK node constructor uses Quinn's existing 900 ms
outer idle timeout and 200 ms keepalive. The locked Quinn API installs these
transport parameters at outer TLS setup; it cannot change them after the inner
capability exchange. This profile is therefore opt-in only for the new original
migration owner, whose inner ALPN and bilateral capability proof remain required
before business handoff. Legacy node and chain constructors retain their
10-second idle / two-second keepalive profile. No application ACK heuristic,
longer node lease, grant extension or deadline renewal substitutes for physical
loss detection. The ordinary profile's ten-second idle timeout would otherwise
expire at the original ten-second node authority, leaving no authorized DROP
migration window.

The existing general remote runtime requires View to create its lifecycle.
The new migration ALPN therefore has one explicit file-only admission adapter:
the signed original permit must contain only FileRead/FileWrite, and at least
one of them. It reuses the same endpoint proof and exact channel profile, and
authorizes that original file permission to create the lifecycle. Every legacy
entry keeps its View requirement. A View/Input/Audio/clipboard permission cannot
be hidden by temporarily idling the corresponding channel or calling this
adapter directly.

A prepared independent standby permits one physical-loss hold of at most two
seconds, capped by the original authority deadline. Its actual gate publishes
held-loss facts to the same scheduler, separately from terminal lifecycle
failure. Revocation, authenticated authority shutdown, protocol failure and
expiry bypass the hold. Old-path receive drain has one absolute cutoff of at
most 250 ms; repeated calls cannot renew it. After commit, errors from that old
gate cannot overwrite the new carrier's lifecycle. Cancellation preserves the
original, pending and draining owners and their actual completion receivers.

The current route-set readback separates `authorized` from `available` for
each immutable original member. Explicit node revocation, identity replacement
or relay-role withdrawal clears authorization; lease/runtime/endpoint changes
only affect availability. Path, business, membership and transit revocation
still reject the complete authenticated GET through the original policy
snapshot and signed-grant checks. The retained business observer requires its
actual current member to remain authorized even during a physical-loss hold.
Its shared required-member mask includes both original and candidate authority
before detach/rebind/drain begins, and cancellation preserves both requirements.
Only successful migration with actual old-owner release narrows it to the new
member, so revoking a released old node cannot revoke the healthy current one.
Independent standby withdrawal retains the existing healthy-member behavior.

The current input/media/clipboard business formats have no per-frame path
epoch. Even an idle permission could later admit an old frame already buffered
in an existing reliable stream, so clearing a local queue or requesting one
keyframe would be insufficient. The complete proved channel set therefore
selects full safe recovery for any of those channels. After bilateral control,
the original stop boundary releases held input and platform transient state,
discards old queues, joins all business I/O and releases both physical owners.
AppCore uses this automatic entry and then its existing recovery coordinator:
the same application session receives a fresh business generation, new endpoint
proof, fresh media owners and the required first keyframe. No old input or
arbitrary request is replayed. Native media does not claim original-generation
seamless continuity. The lower-level commit API independently rejects these
unsafe channel sets, so callers cannot bypass the product boundary.

Successful safe recovery first joins the control endpoint while its raw
carrier remains authorized and owned. The unique Committed writer already
awaits Quinn's acknowledgement of the final signed bytes; it then initiates a
dedicated inner-control completion close. The Committed reader waits for that
exact authenticated close before closing its own control endpoint. Both await
their original tracked endpoint/driver/poller release receipts within the same
original two-second control deadline, then repeat the existing exact authority
GET before returning a recovery receipt. Only after those joins may full
business shutdown revoke standby raw I/O. Otherwise the reader could destroy
the final ACK path while the writer still awaits it. This completion close is
control lifecycle evidence after all four signed phases, never new business
authority or a recoverable physical-fault classification. Real denial,
revocation, cancellation and expiry still revoke immediately; no generic
ConnectionLost or ApplicationClosed error is accepted as completion.

This bounded two-member route set consumes each original node admission once.
After a retained-file migration the old allocation is fully released and is
not replayed as another standby. A later failure uses the existing independently
authorized safe-recovery rules; no poll refreshes group lifetime or quota.

An actual failed original carrier may also enter the existing complete safe
recovery while its prepared-migration hold is still active. That hold keeps
the business lease temporarily live, so a successful lease read alone cannot
mean the old physical path is healthy. The original owner must expose its
still-current held-loss deadline, which independently checks live authority
and the fixed two-second limit. Healthy paths without that observation remain
ineligible. The same complete shutdown, physical cleanup, original recovery
budget, authenticated management readback and fresh business proof still apply.

Source regressions cover canonical packet/request bounds, signature tampering,
phase replay, lost final-confirmation retry, clock rollback, terminal revocation,
hold expiry and nonrenewing drain. Real pinned QUIC and HTTP/two-NodeControl
tests cover bilateral control, a single larger-peer request with ordinary
smaller-peer polling, retained original file streams after old UDP address
release, unchanged TLS binding/generation/group, and observation epoch reset.
The safe branch attaches the production InputController to a recording device,
holds a key, queues old text/video, then requires release/reset and rejects old
queue delivery after teardown. These are implementation regressions, not real
OS input or media presentation evidence. No new tests were run locally; exact
source hosted Actions are required by R02.

AC22/W14 remain open until the production SDK/owner path runs through the
Actions namespace fault matrix, including actual old-path DROP or external
relay-process loss, cancellation at detach/rebind/drain, held external pollers,
revocation during drain and target evidence. The existing carrier-rebind
prototype is separate feasibility evidence. Windows interactive recovery,
real input/media presentation, fresh keyframe and p95 recovery targets retain
their original L3/L4 requirements; this source slice does not close them.

The dedicated `network-sdk-migration.yml` dispatch defines a separate production
SDK DROP slice. An ordinary-user integration test runs management HTTP, two
registered production node listeners, original endpoint proof and approved OS
FileRead workers inside one owned loopback namespace. An external controller
only installs nftables UDP DROP for the signed active relay port; it never
calls NodeControl.stop or injects an authenticated close. Twenty fresh original
authorities use ordinary one-second SDK polls and no manual migration request.
Each trial requires both epochs to advance, unchanged original exporter,
generation, group and exact lease deadlines, all fresh file bytes verified on
the new route, and real old/standby UDP and file-worker cleanup. Timing starts
before requesting DROP installation and ends after complete source verification,
so dispatch overhead is included conservatively. The original network p95
threshold remains three seconds. Exact-source hosted execution, nft counters,
complete pcap, process identity and namespace cleanup receipts determine its
result; adding this harness alone establishes no passing evidence. This does
not close public NAT, external relay-process crash, native interactive recovery
or the remaining detach/rebind/drain/external-poller matrix.
