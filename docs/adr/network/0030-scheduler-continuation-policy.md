# ADR 0030: Optional continued policy in the sole connectivity Scheduler

Status: source implemented, awaiting GitHub-hosted Actions verification. This
is a policy and opt-in SDK owner slice of W13. Its new production API performs
real transport-only standby preparation/probing, but does not complete W13,
W14, AC20 or AC21.

## Choice and original authority

The existing Scheduler races bounded native candidates and finishes at its
first success. A separate continuous manager would duplicate route selection
and lifecycle ownership. We compared that approach with extending the same
Scheduler with an optional continued phase. We chose the optional phase:
legacy new/poll/finish remains unchanged unless explicitly enabled. An owner
may attach it to its successful existing race, or resume this same Scheduler
type after establishing an original-group carrier. Neither entry point
performs a handshake or proves that a supplied carrier is authorized.

The new OriginalGroup freezes the business digest and generation, original
PathGrant ID, transport group, purpose, allowed path set and monotonic original
deadline. Its bounded original route list freezes each complete observation
binding. Route identity is (transport_group, route_binding), never a socket
address. Two registered nodes using the same endpoint hint remain distinct.
Missing group/route identity, duplicate bindings, an incompatible purpose,
direct_only violation or candidate network generation mismatch is rejected.
An existing native candidate must match its race winner when opting in.

The intended source is SDK VerifiedRemoteRouteSet and its distinct typed
VerifiedRemoteRouteCandidate values. That existing SDK owner verifies current
readback, original grants, node pins, static byte limits, login and business
bindings. The policy accepts a synchronous CurrentAuthority fact for every
transition, requiring the exact original group and checked_at_ms equal to the
current local decision time. The future adapter must obtain it through the
SDK's is_current_for/candidate_for_admission gates; a retained plain metadata
copy is insufficient. Member availability can withdraw one route without
revoking the other. Whole-group withdrawal or changed frozen authority is
terminal. No transition creates, refreshes or redistributes byte authority.

## Measurements and hysteresis

Feedback comes only from an actual local active or prepared transport owner,
with the exact frozen binding and an opaque owner-incarnation token. Preparing
the same original route again creates a new token, fencing late measurements
and failures from the retired connection. A work completion must match its
one outstanding work token, epoch and deadline and cannot use feedback from
before that work began. A cached read is not a new transport observation.

The adapter retains the genuine local feedback timestamp.
LocalPathMeasurements::rtt_observed_at_ms returns the actual local ACK sample
time without renewing it on idle polls or reads. The original PathObservation
now exposes timed_snapshot, translating that sample's clock to its actual
monotonic Instant and preserving individual None/expiry and terminal checks.
The SDK uses that time in its original policy clock; it never stamps the time
of a cached snapshot read. Pure policy tests remain synthetic L1 evidence.

Snapshots older than three seconds become unknown. Future or non-increasing
feedback is rejected; a reversed decision clock terminates this stage. Idle
polls cannot refresh measurement age. Unknown capacity, cost, RTT or smoothed
RTT change fails any hard constraint that requires that value. Offered local
business TX never substitutes for available bandwidth. Sent packets and newly
declared losses remain raw counters: delayed losses may exceed packets sent
in a window, so the policy neither derives a loss probability nor ranks those
windows as if they represented equal packet cohorts. Current optimization
uses measured RTT, with optional known capacity/cost/RTT/change hard limits;
a broader validated quality model remains future work.

A normal switch requires at least 15 percent lower measured RTT, sustained
for two seconds with fresh observations from both owners spanning that hold.
An expired gap resets the hold before accepting replacement feedback. A
committed switch starts a ten-second optimization cooldown. A locally failed
or unavailable active route can propose an already proved, fresh and
constraint-satisfying standby immediately, including during cooldown. Unknown
measurements are not a fabricated failure or a zero-cost fast path. Without a
usable standby the owner receives an explicit Unavailable policy action.

## Work, proposals and cleanup

The stage retains one active identity, at most one standby and one preparation
or probe operation. Prepare and Probe are bounded by two seconds and 700ms,
respectively, always capped by the original group deadline. Only explicit Tick
input schedules network work. Cold preparation is demand driven (or needed
for a failed active path); idle standby probes double their interval up to
30 seconds, while demand restores the one-second interval. Repeated ticks
cannot multiply outstanding work. A timeout retires that standby and fences
its delayed result.

Prepare, Probe, ProposeSwitch, CancelProposal and Retire are pure actions to
the sole original transport owner. No action changes a carrier, migrates a
connection or starts a business stream. A proposal contains an opaque
sequence, current path epoch, exact source and target, reason and fixed
deadline capped by two seconds, the original group and the freshness of its
supporting observations. New observations never extend an old proposal.

W14's original owner must serialize bilateral preparation/switching, recheck
this exact proposal/epoch and typed authority, then explicitly Commit after
actual switch success. Commit rechecks target freshness, hard limits, the
normal-switch hold/cooldown and fixed proposal deadline before advancing the
policy epoch. Delayed, duplicate, rejected, expired or invalidated proposals
cannot become current again. This policy commit is a bookkeeping transition,
not evidence that Quinn or any business session actually migrated.

Retire carries an opaque physical cleanup token. A Drop request does not
consume it. Further preparation waits until the owner acknowledges completed
cleanup with the exact token, preventing a third owner while an old route
drains. Cleanup receipts can still be consumed after terminal withdrawal but
can only remove owners. Terminal policy, network change, expiry and security
failures cancel proposals and retire all retained original owners. Late work,
feedback, failures or commits cannot revive the terminal stage.

## Evidence and remaining integration

New policy regressions cover independent same-address identities, frozen
authority/purpose/direct_only/generation, transient and stale feedback, exact
15-percent/two-second thresholds, normal cooldown and failure bypass, unknown
hard limits, raw deferred-loss/offered-TX inputs, clock and authority fences,
one bounded work item, idle backoff, cleanup receipts, old owner incarnations,
proposal expiry, delayed/duplicate commits and terminal non-revival. Existing
legacy Scheduler tests remain in place. Run all compilation, formatting,
clippy and tests only in hosted Actions under R02; source is not a passed run.

## Opt-in SDK continuous session owner

connect_continuing_network_remote_route_candidate enters the existing selected
member's node admission, business proof and ChannelRuntime carrier owner, then
retains that original runtime and the one Scheduler in ContinuousRouteSetSession.
The original connect_network_remote_route_candidate API remains compatible.
Both peers must select the same active member and drive their session owners'
async poll at least once per second. This is an explicit caller-driven API;
there is no second scheduler or silent background selection loop.

Each poll uses the actual caller's current SDK/login and device identity.
Authenticated route-set refresh preserves the immutable fingerprint and caps
the original deadline. Its refresh schedule starts at the real fetched time,
not at the time connection setup returned. Every admission/probe again checks
the typed candidate gate, deadline, original relay pin and route binding.
The existing signed-host resolver and all-answer address/loopback policy apply.

Prepare performs actual mutual node admission and original-group inner QUIC
TLS on the other member, within its policy work budget. It retains no business
SessionSetup or channels for that spare. Probe sends one small encrypted
transport DATAGRAM, waits within the original bounded work deadline for newly
observed Quinn ACK feedback and samples the mature connection's RTT/counters.
This is local transport feedback, not an application echo, exact probe-ACK
cohort proof, available bandwidth or business delivery evidence. Missing
capacity/cost remains unknown. Original node meters and statically split byte
limits apply to preparation and these probes without replenishment.

The session stores pending AdjacencyEndpoint/RoutedEstablishment/RoutedTransport
owners before awaiting, so cancellation cannot lose their original receipts.
The next poll retires interrupted work before starting another attempt. A
small guardian observes the original business stop/cancel/deadline and revokes
the spare even while the application is not polling; it owns no scheduler or
business data and joins during cleanup. Node Pair/seen permits an original
endpoint role only once: after an attempted member is retired, this adapter
does not replay that allocation even if its metadata still says available.

The owner consumes Retire only after actual joined physical cleanup. It keeps
pending retirement tokens and first close deadlines across cancellation and
failure. ChannelRuntime::wait_stopped_before caps its existing close budget,
so an enclosing shutdown shares one absolute deadline with the spare. Drop
requests closure and never supplies a completion receipt.

A current proposal is exposed as RouteSetRecoveryProposal and explicitly
requires fresh business admission. There is no SDK Commit API or in-place
carrier replacement. retire_for_recovery validates the exact proposal, target
and deadline, then retires the old business generation and every spare using
the existing stop/input-release/queue-discard/cleanup path. The application
must subsequently use its existing recovery coordinator to obtain new business
and network authority; the old spare cannot be promoted into a business
channel and no old input, clipboard, audio or arbitrary request is replayed.
Automatic bilateral W14 negotiation and automatic redial remain open.

The new real network-relay test source drives two actual owners, proves two
node connections per original member, completes actual bounded spare probes,
keeps FileRead on the unchanged active binding/epoch, withdraws only the spare
and immediately rebinds its two physical sockets, then revokes and cleans the
original active sockets. Its exact Actions run has not yet been verified.
Production UI/daemon integration, fully automatic safe application recovery,
authenticated W14 switching, broader quality policy and target evidence remain
required before W13 or its acceptance groups can close.
