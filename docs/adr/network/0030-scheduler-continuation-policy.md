# ADR 0030: Optional continued policy in the sole connectivity Scheduler

Status: source implemented, awaiting GitHub-hosted Actions verification. This
is a policy slice of W13. It has no production carrier adapter and does not
complete W13, W14, AC20 or AC21.

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

The adapter must retain the genuine local feedback timestamp. Existing
PathObservationSnapshot does not itself expose that timestamp, so reading a
snapshot and stamping its read time is not a valid production adapter. It must
also keep individually expired values None. This prerequisite remains open;
the policy tests supply explicit synthetic timestamps and are L1 evidence.

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

The next slice must connect the typed SDK original route set and genuine
feedback timestamps to this optional phase within the original transport
owner, perform real bounded probes, and implement W14's authenticated switch
or safe application recovery. It must retain original cumulative quotas,
path permissions, business proof, terminal priority and cleanup receipts.
Actual business data, migration/recovery and target evidence remain required.
