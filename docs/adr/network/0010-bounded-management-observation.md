# ADR 0010: Bounded control admission and independent route observation

Date: 2026-10-31 (Asia/Shanghai). Scope: W04/W11 route lifecycle.
Status: source implementation; exact-source Actions required.

The real two-node fixture at 8186f75 received HTTP 429 on route readbacks on
both platforms. Windows also received 429 on a signed node TURN-resource poll.
That poll has a separate 1024/minute limiter, so the observations do not prove
the 30/minute network-path budget was the sole cause. The original database
admission rejected a ninth concurrent operation immediately. That is a separate
burst constraint from authenticated rate limits.

The SDK independently checks current authority at setup and final handoff, then
observes each endpoint's route every second. Sharing a 30/minute mutation budget
with these reads makes even one healthy endpoint stop during a long session.
Increasing the common limit would also increase signing allowance and still
allow read traffic to consume revocation capacity. Making observation failures
nonterminal would weaken current-authority enforcement. Neither is selected.

Reuse the existing authenticated, one-minute, bounded server rate buckets with
three namespaces per authenticated login:

| Operation | Limit per minute | Callers |
| --- | --- | --- |
| Issue | 30, unchanged | Membership, direct path and relay allocation issuance |
| Observe | 512 | Current membership, path and relay readback |
| Revoke path/allocation | 30 | Explicit path or allocation termination |

512 allows eight one-second observers plus 32 setup/handoff reads in a minute.
This is an explicit capacity bound, not an unbounded polling entitlement or a
qualification of twenty active pairs. Every namespace retains the existing
2048-login bound and stale-bucket eviction. Authentication precedes reservation;
resource authorization is checked again in the database operation. Observation
exhaustion still stops SDK business. No backoff extends an authorization lease.
The administrator policy limiter remains 30/minute with its original tests.

The observer's first periodic tick is one second after start. Setup and final
handoff still perform their existing immediate reads, so a duplicate initial
tick adds no authority check. Every failure, changed fingerprint or deadline
still stops the original lease and its business owner.

Reuse Tokio semaphores and timeout for database admission: eight active blocking
operations, at most eight async waiters, and at most 200ms waiting. Waiting holds
no Store lock and spawns no blocking task. Overflow and expiry return 429.
Cancellation drops an unadmitted future; an admitted blocking task retains its
permit until completion. The existing outer node poll deadline remains 700ms.
This absorbs brief overlap without adding workers, an unbounded queue or a
request retry mechanism. It does not promise success under sustained overload.

Actions tests cover actual signed relay reads beyond 30, unchanged issuance and
replay denial, successful revocation after issuance exhaustion, hard observation
capacity, authentication before reservation, and separate login capacity.
Database tests cover the worker/queue caps, a short burst, canceled waiters and
expired requests never executing. The original two-node traffic, revocation,
quota and physical socket assertions remain required on both platforms.
