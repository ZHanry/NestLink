# ADR 0065: Bounded native management HTTP admission per original origin

Status: implemented; awaiting exact-source GitHub-hosted validation.

The original management server admits seven ordinary database workers and one
reserved revocation worker, with eight waiting slots and a 200 ms waiting budget.
The fifty-flow capacity execution on source a3d returned CapacityExceeded before
the original leases and application flows became ready. Its server diagnostics
recorded five database_capacity_exhausted events, including the first wave's
seventeenth request_private_service. That failed execution remains evidence of
the original admission boundary. Raising the server's limits or suppressing
the failed assertion would change the workload's safety and acceptance contract.

Independent native SDKs previously sent every management request immediately.
Private flow currentness monitors and routed control observers use the same
native request adapter, so separate SDK instances and independently constructed
reqwest clients can converge on the same management origin. Their HTTP
connection pools alone do not bound concurrent authenticated database work.

## Decision and reused components

Reuse Tokio's existing FIFO Semaphore and cancellation-safe owned permits at the
native request adapter. No dependency, scheduler task, response cache, mutation
retry, credential owner or database admission mechanism is added. All requests
to one canonical HTTP(S) origin share four ordinary active slots. DELETE uses
one separate active slot and cannot be consumed by ordinary calls. This leaves
the original server responsible for actual authentication, revocation ordering,
database worker admission and transactions.

Each lane has its own finite waiting semaphore: 256 ordinary waiters and 32
DELETE waiters. A full local waiting lane returns the existing
SdkError::Api(429, CapacityExceeded) before sending HTTP. A short standard mutex
protects a process-local registry and is released before any asynchronous wait.
The registry holds weak owners, sweeps expired entries on lookup, accepts at
most 256 live canonical origins and limits each canonical origin key to 512
bytes. A live entry is never evicted to admit a different origin. Excess live
origins return the same capacity error; invalid origins return Invalid.

The active permit retains an Arc to its exact admission owner. Retaining only
the semaphore permit would allow the weak registry entry to expire while a
request was still active, creating a second gate for the same origin. Waiting
futures likewise retain the original owner. When the last active or waiting
request ends, its weak entry becomes eligible for cleanup; idle SDK instances
and credentials do not keep registry entries alive.

The original native request entry remains the shared entry used by Sdk::call,
health/proof requests, routed control observers and private relay observers.
The SDK struct and its public API are unchanged. The WASM/browser adapter keeps
its existing browser cancellation and request behavior. The new bound is
native and process-local; it does not coordinate separate processes or promise
that all concurrent server clients can fit the original server capacity.

## Deadlines, cancellation and mutation semantics

The native adapter establishes one absolute fifteen-second deadline before
admission. Waiting, connection setup, response headers, the bounded response
body and JSON decoding share that original budget. The reqwest operation uses
only its remaining duration. Existing enclosing signed-handshake and reporter
deadlines can cancel earlier. All original response size limits, status/body
decoding, Origin/bearer headers and redirect policy remain in force.

Dropping a waiting or active future immediately drops its local permits.
Queued requests never reach reqwest after timeout or cancellation, and no
background task can emit them later. Dropping an active HTTP request releases
the local slot and cancels the client operation; it does not roll back a
mutation already received by the server. The server retains its original
transaction, cancellation and idempotency behavior. There are no automatic
POST retries, refreshed business grants, enlarged leases or hidden credentials.
Original 401 and 429 responses pass through unchanged. Reusing the existing
capacity error preserves the SDK refresh rule that transient pressure must
not clear the login's existing credentials.

## Alternatives and validation boundary

Increasing the original server workers, waiters or waiting deadline was rejected
because the measured workload must satisfy those unchanged limits. Retrying
failed mutations was rejected because a transport error can occur after the
server has committed, and a retry would introduce replay/idempotency behavior
outside this change. A separate limiter on every Sdk would miss independently
constructed clients. One global semaphore for every origin would let an
unrelated deployment block another and would consume revocation capacity with
ordinary polling. A permanently strong origin map would grow with every origin
ever contacted. Tokio's existing semaphores and a bounded weak registry cover
these local adaptation needs without a new general scheduling framework.

The independent HTTP tests create original Store/router/AppState deployments and
perform the actual Sdk::connect signed management identity exchange. Observation
handlers then measure twelve independent clients sharing four HTTP slots,
independent origins, a DELETE progressing under fully occupied ordinary work,
bounded ordinary and DELETE waiting, cancellation restoring exact slots,
fifteen-second waiting timeout with no late POST, known/chunked response size
limits and original 401/429 mutation responses received exactly once. A local
registry case covers canonical aliases, the 256-origin cap, weak cleanup and
retention of the exact live admission owner. These handlers observe transport
admission and do not replace authorization acceptance tests.

All builds, formatting, lint and tests run only on GitHub-hosted Actions. These
tests do not establish fifty-flow capacity, the independent Luanti timing
requirement, target qualification or release readiness. The original failed
capacity and Luanti evidence remain in their history; the unchanged real
workloads must be rerun and satisfy their original assertions on the final
source before those gaps can be closed.
