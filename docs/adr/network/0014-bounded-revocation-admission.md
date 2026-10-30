# Preserve a bounded worker for authority revocation

The exact c7d1ae1 Windows two-node test completed both routes and their business
transfers, then its authenticated node DELETE received CapacityExceeded after
212 ms. The handler and Store operation have no request-rate limiter. The
database admission's 200 ms waiting limit is the source of that 429. Ordinary
resource and usage polling can occupy every database worker during a burst.

Raising the worker, queue or wait budgets would hide that resource competition
and increase blocking threads or stale work. Instead the existing eight-worker
budget is partitioned into seven ordinary workers and one revocation worker.
The two lanes share the existing eight waiting slots and 200 ms wait deadline.
Normal polling and maintenance cannot consume the reserved worker. Revocation
still authenticates the real session and passes the original Store permission
checks before mutation. Anonymous, invalid-token and member requests do not
gain administrative authority by using this admission lane.

The reserved lane remains bounded: a saturated revocation lane returns 429;
expired or canceled waiting futures never enter spawn_blocking. Once a database
operation has entered the blocking worker it retains the original worker owner
and transaction semantics. This cannot bypass a Store operation already holding
the mutex, nor promise an arbitrary latency bound during continuous overload.

The node DELETE and new topology publisher revocation use this entry point.
Tests cover the full seven-plus-one worker ceiling, shared waiter ceiling,
cancellation/expiry, and actual TCP/HTTP revocation with the ordinary lane and
its queue occupied. The original two-node test is unchanged and must pass again
on Windows at the integrated source SHA. All tests execute in GitHub Actions.
