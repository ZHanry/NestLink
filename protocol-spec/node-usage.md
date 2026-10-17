# Independent node runtime and cumulative usage

Development contract for v15. This does not claim an implemented QUIC/TURN/edge
data service or installed-product acceptance.

Each `NodeControl::start` creates a new canonical, non-nil runtime UUID. The v2
node proof signs the protobuf `NodeProof` with its signature cleared, including
that runtime and the exact server challenge. Its domain is
`NestLink/v15/node-control-proof/v2\0`. Old proofs without runtime binding are
rejected. A control socket cannot change its runtime during renewal.

SQLite schema 11 persists the runtime UUID and increasing generation in each
node lease. Renewals retain the generation and increase the lease sequence.
Starting a new runtime retires the former one, without waiting for its renewal
interval. Supervisors recheck current runtime/sequence/policy every 250 ms with
a 700 ms database budget. Old sockets and their local capacity guards stop on
the resulting terminal control failure. Starting an expired runtime UUID is
rejected. Restart requires a fresh UUID.

One row per runtime preserves its counters and latest acknowledgement, also
serving as a replay tombstone. There are at most 4096 registered node IDs, 128
non-revoked nodes, 4096 runtime rows per node and 65536 runtime rows globally.
Reaching a limit rejects new runtimes; it never evicts old UUIDs to make them
reusable. A new node registration requires a distinct key. Counter/generation
or audit exhaustion rolls back the entire issuance transaction, including the
consumed challenge. Tombstones survive ordinary reopen and snapshots. Restoring
a snapshot clears current runtime pointers and rotates the security epoch;
generations resume from that snapshot, and epoch binding invalidates proofs,
leases and reports from the prior deployment state.

`POST /api/v3/nodes/{id}/report` takes `SignedNodeUsage`. The registered node key
signs its exact claim bytes under `NestLink/v15/node-usage-report/v1\0`. Reports
bind deployment, security epoch, node ID, runtime ID/generation, policy revision,
lease sequence, report sequence, sample time and cumulative opened connections,
closed connections and admitted bytes. The route ID must match the signed node
ID; management bearer tokens do not authorize reporting.

The control center verifies the signature and active runtime/epoch/policy lease
inside its database transaction. New reports require the exact current lease
sequence and the next report sequence starting at one. All stored values fit a
signed 64-bit integer; counters never decrease, closed cannot exceed opened,
and active connections cannot exceed the node limit. Samples cannot precede the
runtime or prior sample, or be more than 1000 ms ahead of acceptance. Acceptance
time cannot move backward. Cumulative bytes are bounded by the configured rate
times runtime duration plus one second of burst allowance. This is a consistency
check of the node's signed report, not independent proof of forwarding behavior.

Retrying the latest sequence with identical claim bytes returns its original
acknowledgement and acceptance time without changing counters. The lease may
have renewed, but the runtime, epoch and policy must remain current and live.
Different bytes at the same sequence, older or skipped sequences, old runtimes,
revoked nodes, changed policy and expired leases are rejected. Only the latest
report is retained for retry, keeping storage bounded.

`SignedNodeUsageAck` uses the node-policy issuer key and a separate
`NestLink/v15/node-usage-ack/v1\0` domain. It binds the original claim-byte SHA256,
sequence, runtime, deployment/epoch and original acceptance time. The node checks
all of these against its outstanding report. It cannot be used as a policy lease,
resource/session permit or authority to extend any deadline.

The node reports after each successful policy exchange. The initial report must
be acknowledged before capacity can be reserved. One retry reuses the exact
signed bytes, with 700 ms per attempt and a 32768-byte response budget. Requests
stay in the same bounded control future, so lease checks and cancellation remain
active. Unavailable/invalid acknowledgements terminate node authorization. Dropping control publishes stop synchronously, even before its task is first polled.
An open but stalled control socket still expires at the original monotonic lease
deadline; metering acknowledgements do not reset that budget.

All roles in a process share one capacity meter. `reserve_capacity` checks live
policy and total active connections and returns a non-cloneable RAII reservation.
Every admission rechecks the live gate and shared token bucket, with one second
of burst and monotonic refill. Only a successful bounded synchronous enqueue
increments admitted bytes. Rejected queues and oversized/rate-limited admissions
do not count. Dropping a reservation increments closed once and releases local
capacity. Data services must also enforce separate resource/session permits and
observe the independent stop notification; a node lease or capacity reservation
alone grants no business resource.

`GET /api/v3/nodes/{id}/usage` and `Sdk::node_usage` are administrator-only queries.
The cursor binds the current security epoch, starts after a runtime generation,
and returns 1–100 rows plus a continuation indication. Each row retains its own
epoch and timestamps. `current` means the runtime still has the current policy
lease and registration; counters may include connections stopped since the last
acknowledged report. Closing or revoking a runtime does not invent final counts.

These are cumulative admissions reported by a registered node, not delivered
bytes, billing measurements or independent packet capture. Reports do not grant,
reserve or release resources in the control center. Cross-node/account/device/
resource limits, independent relay/edge data services and sustained capacity
acceptance remain separate work.
