# Combined control-role WSS relay quotas

The administrator API and native/WASM SDK expose `GET /relay/quota`,
`PUT /relay/quota` and `GET /relay/usage` under `/api/v3`. Storage verifies the
current administrator role, login state, access expiry and security epoch.
Membership or device ownership grants no access to these routes.

`RelayQuota { revision, limits }` is persistent configuration. Updating it
requires the expected revision and commits `relay_quota_changed` with the
management actor in the same transaction. Stale revisions, invalid limits or
an audit failure change neither the configuration nor audit counter.

| Limit | Default | Allowed range and meaning |
| --- | --- | --- |
| `max_allocations` | 128 | 0–128 concurrently present session pairs, including pairs waiting for a peer |
| `max_account_endpoints` | 16 | 0–256 reserved endpoint slots for one account; both endpoints count when their account is the same, including a peer still waiting to join |
| `bytes_per_second` | 16 MiB | 1–1 GiB admitted opaque bytes in both directions combined per allocation, within its one-second monotonic fixed window |
| `bytes_per_allocation` | 1 GiB | 1–1 TiB admitted opaque bytes in both directions combined over one allocation's lifetime |

Zero capacity explicitly prevents new relay admission. The allocation safety
ceiling keeps the current eight-by-64-KiB per-direction queue budget bounded;
raising it requires a separately verified memory/capacity implementation.
Byte limits include the inner TLS record overhead. Quota configuration is
separate from the policy and signed remote permit: forwarding still requires
an allowed relay path, active login, device-key proof and current session lease.

Schema 10 seeds the previous fixed defaults without granting forwarding
permission. Database reopen, snapshot and offline restore retain configuration.
Restore still changes the security epoch and invalidates prior authorization.

## Runtime changes and stopping

AppState loads persistent configuration at startup. Each authenticated relay
registration carries the quota revision read during its device proof. One hub
mutex applies revisions, checks capacity and installs the endpoint atomically.
A delayed registration cannot lower the current revision; a same-revision
configuration with different values is rejected.

A successful revision update stops every existing pair, including peers still
waiting to connect. A separate stop watch accompanies each endpoint, so a full
payload queue cannot hide the stop notification. The serving future polls this
watch before its reader/writer and owns their cancellation. Old registration
cleanup matches its random connection ID; it cannot remove a replacement
allocation that happens to use the same session ID.

Each connection's existing 250-ms authorization supervisor also reads the
persistent quota revision with its current permit. Thus a cancelled management
request cannot indefinitely leave an old allocation running after the database
commit. The same 700-ms database budget and independent permit deadline apply.
Registration and usage reads also synchronize the latest committed revision.

Admission and byte counters share the hub mutex. Both directions consume the
same rate and lifetime budget. A rejected payload is not charged. An admitted
payload is charged before enqueue and is not refunded if enqueue, socket write
or its future later fails. Resetting a rate window never resets lifetime usage.

## Meter snapshot

`RelayUsage` contains a random `runtime_id`, monotonically advancing
`report_sequence`, quota revision, current allocation/endpoint counts,
cumulative `admitted_bytes` and cumulative `closed_allocations`. Reads do not
advance the report sequence or charge bytes. Quota changes and allocation
cleanup preserve byte totals; stale drops do not release capacity twice.
Failed metadata-counter arithmetic rejects the operation instead of wrapping.

These are admission counters for the combined control process, not receipts
proving peer delivery. A server restart uses a new runtime ID and new counters;
consumers must distinguish it from an older report. Durable node metering and
shared control-side allocation/account-slot reservations are implemented in
[node-usage.md](node-usage.md) and [relay-allocations.md](relay-allocations.md).
Independent data services, device/resource aggregate budgets, QUIC/TURN/edge
limits and installed management UI are outstanding work. These counters
must not be used to claim persistent accounting or capacity acceptance.

## Development verification

Fixtures cover current role/access enforcement, revision and range failures,
audit rollback, SQLite reopen/snapshot, schema migration, capacity and combined
direction limits, rate-window reset without lifetime refund, report stability,
replacement cleanup and stop notification with a saturated payload queue.
A real HTTP SDK fixture establishes both native endpoints over WSS inner TLS,
transfers authorized data, sets zero relay capacity, observes both live peers
stop and rejects a fresh relay allocation. Fixed-artifact load/capacity,
independent node meters and full product acceptance remain open.
