# Current node observation bootstrap and production QUIC probes

Status: implemented in source; exact-source Actions and target qualification pending.

The existing TopologyReporter accepted caller-owned observations, but no running
relay produced them. A separate arbitrary peer directory or a new UDP socket
would duplicate trust and resource ownership. Instead the current policy-signed,
exact-query NodeResourceSnapshot delegates observation-only metadata: the exact
local publisher and RouteExport envelopes, its authority key, endpoint revision,
and fixed neighbors whose current publishers mutually allow each other.

NodeControl independently authenticates these bytes and the local incarnation,
checks bounds and original publisher expiration, and retains a monotonic deadline
across refreshed snapshots, omission and resource stop. The current snapshot and
NodeGate remain mandatory. Publication metadata never creates an allocation,
relay Pair, TransitGrant, business permission or prefix forwarding owner.

The production relay reuses its existing Quinn listener/socket, mutual node TLS
certificate validation and shared selector permits. The new topology ALPN only
exchanges bounded nonce probes on an authenticated control stream. It checks the
current space, both publisher digests and both endpoint revisions. Revocation,
metadata changes, expiration, extra streams or datagrams stop the observation
connection. Same-neighbor connections are reused across spaces; no independent
application forwarding path is introduced.

One owner keeps at most sixteen active physical neighbors. Each connection
pipelines at most sixty-four space probes. Successful measurement schedules its
next attempt relative to the original start, avoiding artificial down reports
when a valid probe takes longer than the reporting interval. Failures back off
at one, two, four and eight seconds. Unsampled or expired observations remain
down. Reports start every 500ms, retain the original 1000ms report TTL and 700ms
HTTP bound, and allow at most two in flight per space, 128 globally. The existing
NodeControl sequence owner rejects stale acknowledgements. All owned probe and
report tasks are aborted and joined during shutdown before cleanup succeeds.

ADR 0022 separates continuously refreshed liveness evidence from immutable
transit authority. Creation still binds the exact initial two advertisements;
subsequent authenticated observations advance durable continuity fences without
re-signing or extending any grant. Down, expiry gaps and publisher replacement
permanently retire the original chain. Original capacity promises are retained.

The Web space panel exposes current relay/publisher/export setup, explicit
revocation, canonical CIDR validation and a separately verified topology query.
Saved authority and observed runtime health are different displayed states.
Management SDK methods are shared with WASM; native network paths retain their
existing module aliases.

Registered-chain source tests now start the production observer and obtain
nonce-bound signed topology snapshots, instead of signing fixture observations.
They exercise both endpoint orders, approved OS file reads, revocation, neighbor
loss and physical socket release. The Store bootstrap and continuity regressions
also use real signatures and durable transactions. Execution is pending Actions;
this ADR does not qualify AC18/AC19 or announce release readiness.

Local exported-prefix reachability, raw-IP ACL/anti-spoofing, TUN/LAN forwarding,
broader routing selection and later mandatory work packages remain required.
