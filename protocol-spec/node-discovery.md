# Signed native relay endpoint discovery

Discovery uses the existing pinned permit issuer with the separate
`NestLink/v15/node-discovery/v1` signing domain. It never bootstraps a trust anchor
from DNS, peer candidates, node self-description or unsigned health replies.

Administrators use `GET/PUT /api/v3/nodes/{id}/endpoints`. Schema 13 creates an
initially empty endpoint table. Updates compare `expected_revision` and increase
a persistent revision, including withdrawal with both endpoints absent. Current
administrator authentication and the audit entry share one transaction. Relay
locations cannot be assigned to nodes without the relay role. Restore preserves
operator configuration but rotates the security epoch and invalidates logins,
permits, node runtimes and outstanding reservations.

Approved locations are an HTTPS origin for WSS and/or a `quic://host:port` URI.
Credentials, path, query, fragment, whitespace, wildcard and multicast literals
are rejected. HTTP requires an explicitly approved literal loopback exception.
QUIC loopback also requires that exception. IPv4-mapped IPv6 uses canonical IP
classification; production resolved loopback addresses are rejected. Private-LAN
addresses are not implicitly added to the approval.

`POST /api/v3/remote/{id}/relay/discovery` requires current management login,
endpoint ownership, a signature with the current endpoint key, the full current
permit digest and a fresh SDK-generated 32-byte nonce. The controller also uses
the original request login. The action has its own `RELAY_DISCOVER` purpose;
relay connection/allocation signatures cannot substitute for it.

The protobuf response binds deployment, security epoch, account/device/key,
session, full permit digest, exact action-transcript digest and nonce. It lists
at most 16 sorted distinct live relay nodes: approved URLs, endpoint revision,
node key digest, current runtime ID/generation and node-specific expiry. It is
bounded to 64 KiB and five seconds, never beyond the existing permit/node lease.
Unregistered, withdrawn, revoked, expired, wrong-role or old-policy/epoch runtimes
are absent. Capacity snapshots can omit unavailable nodes but do not reserve
capacity or guarantee later admission. Discovery does not renew permits/node
leases, add allocation rows or refund old promises.

An endpoint joining a still-live allocation for the complete current session
binding may discover that allocation's node even at global/account/node capacity.
The existing promise must match the current control runtime, security,
connection, policy and quota revisions, node key/runtime and endpoint revision.
The descriptor's expiry is capped to the existing allocation. This avoids a
first-endpoint/last-slot race; additional UUIDs still undergo unchanged admission,
and closed, expired or obsolete reservations cannot make nodes reappear.

Native and WASM management SDKs verify signatures, exact requests and full
permits before exposing responses. They retain the original request-start
monotonic clock, configured issuer and login session. Delayed responses and reuse
never restart the five-second budget. Native route creation also checks wall
expiry and the specific node's original monotonic deadline.

Clients select a listed node and separately request a relay allocation. Before
DNS, `Sdk::discovered_node_routes` checks its signature against the pinned issuer,
node ID/key/runtime/configuration revision and full permit. Each returned route
performs one bounded DNS resolution, pins at most 32 unique literal addresses,
retains the original discovery deadline and bounds connection setup by it. Peer
candidates must match these locally verified routes. Outer WSS uses normal HTTPS
certificate verification; outer QUIC uses the allocated node key. Inner endpoint
proof, business authorization, current resource snapshots and quotas remain
mandatory.

Allocations bind `node_endpoint_revision` and only configured transports.
Revision zero supports explicitly approved local routes when no endpoint row has
ever been configured; it cannot match discovered nodes. Older schema 12 stored
JSON defaults this added field to zero. Updating endpoints removes old-revision
grants from the next signed resource snapshot, so guard/watchdog checks stop
forwarding. Renewal with the old UUID cannot adopt the new revision: a fresh
allocation is required and old capacity remains held until its promise expires.
Withdrawal denies new allocations and discovery entries.

Development tests cover endpoint/login possession, signing purposes/issuers,
tampering, full permit/nonce binding, URI/default deny bounds, audit rollback,
optimistic revisions, migration/snapshot preservation, capacity/runtime filters,
revision-bound transports and no capacity refund. Actual HTTP→SDK→WSS and outer
plus inner QUIC fixtures carry bidirectional synthetic video-channel frames and
observe two-second idle stop after withdrawal. Expired response/route reuse and
wrong revision/issuer fail before DNS or socket admission. Public Caddy TLS,
multi-node DNS, company/mobile networks, installed products, sustained capacity
and formal G0–G6/A01–A21 remain separate acceptance work. The SDK's single-node
bounded recovery is described in [native-recovery.md](native-recovery.md).
Installed clients, multi-node failover, TURN/edge/tunnels and signed close
receipts remain open.
