# Advisory relay attributes

Administrators read and replace `GET/PUT /api/v3/nodes/{id}/relay-attributes`.
These independent management objects do not change `NodeRegistration`, node
discovery protobuf, network grant canonical bytes, identity, roles, capacity,
leases or any existing forwarding reservation.

`NodeRelayAttributes` contains `region: Option<String>` and
`cost_weight: Option<u32>`. Region is 1–32 lowercase ASCII letters, digits or
hyphens. Cost weight is 0–1,000,000. Both accept null for unknown. Zero is an
explicitly declared weight; unknown must not be interpreted as free. The weight
is an operator-declared relative selection hint, not a price, charge, monetary
unit, spending ceiling or forwarding permission.

Readback returns `{ node_id, revision, attributes }`. Schema 32 stores these
facts separately from `data_nodes`; an existing relay without a row reads as
revision zero with both values unknown. PUT accepts
`{ expected_revision, attributes }`, checks the exact independent revision and
increments it once, including when explicitly clearing both fields to unknown.
There is no delete/reset-to-zero operation. Stale writes return Conflict.

Each operation rechecks a live deployment administrator session, active account
and an existing non-revoked node with the NodeRelay role in an immediate SQLite
transaction. A write and its management audit event commit together. The first
write requires expected revision zero; subsequent revisions survive restart.
Missing nodes, revoked nodes and edge-only nodes cannot be configured. Unknown
request fields and out-of-range values are rejected.

The Web node detail panel reads and edits these values through the SDK. Save is
disabled until current readback, and a conflict or failed request requires a
fresh read before another save. Selection and login changes dispose or invalidate
outstanding UI operations. The server remains authoritative for every request.

Authenticated consumers request `POST /api/v3/remote/{id}/relay/candidates`
with the existing `NodeDiscoveryRequest`. The additive response contains the
unchanged signed `discovery` and `attributes`, one view for each node in that
signed list and in the same node-ID order. The server reuses the existing
authenticated discovery owner and signer, then reads metadata only for the
identities in that result. This does not grant consumers administrator access
to node metadata or expose nodes outside their signed discovery.

The SDK retains the signed list privately. `NodeRelayCandidates::checked`
returns detached copies sorted by known ascending cost weight, unknown last,
then node ID. `Some(0)` remains an explicit known weight. Region is available
as an operator hint; it is not interpreted as a measured distance. The SDK
rejects missing, extra, duplicate, out-of-order or invalid attribute views.
Changing a returned copy cannot change the private signed descriptor used by
`select`. Each checked read or explicit selection rechecks the current origin,
issuer, login session, deployment, security epoch, installation identity, full
permit and original request nonce. It retains the original request clock and
five-second discovery budget, including any shorter individual node deadline.

For compatibility, only a 404 with `ProtocolMismatch` from the new endpoint
permits the old discovery endpoint. That fallback reuses the original request,
nonce and clock and assigns unknown attributes. Authentication errors,
malformed responses, invalid signatures and other errors do not use fallback.

Native automatic discovery initially prefers the checked cost order. Refresh
keeps the existing authenticated peer relay marker preference, then a still
present previous node, then the checked cost order. The SDK's explicit selection
API and native path both use the original node-bound relay allocation and route
owners. They recheck the selected signed identity before and after reservation;
the existing allocation, DNS, endpoint revision and deadline checks still govern
route construction. Advisory updates do not create, renew, revoke or transfer
forwarding rights and do not restart any request or allocation budget.

Measured ranking, user-facing explicit native selection, multi-relay failover
and hard cost constraints remain separate W11/W13 work. The browser WebRTC path
continues to use its existing TURN owner. This slice does not claim two
independent Linux targets or complete AC17 acceptance. Source regressions cover
real SQLite migration, restart, CAS, authorization, unchanged registration and
node lease, failed-audit rollback, identical old/new discovery claims, candidate
identity and freshness negatives, restricted compatibility fallback, real
SDK/HTTP handling and real relay business frames. Passing evidence requires the
exact-source GitHub Actions run under R02; none ran locally.
