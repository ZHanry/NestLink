# ADR 0034: Private service business authority and shared reservations

Status: accepted for implementation; no validation claim.

Private services use the existing endpoint-pinned inner Quinn/routed transport,
fixed local target, service lease and bounded flow/UDP owners. They do not borrow
a remote-desktop permit or terminate private application plaintext at a relay.
SOCKS protocol support belongs to W21 and does not require a new parser here.

An exposure policy is independently versioned against the approved registry
revision and target digest. Legacy records default to public only. A private
consumer ACL binds one space, the approved service revision/target, an account
or installation and the current host/member epochs. Membership alone grants no
service access. Changing exposure/ACL invalidates dependent private leases;
changing the target continues to invalidate the original local consent.

A private service grant wraps the existing signed ServiceLease and adds an
independently signed consumer/host/space/ACL binding. Its business digest covers
the complete wrapper, including the shared usage-grant digest. Connectivity,
PathGrant and TransitGrant must all use PrivateService and that exact digest.
No unchecked route constructor or additional scheduler is introduced. A private
lease's legacy edge fields name its fixed private responder and accounting node;
the wrapper identifies the installation responder explicitly. Public ingress
owners must reject these leases. Endpoint proof authenticates both installation
keys before any local target is connected.

Private and public reservations are rows in the existing service_usage_grants
table and consume the same account/device/node/resource service_quota_ledgers.
The exposure policy partitions the service's existing maximum_bytes; its public
and private sublimits cannot exceed that original total. Reservations are made
under one immediate transaction. Mode changes, revocation, expiry or a lost
report do not refund an unresolved promise. Neither mode has a second balance.

An empty legacy edge_node_id explicitly selects a private-only installation
host. Schema 40 stores that absence as SQL NULL and preserves existing signed
definition bytes. Its node accounting key is the host installation ID in the
same node ledger; no synthetic data node or second allowance is registered.
Only this private-only target consent may be approved with public ingress
disabled. A public or both exposure still requires a real registered edge and
the existing public publication policy. The nullable FK migration checks all
foreign keys before committing and restores FK enforcement on every result.

Each private reservation has exactly one installation-host report owner, bound
to its device key, runtime and current security/member epochs. Device-signed
monotonic reports are checked against that binding and the original grant before
charging the four existing ledgers. A terminal seal requires final zero active
flows and the owner's final report. Old runtimes cannot acquire a replacement
owner or recover an outstanding allowance. Existing node-report endpoints must
reject grants owned by an installation. Snapshot reconciliation remains fenced.

The SDK retains the original local target consent. A remote response can never
select or re-resolve that target. Stop/cancellation must retain task/socket
receipts until join and physical release. HTTP/TCP use existing half-close
forwarding; UDP uses the existing native datagram codec, bounds and replay window.

Alternatives considered: an authenticated edge gateway could reuse most public
attachment code, but would expose private plaintext at that gateway and would
require removing its automatic public listener. It is not the selected final
architecture. A second private quota store would make implementation simpler but
would duplicate cumulative allowance and cannot satisfy the shared-budget rule.

Validation must run on GitHub-hosted Actions: actual HTTP/TCP/UDP bytes, exact
consumer and target denial, public/private isolation, shared cumulative budget,
monotonic reports, stop/revoke and physical socket release. Target protocols and
real-device evidence remain separate from automated laboratory evidence.

The current direct-carrier slice now issues two exact installation Membership
grants, a ConnectivityGrant and a PathGrant with `Purpose::PrivateService`.
The independent network signer is pinned in the delegated service business
signature. Its immutable grant set is stored on the original reservation in
schema 41; retrying the original request returns those exact bytes. Both native
consumer and host verify that complete typed chain during their authenticated
current-management readback before proving service access or opening the fixed
backend. Membership epochs, device keys, business digest, authority, space,
policy epoch and lifetime must all agree. A remote-control grant cannot pass
this admission path.

Direct admission intersects global policy, both accounts, both installation
limits, the service resource, host resource and consumer login. The captured
consumer login remains current in host readback checks; sign-out cannot keep a
previously signed private lease alive through the host's separate login. This
slice refuses relay-only policy before reserving bytes. A private TransitGrant
binding is available in the common routed authorization owner, but private
relay/multi-hop orchestration and its actual business traffic remain required
follow-up work. They are not established by a direct Quinn test.

Host presence and withdrawal use the existing ten-second service lease bound;
refresh never extends a private business lease or refunds its original promise.
The standard W21 SOCKS integration uses this exact SDK path, and tests actual
request/response half-close, authentication/target denial, listener collision,
an accepted stalled authentication worker, expiration and physical cleanup.
