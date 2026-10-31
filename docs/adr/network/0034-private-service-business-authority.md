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
