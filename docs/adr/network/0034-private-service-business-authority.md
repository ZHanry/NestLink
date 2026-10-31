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
Presence refresh is capped by the original local target approval deadline. A
shorter valid approval can therefore start normally, and an independent monotonic
deadline retires all workers and the physical listener when that approval ends.
The standard W21 SOCKS integration uses this exact SDK path, and tests actual
request/response half-close, authentication/target denial, listener collision,
an accepted stalled authentication worker, expiration and physical cleanup.

The ordinary-user daemon now exposes that original host through
`private-service-proxy --state-dir <installation> host`. It reuses installation
startup admission, the single headless runtime lease, the existing installation
identity and protected management-session recovery. It cannot implicitly enroll
a device or start another login/refresh owner. The caller explicitly supplies
service/space IDs, a numeric fixed backend and its protocol, QUIC listen address,
reachable numeric advertised IP, private/both mode, finite private/public byte
shares and an approval lifetime of 1..3600 seconds. `--approve-target` is required
and confirms the local target and the current definition/exposure update. Help
and startup output explain that each invocation invalidates previous consumer
ACLs/leases and stops previous publications. The command never grants consumer
access; the existing Web private ACL panel can grant specific consumers while
the host runs. Both mode reserves the explicit public share but this command
starts the private listener; public ingress still uses its existing publication
owner and must be started separately after the exposure change.

The command creates `LocalServiceTargetConsent` from the current service and
that local numeric choice, obtains the existing signed target approval, updates
exposure with both original revision fences, then calls the existing SDK private
host. HTTPS requires an explicit local TLS server name and 1..8 local DER X.509
CA files, bounded at 16384 bytes each, through `HttpsBackendTls`; no certificate
or name check is disabled. Public-unicast relay endpoints remain the default.
The host command passes explicit repeated `--relay-private-prefix` choices and
`--allow-loopback-relay` into the SDK's existing local relay endpoint policy;
these choices do not select or authorize a backend target.

Termination, installation maintenance, changed/disabled protected login, original
login expiry, target-approval expiry or wall-clock regression stops this same
host. Setup retains its original resource-owning future after a stop request,
checks the same session between approval/exposure/start effects and joins any
host returned by an already in-progress start. Shutdown retains the original
handle through pending waits and requires its actual worker/listener cleanup
result before reporting success. The stable installation-private directory
`private-service-usage` retains the original cumulative usage database across
invocations and is never cleared as runtime cleanup. Hosted tests exercise the
production command function against the actual management router and local TCP
backend, explicit consumer ACL, byte exchange, session-change/backend EOF,
physical UDP listener release, approval expiry and retained usage state. These
are implementation/test sources awaiting Actions evidence, not a laboratory or
target verification claim.
