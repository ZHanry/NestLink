# Explicit local host-prefix reachability observations

Status: implemented in source; exact-source hosted Actions validation pending.

The current NodeResourceSnapshot already authenticates the exact topology
publisher, RouteExport envelopes, local endpoint revision and node incarnation.
Those publication rights cannot establish that a locally selected destination
is reachable, and a successful TCP connection cannot establish reachability of
all addresses in a subnet. The former reporter therefore emitted no prefixes.

Two alternatives were considered. Publishing every authorized export would
confuse authority with observed state. A generic subnet scanner or new raw-IP
forwarder would add unrelated networking mechanisms and would still need an
independent NetworkAccess authority. The selected first adapter measures one
exact, explicitly approved host and TCP port, using the existing mature Tokio
socket, task, watch, timeout and semaphore implementations (component C02).
No dependency, packet parser, TCP implementation or topology wire format is
introduced. Product code supplies only the local choice and its authorization,
freshness, continuity and cleanup policy.

LocalPrefixChoice is deliberately neither deserializable nor cloneable. A local
product owner explicitly constructs it from an IP prefix and SocketAddr. Only
an exact /32 or /128 matching that address, with a nonzero port, is accepted.
Existing canonical-prefix/default/loopback/multicast rejection still applies;
IPv4-mapped IPv6 addresses are additionally rejected. There is no hostname
lookup, subnet scan or remote choice of a probe target. The authenticated
publisher must allow that exact host prefix under its exact signed RouteExport
proofs. A /24 export does not automatically permit publishing a /32 under the
existing protocol's exact-prefix contract.

LocalPrefixOwner binds the original control object, deployment, node key,
runtime incarnation, security and policy revisions, publisher, exports and
endpoint revision. It retains the original publisher monotonic deadline and
the initial node-lease deadline and signed wall expiry. The sole existing
resource owner remains responsible for current signature verification and
snapshot validity. Refreshed snapshots and renewed leases cannot extend this
local choice. Omission, replacement, stop, expiry or explicit local revocation
invalidates its evidence; an observed terminal withdrawal cannot be revived
from a detached envelope. An unrelated caller cannot revoke another owner's
measurement merely by presenting the wrong control object.

One owned task attempts a real zero-payload TCP connection every 500ms, with a
700ms attempt budget. It drops a successfully connected stream immediately.
The original attempt start bounds freshness to 1000ms under both wall and
monotonic clocks, independently capped by the original authority and lease.
The next attempt is scheduled relative to its start. Failed or expired
measurements withdraw the prefix and advance a continuity fence. Recovery may
create new evidence, but cannot validate an acknowledgement for evidence from
before the withdrawal. A 25ms supervisor rechecks the original current owner
while connect and interval waits are pending. A process-wide Tokio semaphore
allows at most 32 physical probe tasks; the actual task future retains its
permit until it finishes or is physically destroyed after cancellation.

TopologyReporter::publish_authority_with_prefixes is a thin entry point into
the original reporter, not a second publication engine. Only private
owner-produced evidence can supply prefixes. Duplicate or excess owners are
rejected; report expiry is capped by the original evidence, publisher and
lease. The same runtime sequence owner, node signature, bounded HTTP request
and exact signed acknowledgement check remain in force. Current authority and
the original evidence are checked before sending and after receiving an
acknowledgement. The existing no-prefix entry point remains suitable for
publishing withdrawal while a local target is unavailable.

Explicit close revokes immediately and aborts and joins the original physical
task within its first deadline, capped at five seconds. Cancellation of close
retains the task handle and deadline. A retry cannot refresh the budget, and
late release or task failure cannot later turn into a successful cleanup
receipt. Drop requests abort and withdraws evidence without claiming that an
asynchronous join occurred.

Source regressions use real nonloopback hosted-runner TCP listeners and actual
HTTP requests with real node/authority signatures. They cover zero payload,
signed prefix publication and sequence continuity, duplicate observations,
revocation during HTTP, forged and unrelated authority, absent exact export,
endpoint replacement, omission and attempted revival, actual TCP failure and
recovery, original expiry despite lease renewal, and cancellation-safe join.
The resource fixture enters through the original Resources acceptance and
topology verification code; it does not manufacture reachability evidence.
No local compilation, formatting or test execution qualifies these assertions.
Actions execution and target evidence must be recorded separately.

This slice supplies host reachability observations only. The production relay
receives explicit protected local choices through `relay --local-prefixes`.
The private file pins deployment, node, space and the exact publisher grant.
Each choice starts at most once and the original report owner joins all probe
owners under one cleanup deadline. An empty local choice keeps prefix
publication disabled. See `docs/network-rewrite/HOST-PREFIX-OPERATIONS.md`.
NetworkAccess issuance,
current delegation, raw-IP ACL and anti-spoofing, TUN/LAN forwarding, subnet
overlap, gateway failover and full AC18/AC19 qualification remain separate
required work. Neither RouteExport nor TCP reachability authorizes forwarding.
