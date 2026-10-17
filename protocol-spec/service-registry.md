# Service registry and local target approval

This contract persists service configuration and an installation's independent
approval of a locally selected target. Responses also report the current
publication state from the separately authorized publication lifecycle.
Creating, updating, approving, or restoring a record opens no listener, creates
no target connection, and issues no data-plane capability. Changing or revoking
a published definition, or replacing its approved target, stops renewal of the
previous publication in the same transaction.

## Configuration

All seven routes use the existing management authentication, Origin/CSRF checks,
request-size limit, and database concurrency budget:

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/v3/services` | Account-scoped cursor page |
| POST | `/api/v3/services` | Revision 1 configuration |
| GET | `/api/v3/services/{id}` | Current configuration and approval state |
| PUT | `/api/v3/services/{id}` | Replace definition, increment revision |
| DELETE | `/api/v3/services/{id}` | Revoke permanently, increment revision |
| POST | `/api/v3/services/{id}/approval/challenge` | Independent target challenge |
| POST | `/api/v3/services/{id}/approval` | Verify local installation signature |

A service belongs to one account and records the management login that created
or most recently changed its definition. An administrator flag grants no access
to another account's services. The host must be an active permanent installation
of that account; an expiring browser endpoint cannot be an exit. The edge must
be an active registered node with the `NODE_EDGE` role. Registration does not
require the node to be online and is not an online-status assertion.

`requested_ingress` expresses an HTTP/HTTPS hostname or a TCP/UDP port request.
It is not a domain ownership claim or a port reservation. HTTP names must be
lowercase ASCII fully qualified names without wildcards, IP literals, ports,
URLs, or trailing dots. The management API rejects its own origin's hostname.
Domain ownership and ingress conflicts require separate enforcement before
actual publication.

Definitions are bounded to 16 KiB, names to 128 bytes, and source ACLs to 32
unique canonical CIDRs. An empty ACL denies every visitor; `0.0.0.0/0` and `::/0`
are explicit public choices for their respective address families. Limits are
1–128 connections, 1–1 GiB/s, 1 byte–1 TiB total, and 1–300 seconds idle timeout.
The service data plane enforces these limits independently of remote-control
session budgets; saving the configuration does not allocate them.

## Independent local approval

Storing a definition is allowed under the default deny policy. Both issuing a
target challenge and accepting a proof require `NetworkPolicy::may_publish()`.
This allows service approval under `allow` + `direct_only` + public ingress
enabled, without changing the peer path policy or reusing remote desktop consent.

A native caller must display the full definition and obtain a local choice
before constructing `LocalServiceTargetConsent`. The caller supplies a fixed
`SocketAddr` and a compatible target protocol. The helper does not resolve a
remote string and rejects port zero, unspecified, multicast, and the IPv4
limited broadcast address. It retains the chosen address locally and sends only
an opaque target ID and a digest to the management server. The type has no
deserialization implementation and is unavailable to the WASM approval API.
Its construction boundary is an API requirement; the SDK is not a local UI or
a daemon target registration implementation.

The target digest commits to a domain separator, service ID, pre-approval
revision, typed definition digest, target ID, protocol, and fixed address. The
installation proof uses `APPROVE_SERVICE_TARGET` and signs the typed challenge
and choice. The challenge binds deployment, security epoch, policy revision,
account, approving login, host installation, service ID/revision, definition
digest, nonce, and its issue/expiry interval. A challenge lasts at most 60
seconds; target consent lasts at most one hour from challenge issuance.

The creator login and approving login may be distinct current logins of the
same account. Both must remain active for approval to be reported as valid.
The server verifies the current host key, definition and endpoint registration,
policy revision, epoch, timestamps, and full stored signature whenever it reads
approval state. Logout, account disablement, device or node revocation, policy
change, definition change, expiry, or security-epoch change invalidates approval.

Successful approval advances revision **N to N+1**. The stored proof continues
to bind challenge revision N; the approved row binds current revision N+1. A
second challenge for N and a replay of the accepted proof therefore cannot
replace the approved target. The local target owner must retain the original
selection and its revision-N binding. Recomputing a target digest from the
approved revision-N+1 view produces a different digest and must not be used as
the original choice. Updating a live definition also increments the
revision, binds its creator login to the current caller, revokes the previous
approval, and removes outstanding challenges. Revoke leaves a permanent
tombstone. Repeating revoke with the same expected revision is idempotent.
Creating the identical initial revision with the same ID and creator login is
idempotent; creation never revives an updated or revoked record.

## Persistence, budgets, and recovery

Schema 18 adds `services`, `service_approval_challenges`, and
`service_target_approvals`. Existing configurations and original proof JSON are
included by SQLite's existing online snapshot mechanism. Restore invalidation
deletes challenges and revokes approvals while preserving definitions. A fresh
login must update a restored definition before seeking fresh approval because
the recorded creator login has been invalidated.

All configuration mutations, proof consumption, and their audit event commit
in one SQLite transaction. An audit failure rolls back the mutation and nonce
consumption together. A failed signature does not consume the challenge.

Budgets include revoked service history: 128 service records per account and
4096 globally. There are at most 16 unexpired challenges per account and 4096
globally; consumed and expired challenges are removed before allocation.
List pages contain at most 100 records, sorted by service UUID, and carry the
security epoch. The server also rate-limits authenticated create/challenge
requests by management login.

## Publication state and management stop

Publication authority and runtime ownership are specified in
`service-data-plane.md`. The registry status has three wire values:

| Value | Meaning |
| --- | --- |
| `not_published` | No unexpired publication promise is retained. |
| `published` | A current unexpired lease matches the current approved definition, installation, edge runtime, namespace, policy and control runtime. |
| `stopping` | A previous promise is still held after stop, invalidation, loss of authority or lease expiry. It must not be treated as authorization to renew. |

`published` reports control-plane authorization; it is not proof of a ready
public listener, DNS propagation, a certificate or successful visitor traffic.
Reads apply the same current binding checks as renewal, so a renewable database
row cannot hide a revoked login or obsolete definition until the next edge poll.
Management views use whole Unix seconds; a millisecond issuance or heartbeat
later within that same second is included in the check. `stopping` can accompany
an invalidated or revoked target approval and remains visible until the original
promise expires. It neither refunds the promise nor extends the lease.

Authenticated `DELETE /api/v3/services/{id}/publication` accepts
`ServicePublicationRequest { expected_revision }` and returns 204. The account
must own the service and the revision must match the current definition;
administrator status does not permit stopping another account's service.
Repeating stop with the same revision is safe. Stop preserves the definition
revision and local target approval, and atomically stops renewal with its audit
event. A stale revision returns a conflict without changing the publication.
Native and browser SDKs use this same management route. Definition and publication
mutations emit account-scoped `service_changed` events with the actual status.

An `approved_target` record must never by itself authorize dialing a target or
accepting public traffic. Only an owner of the actual local registration and a
current independently verified publication capability may do so.
