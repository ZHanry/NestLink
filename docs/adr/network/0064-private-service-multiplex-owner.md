# ADR 0064: Explicit private service streams under one original owner

Status: implemented; awaiting exact-source GitHub-hosted validation.

The original private-access POST rate gate permits thirty grant requests per
consumer login per minute. A test that requests fifty independent grants under
that login cannot establish fifty simultaneous private application flows in
the original lease interval. The failed independent-grant experiment remains
valid evidence of that limit. Changing the rate, creating extra logins,
refreshing business leases or suppressing the failed assertion would change
the question being tested.

The existing installation-pinned Quinn carrier already supports multiple
bidirectional streams. The existing PrivateServicePublication, LocalTargetOwner,
ServiceFlowPermit and ServiceUsageStore already enforce a finite connection
count, one cumulative application allowance, replay protection, exact target
approval and original deadlines. Reusing these owners gives an explicit
TCP/HTTP(S) mode for multiple independently authenticated application flows
under one original private lease. No new grant, forwarding implementation,
meter, local target or transport scheduler is created per stream.

## Negotiation and compatibility

Existing connect_private_service and its relay-policy variant retain their
single application stream behavior. Their Hello contains exactly the original
service_id and grant_id fields; absent optional version/mode fields are omitted
from serialization. An explicitly selected
Sdk::connect_private_service_multiplexed (or its relay-policy variant) retains
the same original SDK in the returned owner. It sends version 1 and mode
`multiplex-control`, verifies the original nonce/Open/Ready signatures and then
requires a version/mode acknowledgement. The control stream forwards no backend
bytes and reserves no application connection. The original local consent must
still accept the immutable lease before its durable owner can activate.

An old host's deny_unknown_fields Hello refuses the new version/mode fields.
There is no automatic fallback that could expose a control stream as an
application stream. Partial, unsupported or application-stream negotiation on
the initial stream is refused. UDP explicitly refuses multiplex and retains
the existing signed control and datagram entry.

PrivateServiceConnection::is_multiplexed exposes the selected behavior.
stream() and the internal take_stream() refuse the multiplex control stream.
open_stream(&DeviceIdentity) returns an original BiStream only in explicit
multiplex mode. Applications own the returned stream workers and must finish
or drop all of them before awaiting the carrier's physical close receipt,
matching the existing take_stream ownership contract.

## Per-stream authority and original limits

Each application bi stream sends the exact original service/grant IDs, version
1 and mode `multiplex-stream`. Both endpoints recheck original current
management authority before and after its fresh challenge/signature exchange.
The verified private lease digest and immutable signed lease/network bundle
fingerprint must match the owner's originals. GET readbacks do not issue grants
or call the private-access POST rate gate. Delegation observation refresh does
not change the original business or network bytes included in that fingerprint.

The host creates a fresh nonce for each stream and verifies the original
consumer PrivateServiceOpen. It then calls the same publication.prepare with
the same LocalTargetOwner before signing the original PrivateServiceReady.
That call retains the original used-opens replay cache and reserve_private
capacity, cumulative bytes, deadline and durable reservation checks. HTTPS
uses the same locally selected TLS adapter and certificate/name verification.
Forwarding uses the original PreparedPrivateLocalTunnel methods and original
bidirectional half-close and charging implementation.

Both endpoints admit at most eight simultaneous handshakes, each bounded by
the original three-second handshake timeout. Excess attempts are refused;
there is no unbounded queue. The host additionally bounds all live/pending
workers by the original effective maximum_connections plus eight. The original
Quinn limit remains 128 application streams plus the control stream. A caller
can establish its finite set in batches of at most eight, keep those streams
live and run application work concurrently without enlarging any lease or
resource allowance. Reaching the original maxconn limit refuses the next
application stream while existing admitted streams retain their owners.

## Cancellation, durable accounting and retained failures

Control EOF/error/unexpected data, carrier close, host stop, original fixed
lease deadline or a currentness/report monitor failure ends this owner. It
revokes the same publication and target, signals every pending/active worker,
closes the original carrier and joins every worker. Pending handshakes and
normal FIN acknowledgement waits also observe that stop signal. Only after
all actual original flow permits and backend sockets have dropped can the
original publication produce its drain token. ServiceUsageStore confirms that
token and the original signed report/ack path seals actual admitted bytes.
No aborted task or synthetic receipt stands in for drain completion.

Original durable-owner activation errors are retained. Replaying a lease on a
second carrier cannot acquire another report owner or replace the first. As
on the legacy path, the host records that worker failure and returns it after
joining workers and physically releasing its listener. Ordinary unauthenticated
stream or capacity refusals do not discard admitted sibling flows.

## Alternatives and validation boundary

Keeping one lease per application flow is the compatible existing API and
remains appropriate when independent grants are required, with its original
POST rate and reservation limits. Raising that gate or distributing requests
across extra logins would alter authorization rather than solve transport
reuse. Sharing a new private counter or reconstructing LocalTargetOwner per
stream would bypass original shared accounting/replay state and is rejected.
An arbitrary unversioned extra bi stream would silently change compatibility;
the explicit negotiated mode avoids that ambiguity.

The independent private_services/multiplex.rs integration module uses the
original management Store/router, target consent, installation identities,
Quinn transport and usage ledger. It covers four original admitted flows and
fifth-flow refusal, two real concurrent HTTP handlers, exact application byte
charges, ACL revocation with actual backend EOF, control FIN, a captured-proof
replay, a second durable-owner refusal and connection Drop, plus the unchanged
UDP entry after explicit mode refusal. The negotiation unit test preserves the
exact legacy Hello bytes and old deny_unknown_fields refusal. All builds,
formatting and tests run only on GitHub-hosted Actions. These source additions
do not establish fifty-flow capacity, the separate Luanti timing requirement,
target qualification or release readiness until their own evidence passes.
