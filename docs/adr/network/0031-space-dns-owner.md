# Current-session owner for constrained private DNS

Status: source implementation; lock refresh, formatter, compilation and tests
must execute on GitHub-hosted Actions before this slice is verified.

This W19/AC32 slice serves the address directory from ADR 0029 through a real
native SDK owner and an operator CLI. It does not complete W19 or introduce an
IP/route permission. The current delivery deliberately exposes only active
records belonging to the signed-in account. Cross-account private-name access,
including names visible to a space administrator through management HTTP,
remains outside this resolver slice and must receive its own explicit access
policy before it can be enabled.

## Component comparison and boundary

The existing `webrtc-mdns 0.10.0` implements ICE's multicast `.local` behavior;
reusing it here would conflate managed private DNS with link discovery and risk
capturing unrelated names. `hickory-resolver 0.26.3` provides DNS client and
recursive/stub resolution; the required owner is an authoritative responder for
one already-authorized directory and has no upstream resolver. The selected
`hickory-server =0.26.3`, with default features disabled and no resolver/recursor
features, supplies the maintained parser, response encoder, ordinary UDP/TCP
server and task shutdown. NestLink adds only its current-session policy and
lifecycle. No DNS packet parser, DNS transport implementation, recursive
resolver or arbitrary forwarding path is written locally. `async-trait
=0.1.89` implements Hickory's handler trait; the existing `ipnet =2.12.2`
component validates directory pools. The new dependency lock is resolved only
by Actions under R02.

The upstream API/source comparison used the immutable `v0.26.3` tag, particularly:

- [server manifest](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/server/Cargo.toml)
- [server and socket task ownership](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/server/src/server/mod.rs)
- [handler request/response contract](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/server/src/server/request_handler.rs)
- [response builder](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/server/src/zone_handler/message_response.rs)
- [record construction](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/proto/src/rr/record.rs)
- [DNS client role](https://github.com/hickory-dns/hickory-dns/tree/v0.26.3/crates/resolver)

The pin is MIT OR Apache-2.0. C12 records the selected component and boundary.
The source was read for integration, not copied as an independent DNS server.

## Authority and failure behavior

`SpaceDns::start` takes the live `Arc<RwLock<Sdk>>`, one explicit space ID and
a loopback socket address. Its pin includes management origin, deployment and
issuer, security epoch, account ID, session ID, refresh generation, access
expiry, space authority key and the caller's space member epoch. Replacing the
SDK, logout, refresh/session rotation, expiry, loss of membership or a changed
authority terminates the owner. Selecting another space requires stopping the
old owner and starting a new one; no implicit space fallback exists.

Every accepted query fetches the actual authenticated management directory.
An independent 250 ms authorization monitor also fetches it while DNS is idle.
Each HTTP observation has a one-second total timeout. There is no response or
directory cache and no offline fallback. A directory must match the pinned
space/deployment/authority/member epoch, exact suffix and virtual pools, remain
unarchived, and advertise a zero cache age. Its original server observation can
be at most five seconds old, allowing at most one second of forward clock skew;
the local response deadline is derived from that original observation and
access expiry, not reset when the response is read. Directory revision may not
decrease. Slow, unavailable, unauthorized, stale, malformed or conflicting
authority responses close the service without reusing earlier records.

Administrators receive a wider directory than ordinary members. The resolver
filters it again to `account_id == current principal.account_id`, `active` and
`!revoked`, validates identity/address epochs, canonical public key, managed
labels, FQDN, usable pool membership and duplicate own-account names/devices/IPs,
and returns only that account's matching record. The shared SDK read guard is
held through response enqueue, so a completed account/session replacement
cannot race a response from the former session. Eight concurrent accepted
queries bound directory work; excess queries fail closed.

Only ordinary single-question `IN A` and `IN AAAA` requests for exactly one
label under `s-<space-id>.nestlink.internal` can read authority. Responses carry
TTL zero. Missing or hidden names return NXDOMAIN without a cached negative
SOA. Other suffixes/spaces, `.local`, nested names, ANY, AXFR, UPDATE and other
classes are refused; multiple questions receive FORMERR. No unrelated query is
forwarded. The local loopback DNS protocol authenticates no individual local
process; this limitation is why the owner does not widen the account's name
visibility or treat a DNS result as trust, NetworkAccess or service permission.

## User entry and resource owner

An installed normal-user executable can run:

```text
nestlink-daemon space-dns --state-dir <private-instance-directory> --space <space-id> --listen 127.0.0.1:5354
```

The command restores the existing opt-in, OS-protected `SessionStore`, never
accepting passwords/tokens in command arguments or printing them. It first
acquires the existing daemon singleton through `HeadlessRuntimeLease`, a thin
wrapper over the original `StateLease` and maintenance admission. Consequently
the ordinary daemon must be stopped before this standalone command starts;
two processes cannot rotate the same protected management session concurrently.
It publishes no unused IPC endpoint. A protected-store change, disabled
recovery, maintenance request, Ctrl-C, SDK/session expiry or authorization loss
stops the DNS owner. The command does not silently reopen a new account.

UDP and TCP bind the same explicit loopback port. Failure to bind either drops
both. Explicit shutdown cancels and joins Hickory's server within a bounded
deadline, aborting and joining on timeout. Dropping the owner cancels its task;
Hickory's nested task sets abort their UDP, TCP and active connection children.
Real socket tests require the port to be reusable and an idle TCP peer to close.

The command prints its bound address and private suffix. It does not install a
system DNS rule, change the user's ordinary resolver, install a route/TUN or
grant reachability. Windows/Linux split-DNS configuration/restoration and its
durable system-resource owner remain the parent's next W19 implementation,
with Windows DNS, other-VPN coexistence, crash/upgrade/uninstall cleanup and
AC31/AC32 target evidence still required.

## Evidence boundary

`crates/sdk/tests/space_dns.rs` uses the actual in-memory SQLite Store, product
HTTP middleware, signed SDK deployment connection, account login and device/
space enrollment before opening Hickory UDP/TCP sockets. It covers ordinary
member and administrator same-account filtering, A/AAAA and case handling,
unrelated/cross-space/.local refusal, multiple questions and zone transfer,
rename/revoke without stale answers, member removal, logout, SDK replacement,
refresh generation change, slow HTTP, forged/stale/duplicate/out-of-pool
directories, public bind rejection, Drop, idle TCP close and actual port rebind.
The local-IPC test checks mutual exclusion between the headless owner and real
daemon without a fake endpoint. These are source tests awaiting Actions, not
recorded passes and not host split-DNS/real-device evidence.
