# ADR 0036: Authenticated local entry for one private service

Status: selected authenticated TCP/UDP implementation; hosted and device verification pending.
This decision does not close W21 or AC34.

The SDK reuses the private-service admission, exact approved target, shared
reservation and endpoint-authenticated carrier introduced by ADR 0034. The local
entry adds a standard SOCKS5 interface without making a local port into network
authority. A local user explicitly selects one Ready private service revision,
exposure, target digest, private alias, port, sub-reservation and bounded lifetime.
The choice is not deserializable. Each accepted application flow requests its own
existing private grant; it neither creates a second allowance nor retries an
application stream under a new grant.

R01 component review found no existing SOCKS protocol implementation in NestLink.
The selected component is official fast-socks5 1.0.0 (MIT, published 2026-01-20,
non-yanked at review), using its explicit typestate server API. Its crate checksum
is `9545787d8304a71e1bf1b711705070a4c400cce9b332c4a11800627b7c9a2067`.
The official crate, license and source provenance are retained under
`third-party/fast-socks5`; the repository's notice records the exact patch and
hashes. Source review found two debug statements exposing raw username/password
bytes and no RFC1929 authentication-version check. The minimal vendor patch
removes those two statements and rejects versions other than 1 in the component
parser. NestLink does not introduce a second parser, protocol framing or auth
negotiation implementation. Debug-level authentication tests must detect a
reintroduced plaintext or byte-array credential log.

SOCKS authentication, command parsing and success/error replies belong to the
component. The adapter accepts password authentication only, with independent
random username/password per owner. Credentials are serialized directly into a
zeroizing buffer and created exclusively beneath an existing OS-owner-private
directory. Windows requires the platform-security owner/SYSTEM protected DACL;
Unix requires owner-only directory/file permissions. The API returns a path,
not credentials in a URL, log or management response. Startup readback must match.
An incomplete or unreadable credential startup explicitly reports its retained
path for local-owner recovery. Credential strings passed to the adapter's check
are zeroized after comparison; this does not claim that all upstream temporary
allocation storage is zeroized.

Only loopback listeners are admitted. TCP/HTTP services accept TCP CONNECT to the
one chosen canonical `*.nestlink.internal` alias and exact port. UDP services
accept UDP ASSOCIATE with an explicit nonzero local UDP source endpoint whose
loopback IP equals the authenticated TCP peer IP. Unspecified IPs/ports, domains
as association sources, other source IPs, NoAuth, BIND, and a command for the wrong
service transport fail closed. Each UDP packet still must name the exact selected
alias and port; IP targets, other names and other ports fail closed. The adapter never calls
component DNS resolution, its generic TCP dial/proxy or UDP proxy. It obtains a
verified private lease, compares the complete chosen service/definition/target,
space and exposure revision, then invokes the existing private SDK connection.
Thus a SOCKS request cannot choose an internet destination or local backend.

There are at most 16 process owners, eight workers per owner and 32 process
workers, including workers still joining cleanup. Every flow shares one
three-second setup deadline across authentication, target selection, grant and
ready reply. An in-progress resource-owning private connect is retained after
that deadline or shutdown until its existing bounded operation completes, and
any returned connection is explicitly closed. No success reply follows the
deadline. Transfer reuses Tokio copy_bidirectional, preserving FIN/half-close;
an absolute owner lifetime, lease expiry, wall-clock regression and existing
private host authorization/meter stop the flow. There is no automatic renewal.

Shutdown drops the listener, signals all workers, waits for each private carrier
physical-close receipt, and only then compares and removes the original private
credential file. A changed file is preserved. A wait cancellation retains the
same join handle; Drop sends stop and hands that same task to the saved runtime
reaper. Pending or failed cleanup is distinct from Stopped. A private-connect
error is conservatively an unconfirmed cleanup result. The caller must retain
the owner and stop it when its local UI/daemon session ends; production lifecycle
wiring is a separate requirement, not implied by exposing the SDK method.

Each UDP association owns one separately bound loopback UDP relay socket and one
original private-service connection. Datagrams are parsed with fast-socks5
`parse_udp_request` and replies are framed with `new_udp_header`. Fragmented,
malformed, wrong-source and oversized packets are discarded, without truncation,
fragmentation, reassembly or a fallback transport. The payload maximum is the
existing `DatagramPacket::MAX_PAYLOAD` (1169 bytes); empty application datagrams
remain individual zero-length datagrams end to end. A 65536-byte receive buffer
detects oversized local packets instead of silently forwarding a truncated one.
Replies identify the one selected private alias, never the backend's address.

The declared UDP source endpoint is pinned for the association's entire lifetime;
there is no first-packet source selection or automatic rebinding. The authenticated
TCP control connection must stay open; EOF or unexpected control data closes its
UDP mapping. Each association shares the original service idle limit and chosen
byte sub-reservation across request and response payloads, while the private host
continues to enforce the authoritative grant and cumulative meter. A separate
8192-event lifetime work cap also counts empty and rejected datagrams, preventing
zero-byte traffic from evading bounded local work. Payload selection is fair
between local and private inputs, with stop/expiry checked first. Local response
sends have a 250ms ceiling within the original absolute owner/idle deadlines.
The same single authority monitor remains pinned throughout the association, so
loop iterations cannot reset expiry or wall-clock regression observation.

Clients must bind their UDP socket first, authenticate their TCP SOCKS control
connection, and send UDP ASSOCIATE naming that bound socket's exact local IP and
nonzero port. They then send mature-library-framed UDP packets to the relay
address in the success reply, targeting the chosen private alias and port.
fast-socks5's `Socks5Datagram` convenience constructor always requests `[::]:0`
and is deliberately incompatible with this source-pinning policy. Its mature
`Socks5Stream::use_stream` and `request(UDPAssociate, TargetAddr::Ip(bound_addr))`
APIs plus the mature UDP codec provide the explicit-source path. Product help
must describe this requirement rather than silently relaxing local admission.

Alternatives reviewed: socks5-server 0.10.1 is GPL-3.0-or-later and introduces a
different licensing cost. Windows TCP peer-PID lookup is not an atomic credential
boundary, and Linux TCP does not provide Unix-domain SO_PEERCRED semantics.
Owner-private named pipes or Unix sockets are useful for CLI stdio/ProxyCommand,
but cannot alone provide standard SOCKS support to ordinary database clients.
A one-shot unprotected TCP capability port cannot supply the necessary ordinary
client/authentication behavior. Raw unauthenticated local TCP mapping requires
a separate OS admission design; it is not enabled as a fallback here.

Under R02 all build, format, lint and test execution belongs to GitHub-hosted
Actions. Tests include the mature standard client, real private target bytes and
FIN, wrong password/NoAuth/name/port/IP/command denial, port collision, credential
replacement and cleanup, cancelled waits, and component debug-log confidentiality.
A test transport mutates a byte emitted by the mature client to check the
component's RFC1929 version fence; no authentication frame is hand-implemented.
Source availability is not an Actions pass. W21 still requires a reliable OS
admission design for raw loopback TCP/UDP mappings, complete product lifecycle
wiring, unified routed private service carriage and ordinary Windows-user
real-device L3 evidence. Current local-ipc is mutually pinned TLS on loopback,
using private-directory installation keys; it is not an existing named-pipe or
Unix-peer-credential server that can transparently admit ordinary raw clients.

Sources: https://github.com/dizda/fast-socks5/tree/v1.0.0,
https://crates.io/api/v1/crates/fast-socks5/1.0.0,
https://crates.io/api/v1/crates/socks5-server/0.10.1.
