# 0046 — Partitioned original service owners behind a source-preserving IPVS entry

Status: production first slice and dedicated hosted experiment candidate;
W26 remains in progress until exact-source execution and target evidence exist.

The old public service definition selects one edge, one namespace and one
publication. Issuing the complete original budget independently to a second
edge would double the account/device/resource promise. Replacing an original
target approval with a downloaded recipient list would also change its holder
boundary. A hostname with several DNS answers does not supply a fixed entry or
reliably stop sending new connections to an unhealthy edge.

The selected contract retains the approved definition and target digests. An
explicit service-specific edge group binds two to four sorted unique recipients,
their exact namespace revisions, distinct ingress IPs and finite allocations.
Each member's allocation is positive; checked aggregate connection, byte-rate
and cumulative-byte sums cannot exceed the original definition. Idle timeout
stays identical. Group issuance uses the existing atomic SQLite transaction and
original four-scope reservation primitive. It creates one exact original usage
grant per actual member rather than a new balance. Renewal retains those grants.
Unsealed promises are never donated to the surviving member or refilled when a
failed node obtains a new runtime.

The alternative was a deployment-wide edge cluster with a shared signing and
quota owner. It simplifies a homogeneous appliance but would require a new
distributed ownership/consensus mechanism and changes the current account,
target and budget authority. A service-specific immutable selection reuses the
current independent node control and publication owners and makes every
recipient visible to the original local target holder.

Grouped leases use a separate signing purpose. Optional absence retains the
legacy JSON and signature purpose. A v15 verifier therefore refuses a grouped
lease rather than silently applying its single-edge interpretation. Existing
node admission, target proof, QUIC identity, stream/datagram authorization,
durable usage reporting and terminal drain/seal remain the owners. Effective
limits and accounting-node helpers select only the signed member slice. The
legacy local target owner explicitly rejects any group; a non-deserializable
local group choice is required to create grouped native runtimes.

Fixed ingress uses mature Linux IPVS-NAT driven by keepalived. Ordinary nginx
stream proxying was considered: it replaces the visitor source IP on raw TCP
and UDP and therefore changes the existing source ACL contract. HTTP PROXY
headers do not solve all four protocols, and implementing another framing/parser
layer would expand the trusted data path. IPVS-NAT retains the actual visitor
source IP at each existing edge listener. Return routing must pass through the
director. HTTP/TLS terminates only at each original dedicated Caddy, with the
approved host and original source IP passed to the existing private adapter.

The first deployable mode is one explicitly prepared dedicated IPv4 director
and one service-specific group. It exports exact keepalived configuration and a
protected input snapshot. The installer refuses unrelated existing
keepalived/IPVS owners, does not flush a shared table, and requires the operator
to prepare the VIP, return routing, forwarding and destination-expiry settings.
There is no director HA/VRRP, IPv6 VIP, session-state replication or zero-loss
promise in this mode. Existing TCP/HTTP upgrades and UDP mappings may terminate;
qualification measures new application requests after an edge failure.

Each real-server check reaches a separate bounded HTTP endpoint on that exact
edge. Its URL binds group ID, revision and aggregate allocation digest. A 200
requires current original node/publication authority, an attached original host
carrier and actual ingress/Caddy route readiness. A still-running Caddy TCP
port cannot substitute for that authority. Axum parses HTTP; the health owner
limits 32 accepted sockets and two seconds per socket and joins on shutdown.
Keepalived starts members down until these checks succeed and removes failed
destinations. DNS-only failover is not used as fixed-entry evidence.

The group Caddy configuration is an explicit local operator selection. It
requires independently provisioned certificate/key files on each edge; randomly
routing HTTP-01 challenges would not prove ownership of every member. Its DNS
TXT proof binds deployment, group, group revision, service and allocation digest.
Each original readiness probe connects to that exact member ingress address,
using the approved hostname/SNI and normal certificate validation. A separate
fixed-entry experiment must prove that the director actually routes business
requests to both members. A single Caddy instance in this first mode selects
one service group; sharing 80/443 among independent group selections requires a
separately owned deployment design and is not claimed here.

An optional `https_root` is an absolute protected operator-local DER CA file
limited to 16 KiB. It supplements the normal HTTPS roots for group DNS/readiness
clients and preserves chain, validity and exact-name verification. It is absent
from the group management request and signed lease. A remote group cannot
select or disable local TLS trust. Caddy's operator-managed `load_files` is
compared exactly during reconciliation; route cleanup never removes those
independently provisioned certificate/key files.

The dedicated hosted candidate reuses the original management/SDK/node/QUIC
business paths. It creates separate visitor, IPVS director and two edge network
namespaces on a GitHub-hosted Ubuntu VM. The original exported configuration
drives real keepalived and kernel IPVS. It covers actual HTTP/HTTPS/TCP/UDP
requests, both real-server connection counters, the original source ACL, failed
owner health with Caddy still up, new-connection recovery within 30 seconds,
group revocation, new-runtime refusal, both Caddy route deletion/readback and
original cumulative scope settlement. The initial cooperative-stop experiment
can require valid original seals and zero outstanding bytes; a process-crash
experiment must instead retain any old unsealed promise. These are distinct
cases and cannot be exchanged in the evidence matrix.

R02 places syntax checks, formatting, dependency work, compilation and the
experiment itself in GitHub-hosted Actions. Its local HTTPS DoH and short-lived
operator CA are explicit L2 fixtures. They supply no public DNS/ACME, target
deployment, physical network or installed ordinary-user flow evidence. No pass
is claimed from checked-in fixtures or an older source revision.

Upstream configuration references read for the adapter were keepalived v2.2.8
`doc/man/man8/keepalived.8.in` and `doc/man/man5/keepalived.conf.5.in`:
`--check`, `--dont-fork`, `--config-test`, `--pid`, `--checkers_pid`,
`alpha`, `HTTP_GET`, `connect_port`, `retry` and `delay_before_retry`.
The adapter does not copy an upstream load balancer implementation or add an
HTTP, TLS, TCP or UDP parser.
