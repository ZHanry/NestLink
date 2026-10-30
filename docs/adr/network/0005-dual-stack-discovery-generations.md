# ADR 0005: socket-owned dual-stack discovery and original observation lifetimes

Status: implementation slice; exact-source Actions and target evidence pending.
Date: 2026-10-30, Asia/Shanghai. Scope: W08 / AC12 / F01 / F11 / F20.

## Reused owners and the production path

We compared a second candidate scheduler and independent UDP probes with retaining
the existing native endpoint, NetworkMonitor, route manager and DiscoverySocket.
We retain those owners. AppCore constructs the monitored dual-stack native
endpoint. IPv4 and IPv6 have separate real UDP sockets; each socket still carries
both STUN and Quinn traffic, and the existing family race chooses the actual
business connection. One monitor baseline is captured before endpoint creation.
Address, route, interface or suspend/resume changes invalidate both socket
generations and the existing session lifecycle. This adds no second connection
scheduler or fallback authorization policy.

`discovery_endpoint` captures one NetworkPathManager for the actual bind and for
subsequent candidate provenance. An explicit route rechecks the captured interface
index, Windows LUID, name, up state and current source before and after bind.
socket2 retains the existing kernel interface pin (Windows IP_UNICAST_IF /
IPV6_UNICAST_IF or Linux SO_BINDTOIFINDEX). A removed source, renamed/down adapter
or different-index replacement fails instead of silently selecting another
interface. Current candidate facts are restricted to that actual socket family,
bound source and selected interface. Under System policy the kernel route and
packet information remain authoritative; enumerating an address is a fact, not
proof that it can reach a particular remote network.

We compared guessing Linux physical devices from sysfs/name conventions with
requiring a trustworthy interface choice. Linux explicit ifindex is implemented;
automatic PreferPhysical remains explicitly Unsupported. A sysfs mount can
describe another network namespace and is not evidence of the current interface's
hardware. Windows retains its existing IP Helper classification. This boundary
must remain visible in the product until a trustworthy Linux classification
adapter is implemented and tested.

## Address validity and permission

We compared raw if-addrs snapshots with a small validity adapter over the native
OS facts. if-addrs remains the interface enumeration component. Windows IP Helper
GetUnicastIpAddressTable supplies current preferred/DAD/lifetime facts; Linux's
bounded kernel-owned `/proc/net/if_inet6` supplies source flags. Valid temporary
IPv6 addresses remain eligible. Tentative, optimistic, duplicate/DAD-failed and
deprecated sources are excluded, and a selected source is rechecked against the
current set. Link-local IPv6 remains excluded pending scope-aware LAN discovery.
These adapters do not implement a second network stack or general route parser.

Production gathering uses the endpoint's existing AddressPolicy. Public gather
defaults to public-only policy; IPv4 private and IPv6 ULA candidates require an
explicit local CIDR consent. This applies before publishing both interface and
STUN facts, as well as the existing check before dialing. A signed directory or
STUN mapping cannot grant local private-network consent. Relay-only permits
publish no direct candidates and send no STUN probes. No subnet scanning is
performed. Approved local interface candidates provide the LAN path in this
slice; product DNS-SD advertisement/discovery is tracked separately by W28/C13,
and is not claimed by this ADR.

The existing signed directory still checks issuer, deployment, login/session,
permit digest and nonce, and retains its original monotonic five-second budget.
Neither a directory response nor an interface/STUN fact proves peer ownership;
the original mutual TLS and business permit proof remain mandatory.

## Original generation and cache budget

We compared rebuilding the STUN engine/cache with extending the existing bounded
transaction demultiplexer. Trusted servers remain explicitly configured (at most
four), and replies still require the original source, transaction and generation.
The cache has at most one observation per trusted server and belongs to the
original DiscoverySocket. The receive path records an Instant when a matching
reply is consumed. Cache lookup never refreshes that receive time or its original
five-second expiry. Family, original socket address, trusted server, current
interface owner and generation must still match.

Network invalidation serializes against the existing pending transaction lock,
advances the generation, clears the short-lived observations and interrupts all
old waiters. Each actual nonblocking STUN send/retry checks its generation under
the same lock, so an old retry cannot be sent after invalidation completes.
WouldBlock waits also select the original response/invalidation receiver;
invalidation does not wait for a writable event or exhaust the probe deadline.
The existing three-attempt/two-second production budget and flood/GRO bounds
remain in place.

The SDK retains candidate provenance (actual interface identity or STUN
server/local socket) alongside the original permit issuer/digest, generation and
deadline. A gathered result checks its original five-second/permit budget,
per-observation deadline, current source and exposed candidate list before reuse.
It also retains a weak identity of the original socket owner: another socket with
the same generation cannot inherit its facts, and retaining facts does not retain
the physical UDP resource beyond the endpoint's existing close owner.
Dual-stack aggregation retains each result until both families have completed,
then rechecks its original socket/lifetime before publishing the combined list.
Waiting for another family cannot extend an earlier cached observation.
Its lifetime is not a new wire authorization lease. Candidate addresses already
sent through signaling retain the existing network-generation, business-lease,
endpoint proof and cancellation rules; this slice does not claim a new wire TTL
or uninterrupted sessions across an invalidated network.

## Executable checks and evidence limits

The new source tests exercise real IPv4/IPv6 STUN sockets, same-socket Quinn
transport, repeated cache lookup without a second request, real expiry requiring
a fresh request and invalidation requiring a fresh generation. A bounded socket
adapter covers an actual WouldBlock waiter and proves immediate invalidation
without a stale retry. SDK tests use real UDP replies for public and private/ULA
mappings, exact original provenance, denied/approved local CIDRs, substituted
permit/candidate facts, invalid permits and relay-only silence, and a delayed old
reply during generation change.

The existing isolated Linux namespace test now also checks candidate interface
identity/family/source, exclusion of a real deprecated IPv6 address and rejection
of the original socket's facts after source removal. It continues to cover kernel
ifindex pinning, address replacement, interface down/rename/delete and a new
same-named interface. The separate existing netlink test exercises real kernel
IPv4/IPv6 address/route/link notifications. A new real dual-stack test also holds
one family unanswered while the other family's original cached fact expires,
and requires the aggregate to reject those expired facts before publishing.
The original native dual-stack tests
complete actual business proof on each family and invalidate both endpoint
sockets from the same monitor baseline.

All compilation, formatting and automated execution must run on GitHub-hosted
Actions per R02. The Rust core workflow's scoped discovery/native dual-stack and
platform tests execute on Linux and an ordinary Windows token; its existing
linux-network-events job executes each ignored kernel test in a fresh owned
namespace. Exact source/run/artifact results must be recorded after those jobs
complete. Source tests are not passing evidence by themselves. Windows physical
multihoming, IPv6 temporary-address turnover, suspend/resume and target network
changes still require the external AC12 environment; no target pass is asserted.
