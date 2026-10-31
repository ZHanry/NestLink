# 0054: Controlled LAN discovery on the original packet owner

Status: source implemented, hosted and target execution pending. Applies to W28,
F19/F23 and AC47/AC48; it does not mark any acceptance group passed.

The existing `webrtc-mdns` component serves ICE host names. It does not supply
the product's DNS-SD PTR/SRV/TXT service catalog or its registration lifetime.
We select the published, non-yanked `mdns-sd =0.21.6` with default features off.
ADR 0056 records the reviewed complete local snapshot and its default-off,
exact-interface routable IPv4 publication option needed by the peer's original
virtual address. The original DNS implementation and lifecycle stay in this
maintained component.
The reviewed source provides typed resolved services, binary TXT properties,
interface selection, probe/name conflict handling and unregister/shutdown
receipts. Its `socket-pktinfo =0.4.0` dependency is reused directly for UDP
discovery provenance. Windows and Linux both expose the actual receive
interface, source and destination through that maintained provider.

We compared broad layer-2 bridging, forwarding raw multicast packets, and a
restricted application adapter. Broad bridging would add unnecessary driver,
privilege and loop domains. Raw mDNS forwarding would leak arbitrary service
types and foreign link-local addresses. The selected adapter only forwards
approved UDP applications and selected DNS-SD descriptions. It cannot claim
universal LAN or layer-2 compatibility.

`network-lan` starts the same durable one-use `OnlinePacketAccess` used by the
managed packet path, binds the original pinned `DirectPacketEndpoint`, and runs
the existing `network_packet_runtime` loop. Original signed membership, path,
prefix/L3/L4 rules, one-use start, cumulative budget, login observation and
packet admission remain mandatory. The new adapter cannot renew them. Each
complete outer packet is admitted before encrypted transmission or any local
LAN delivery. Network membership alone supplies no LAN permission.

A separately reviewed owner-private `LanPolicy` and its explicit SHA256 consent
pin the space, LAN interface index/address/subnet, unicast envelope port, UDP
rules, exact responding LAN servers, DNS-SD types/ports, directions and bounded
rates. The selected interface is read back before each local action. Changing
the policy, login, installation intent, interface or original authority stops
the resident owner instead of updating its rights.

Discovery uses canonical Prost envelopes over exact original virtual IPv4
hosts. They bind the space and original business digest, a one-hop scope,
two-second wall-clock freshness and a 64-message replay window. The original
packet path still enforces its own monotonic authorization deadline. Clocks
must agree closely enough for the short freshness check; no positive skew or
latency extends signed authority. Complete game UDP datagrams up to the existing
1400-byte NRD1 ceiling use the existing bounded fragment encoder/assembler.
Flow binding additionally includes rule, client flow, request/reply and
broadcast mode, so fragments from different actions cannot be combined. There
is no new generic reassembler or alternate transport scheduler.

UDP reception uses exact kernel interface/destination metadata and a bounded
local subnet. Only approved link/direct broadcasts or traffic to this adapter's
own address enters a local rule. A received broadcast is deduplicated for
500 ms, never re-exported from this adapter's own source, and delivered on the
other LAN under that peer's independent explicit direction/port consent. Only
one configured actual LAN server may answer. Up to 64 idle-bounded client flows
retain their own reply socket; unrequested replies and other responder IP/ports
are refused. Discovery replies appear from the local adapter's approved game
port, allowing subsequent UDP application traffic to use the same bounded
flow. This requires an adapter host separate from the actual LAN game server.
Protocol payloads that embed addresses or require another transport may need
separate approved access and remain unqualified until real application tests.

DNS-SD exports only selected services actually resolved at the adapter's own
physical address. Imports advertise the authenticated remote virtual host,
never a peer-supplied arbitrary LAN address. Access to the discovered service
still requires a separate existing approved host/TUN/subnet path. Imported
records have deterministic peer names and a loop marker; imported records are
not exported again. Catalogs, TXT sizes and queued messages are bounded. Local
imports expire after ten seconds without original authenticated announcements;
withdrawal and normal stop unregister them and retain acknowledgement, then
wait for daemon shutdown under one absolute cleanup cap. External clients may
retain upstream DNS cache TTL after a crash. Such stale names cannot restore
or extend packet authority.

The registry archive SHA256 values and exact new dependency closure are retained
in `components.json`. All dependency resolution, formatting, compilation and
automated execution must occur in GitHub-hosted Actions. Local source review
does not qualify DNS discovery, physical cleanup, a game, cross-site behavior
or release readiness.
