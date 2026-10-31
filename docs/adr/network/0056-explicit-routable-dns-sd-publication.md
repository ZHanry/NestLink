# Explicit selected-interface publication of authenticated virtual IPv4

The chosen mature mdns-sd 0.21.6 filters address records to the advertised
physical interface's subnet. Its public API cannot opt in to publishing a
routed virtual address. This prevents the W28 adapter from announcing the
original authenticated remote peer's virtual IPv4. Publishing the remote raw
LAN address or adding fictitious local interface addresses would produce
incorrect endpoints and does not resolve that integration gap.

We retain the complete checksum-verified upstream package as an excluded local
dependency and apply one explicit, default-off publication option. The option
names an exact nonzero interface index and only permits a caller-supplied
unicast IPv4 outside that interface's subnet on the named interface. The
maintained DNS codec, sockets, parser, conflict probing, cache, TTL, unregister
acknowledgement and physical daemon shutdown remain unchanged. The original
default and all IPv6 behavior remain unchanged. The component owns this DNS
mechanism; NestLink does not implement a competing mDNS stack.

The local policy must explicitly set `allow_routable_publication: true` together
with import approval. The SDK obtains the published address from the original
OnlinePacketAccess peer assignment, uses its separately selected physical LAN
index, and refuses a changed interface. A record contains neither the remote
LAN address nor a peer-supplied destination. This option creates no route and
provides no TCP/UDP authority: the independently admitted virtual path must
already be usable for an application to connect to the announced address.

Both upstream full license texts and original attribution remain in the local
snapshot. Original archive hashes, complete inventory, exact local source edit
and release-notice review are bound by `third-party/mdns-sd/UPSTREAM.json` and
the collector's exact review entry. Cargo locks are derived on GitHub-hosted
Actions, with the same mdns-sd version and dependency closure changing only
from registry identity to this reviewed path identity.

The pure component regression checks default denial, exact interface, invalid
index and address classes, and reversing the opt-in. The original real dual-LAN
fixture checks actual DNS-SD resolution with the authenticated virtual IPv4 and
binary TXT. These are mechanism checks; they do not qualify either frozen game,
Windows target networking, public Internet, physical sites or a virtual HTTP
application data path. Execution evidence must be recorded separately.
