# ADR 0051: Owned Linux subnet namespace and ordinary packet carrier

Date: 2026-10-31, Asia/Shanghai. Scope: W23/F14/F23, Linux IPv4 provider.

Status: production CLI, privileged namespace owner and explicit hosted mechanism tests are implemented in source. The first hosted attempt at source `b313` failed during compilation before kernel execution; its build logs and receipt are retained by `subnet-native` run `41199335653`. Follow-up source fixes require another source-matched run. This ADR does not mark W23, AC37 or AC38 passed.

This implementation follows ADR 0047's signed mapping/ordinary business boundary and ADR 0049's separation of fixed authorization from current node liveness. The "unimplemented privileged provider" and first-node-lease expiry intersection described in ADR 0047 are historical descriptions superseded by these later slices. Their earlier evidence limits remain valid.

## Mature providers and alternatives

Reuse the existing original online one-use packet owner, pinned QUIC endpoint, strict complete-IP parser, cumulative meter and protected metadata primitives. Distribution-installed root-owned `iproute2`, `nftables`/netfilter, `util-linux unshare` and `iputils arping` own namespace/link/route manipulation, prefix translation, checksums, conntrack, process namespace creation and duplicate-address probing. `tun-rs` owns the nonpersistent asynchronous TUN. NestLink supplies exact signed authorization, consent, original process identity, bounded Unix framing and recovery receipts.

Host-global forwarding and shared conntrack manipulation are rejected because another VPN or administrator can own those resources. A userspace packet NAT is rejected because it duplicates maintained kernel behavior. The selected provider places all forwarding, NAT, conntrack and gateway interfaces in one newly created network namespace. No host default route, host address, DNS setting or global forwarding/rp_filter value is changed by the provider.

The component inventory already selects the existing strict parser/TUN and installed nftables boundaries. The native workflow records resolved kernel and package versions plus installed executable hashes. An official manual or source review is not evidence that a particular target kernel accepts the selected statements.

## Exact resources and crash recovery

The ordinary process restores its protected installation login, consumes the original online business start once and binds the original physical carrier before saving an owner-private plan. It explicitly pins the authority, mapping digest, access digest, original LAN parent name/index and a separately approved unused LAN IPv4 gateway address. The helper never reads login or installation secrets.

Each owner has a separately selected root-private journal directory. A durable consumed-business marker prevents helper restart from resetting the kernel quota. The helper verifies the original ordinary UID, process incarnation and executable inode. It starts the same executable with `unshare --net --fork --kill-child=SIGKILL`. The worker proves its nameless namespace inode; the helper commits that identity before using `ip netns attach`. A macvlan is created directly in the recorded namespace and attached only to the explicitly selected original Ethernet parent. The parent is reobserved before activation.

The worker creates one nonpersistent TUN. nftables is checked and applied before the macvlan receives its extra address or forwarding is enabled. `arping -D` must confirm the extra address is unused. Only namespace-local forwarding/rp_filter values change. The exact owned TUN/macvlan names, owner aliases, indexes, routes, addresses and nftables configuration are reobserved; unexpected changes stop the owner and retain an actionable journal.

The packet socket is first bound in the root-private journal directory. Its root-owned device/inode and the original destination-directory device/inode are durably recorded before exposure. A retained ordinary-directory descriptor and `renameat2(NOREPLACE)` expose that same socket without a privileged pathname overwrite. Journal and plan directory must share a filesystem. Cleanup removes only the recorded socket inode and exact named namespace inode; deleting the entire owned namespace also destroys its routes, nftables and conntrack. A replaced path, changed namespace or uncertain process observation is preserved for operator review. Recovery never signals a possibly reused bare PID or flushes shared conntrack.

## Packet authority, freshness and deadlines

Both ordinary endpoints still run the original `OnlinePacketAccess` admission and cumulative meter. The root pipe carries whole packets with a 65,536-byte framing bound; the packet owner and provider enforce the 1280-byte IP MTU. Packet fragments/options and unauthorized source, destination, protocol, direction or port remain denied. The kernel repeats exact prefix/interface/flow fences and a shared named byte quota. Mature prefix DNAT/SNAT maps each local original LAN to its approved alias. Return SNAT uses the separately approved extra gateway address, so ordinary LAN targets can reply without per-target route changes.

LAN hosts that initiate cross-site access still require an explicit route to the remote alias through that extra gateway address, either on the host or their existing router. Space membership does not install this route or authorize LAN exposure. The extra gateway address must be unused; the host's current address is not borrowed.

The root plan retains and verifies the original immutable signed bytes and fixed authorization deadline. Initial administrator admission additionally verifies the freshly captured same-boot node lease. During runtime the original ordinary online owner obtains the newest authenticated node/mapping/association state; failure, revocation, logout, maintenance or an observation gap permanently ends that owner. Root does not treat an ordinary JSON lease field as independently signed current central state.

Root issues bounded monotonically numbered observation challenges. The ordinary packet pipe records a received challenge, and its guard acknowledges it only after the shared runtime has successfully refreshed the original business owner. Root bounds that acknowledgement by the challenge's original monotonic issue time plus five seconds. Repeated or queued old acknowledgements cannot renew that interval. A frozen ordinary process therefore cannot keep root forwarding alive merely by retaining its PID and open socket. Kernel configuration observations have a two-second outer bound and remain bounded by both freshness and the original fixed deadline. Acknowledgement never creates a new grant, start, budget, owner or final deadline.

The kernel rejects traffic at the original absolute deadline, conservatively rounded down to a whole second; the worker also owns a monotonic timer. A helper may be prestarted with `apply --wait-seconds 60` and all independently selected public pins/LAN arguments before the ordinary process creates its fresh plan. This finite preparation window solves initial administrator command timing without renewing authorization.

## Verification and remaining scope

`.github/workflows/subnet-native.yml` compiles the exact source with the original lock and existing codec setup on an isolated GitHub-hosted Linux VM. It executes the test as the ordinary runner UID with separately invoked root helpers and retains build/execution logs, source/lock/executable/tool hashes, package versions, kernel identity and remaining resource observations. No local project generation, build, formatter, lint, dependency installation or test was run.

The native lab creates two independent Ethernet sites that both use `192.168.1.42/24`, distinct aliases and real listening services. It exercises real kernel prefix NAT, encrypted QUIC, complete-IP admission, 1280-byte UDP, segmented TCP, wrong port/direction/source, wrong authenticated peer, normal close, helper SIGKILL and exact namespace/socket/conntrack recovery. These are fixed signed mechanism credentials, not a simulated management login. Existing real HTTP/SQLite/`OnlinePacketAccess` tests supply their own online authorization evidence; a mechanism pass alone cannot claim combined production login-to-LAN acceptance.

IPv6 routing contract validation exists, but this Linux subnet namespace provider currently accepts IPv4 plans only. Windows gateway application, primary/standby logical-site fencing, target Linux distribution qualification, access-LAN overlap and actual multi-device/site tests remain separate required work. No namespace experiment can substitute for mobile or physical target-device evidence.
