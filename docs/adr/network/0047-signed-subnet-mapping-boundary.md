# ADR 0047: Signed exact subnet mappings and the privileged provider boundary

Status: mapping protocol, signature verifier and SDK local-plan source implemented; hosted compilation/tests pending. Management persistence/API, online gateway owner, privileged subnet application/recovery, Windows provider and primary/standby switching are not implemented by this slice. W23 and AC37/AC38 remain open.

Date: 2026-10-31, Asia/Shanghai. Applies to W23/F14/F23. R01 and R02 apply throughout.

## Reuse and alternatives

Reuse the existing signed `RouteExport`, `NetworkAccess`, verified network path, one-use online start, `PacketPeerAuthority`, whole-packet parser, cumulative business budget and original packet carrier. Reuse locked `ipnet 2.12.2` for CIDR overlap decisions, existing Ed25519/HKDF/SHA-256 identity primitives and the reviewed TUN provider. Do not implement packet rewriting, transport checksums, IP forwarding or NAT connection tracking in Rust.

For Linux prefix translation, select the distribution-installed root-owned nftables/netfilter and iproute2 tools. The official nftables manual documents `snat ip prefix to ip saddr map { original/prefix : alias/prefix }` and the corresponding destination-prefix statement. nftables owns prefix rewriting, transport checksums and conntrack state. iproute2 owns route/address changes and readback. Record the exact kernel, nftables and iproute2 versions, feature checks and command output in hosted evidence before enabling this adapter. A recent manual is not evidence that an older target supports prefix NAT.

Alternatives compared:

1. A Rust packet NAT implementation. Rejected: it duplicates mature forwarding/checksum/fragment/conntrack behavior and creates a second security boundary around the existing whole-packet ACL.
2. Unconstrained system-wide masquerade, default routes or globally enabled forwarding. Rejected: the product cannot own those shared resources or infer LAN approval from space membership.
3. Exact nftables prefix NAT plus explicit route resources, with a separately invoked root owner. Selected Linux mechanism, pending implementation/qualification. Existing protected metadata, bounded trusted commands, process identity and exact journal/readback patterns must be reused rather than copying a new generic helper stack.
4. nftables on Windows or an unreviewed custom WinNAT/WFP translator. Unsupported. Windows access endpoints may eventually route approved aliases to qualified Linux gateways, after the Windows TUN ownership work is complete. A Windows gateway requires its own mature provider selection and real standard-user/admin boundary experiment; it is not covered by the Linux selection.

Sources reviewed on 2026-10-31:

- [nftables manual: NAT statements, prefix mapping and chain/conntrack behavior](https://netfilter.org/projects/nftables/manpage.html).
- Existing component decisions C07 (`ipnet`), C08 (strict IP parser), C09 (TUN provider), C23 (nftables protected socket gate).
- Existing ADRs 0021, 0035, 0037, 0043 and 0044 for publication authority, host-prefix ownership, privileged kernel resources, one-use packet access and ordinary TUN ownership.

## Frozen mapping contract

`protocol::subnet::SubnetMappingClaims` contains `mapping_version=1`, the original `GrantScope`, registered `gateway_node_id`, `gateway_public_key`, derived `gateway` PeerId, accepted `gateway_incarnation`, canonical `original` and `alias` prefixes, exact `route_export_digest` and positive `mapping_revision`. The original LAN and wire alias must use the same address family and prefix length. IPv4 supports identity routes or one-to-one prefix NAT. IPv6 version one accepts only identity routes; IPv6 NAT is rejected. Neither a default prefix nor a noncanonical network, loopback/multicast/unspecified prefix is accepted. Maximum mapping lifetime is fifteen minutes and claims are bounded to 4096 canonical bytes.

`identity::NetworkAuthoritySigner::sign_subnet_mapping` uses the existing network authority and a separate `NestLink/subnet/v1/exact-mapping` domain. Existing network-grant verifiers cannot reinterpret the envelope as RouteExport, membership or NetworkAccess. `SignedSubnetMapping` is only an envelope; `VerifiedSubnetMapping` is not deserializable.

`verify_subnet_mapping(signed, network_context, verified_route_export, current_gateway)` requires the exact RouteExport digest, the same authenticated gateway and both exact `original` and `alias` publication prefixes. A broad containing export is insufficient. The mapping interval cannot expand its export interval. Its grant ID is distinct from the export ID. `SubnetGatewayState` is supplied from a fresh authenticated management snapshot, never reconstructed from the mapping: accepted node ID/key/boot incarnation, current mapping revision and current lease end. Changed key/runtime/revision, revoked export/mapping, policy epoch change, expired mapping or expired node lease fails verification. Refreshing a node lease does not change the mapping's original expiry.

`RouteExport` still grants publication only. An alias denotes an exact approved LAN; it does not open a port or authorize forwarding. At both ends, authenticated PeerId/SpaceId must first own the signed alias/source prefix through `PacketPeerAuthority`, then the independent NetworkAccess destination/direction/protocol/port/time/quota policy must admit the complete packet. IP fragments/options/unsupported extensions retain the existing fail-closed policy. Replies retain the same bounded original flow state and cumulative budget.

## Management and online production adapter contract

The next management slice must persist mappings and their revisions/tombstones in one transaction, enforce space-wide alias nonoverlap, verify the current accepted registered node and RouteExport, require space-manager approval, retain the original signed bytes for idempotent readback and audit issuance/revocation. It must also record the exact mapping-digest/NetworkAccess-digest association at business issuance, revalidate it on every online start/readback, and cascade mapping/export/key/runtime changes into all referencing packet graphs. A local mapping file cannot supply that association. A future independently verifiable offline business requires a separate signed binding or explicit mapping-digest reference in the business grant; version one local plans are online-only.

Proposed route family, to be finalized by the API/storage owner before implementation: `POST /network/spaces/{space}/subnet-mappings` issues an exact request with expected policy/revision, existing export ID and current gateway incarnation; `GET /network/spaces/{space}/subnet-mappings/{id}` returns original signed bytes and fresh current gateway state; `DELETE` revokes the original ID using expected revision. API names above are a contract proposal, not registered routes in this slice.

The existing packet-access API currently admits only current installation `/32` and `/128` addresses. Its `OnlinePacketAccess` constructs authorities with empty export lists. RouteExport is currently tied to a registered data-node key, while the packet endpoint uses installation membership. The production owner must explicitly prove a node-to-installation same-public-key association, or introduce an independently authorized gateway endpoint contract. Reusing a node ID as an installation ID or copying an installation membership around a different node key is forbidden. This gap must be resolved before the host-only API is expanded.

The ordinary production gateway owner should extend the original TUN/packet owner with explicit local approval of the complete mapping/access digest pair, both signed export authorities, exact LAN interface and original underlay selection. It consumes the durable one-use start before any resource and keeps the original signed graph and noncloneable packet budget. The approved digest pair cannot silently change on renewal. Fresh online observation must confirm the exact persisted association, mapping revision, accepted gateway runtime, membership, address ownership and both exports; logout, maintenance, observation gaps or any change stops the original resources. No queued old IP packet is replayed after owner replacement.

`sdk::network::subnet::VerifiedSubnetPlan` checks the current signed mapping and separate NetworkAccess, exact alias ownership by the selected authenticated gateway, an explicit non-deserializable `SubnetLocalConsent`, distinct pinned TUN/LAN names and indexes, and concrete original physical endpoints outside the alias route. It bounds the original plan by mapping, business and node-lease expiry, and sixty seconds; real wall-clock and monotonic checks cannot extend it. It creates no packet budget or resource. An OS adapter must additionally intersect the original path's remaining deadline and enforce the already consumed start claim. Serialized `SubnetPlanView` is review data, not an executable authorization. `nft_ipv4_translation` emits only the two bounded mature-provider translation statements; it neither applies rules nor implements the firewall/recovery owner.

`check_mapping_conflicts` uses `ipnet` to reject alias overlap, aliases overlapping another mapping's original network, duplicate mapping IDs, cross-space/policy combinations and local/protected routes. Two independent gateways may have the same original `192.168.1.0/24` when they use distinct aliases. The management transaction must enforce the complete namespace, while the local owner must separately inspect the actual kernel route/address tables and protect virtual pools, local LANs and physical carrier endpoints. Existing default routes are observed and preserved, never supplied as alias reservations.

## Privileged Linux lifecycle still required

Only a separately selected root helper may configure subnet forwarding. Its public plan must authenticate the entire exact mapping/access pair against fresh management pins and the original ordinary owner, then bind the existing interface index/alias/UID, LAN index, finite deadline and route namespace. It must not deserialize an arbitrary shell command or merely trust the SDK plan view.

The helper must use atomic nftables transactions, owner-UUID table comments, exact original table/chain/rule handles and a root-private durable recovery journal. Prefix NAT rules must be restricted to both original TUN index and name, and paired with explicit forwarding/source fences for the exact original LAN. A NAT chain sees the first packet of a connection; deleting NAT rules alone does not invalidate established conntrack entries. Expiry/revocation therefore requires an atomic deny fence for the owned TUN/zone, original owner/carrier termination, exact owned conntrack-state destruction or a proven nonreusable zone, and physical cleanup readback before acknowledging stop. Never flush the shared conntrack table or unrelated nftables rules.

Enabling forwarding must use an explicitly owned isolated namespace or a rigorously checked compare/restore resource contract. Do not silently flip host-global sysctls or restore a stale global snapshot over another VPN. Existing firewalls may still reject a packet; the product must report that failure instead of adding a global accept rule. Partial installation, helper/ordinary crash, changed interfaces/rules, upgrade and uninstall must keep exact journals/fences until safe cleanup is proven. External changes are preserved for operator review.

The final LAN hop is ordinary LAN traffic unless the target application supplies encryption. LAN devices represent the gateway identity plus the authorized source prefix; they do not acquire individual NestLink public-key identities. For individually keyed devices, use installed clients or separately authorized WireGuard credentials.

## Next slices and required evidence

1. Hosted protocol/identity/SDK tests and strict lint for the exact source, including signature purpose, wrong space/epoch/runtime/revision/export, stale clocks, local approval, original endpoint recursion and ambiguous alias cases.
2. Management mapping persistence/API, node-installation identity binding and exact online packet-access association, with actual concurrent HTTP and reopen/revocation tests.
3. Journaled Linux namespace/forwarding/conntrack owner and production ordinary CLI integration. Hosted kernel qualification must exercise full 1280-byte packets, TCP/UDP/ICMP rules, bidirectional original/wire address observations and cleanup; no Rust packet rewriting is permitted.
4. Two sites plus access LAN all using `192.168.1.0/24`, simultaneously access exact different mapped targets; spoof source, wrong peer/space/direction/port, route reflection, revoked mapping and default-route hijack must fail. Primary/standby needs an explicit logical-site ownership revision and fencing contract before any shared-alias adoption. New flows may switch; old NAT connections are not promised to survive.
5. Windows TUN access/provider work and Windows gateway boundary qualification, target Linux distributions, actual multi-gateway sites and target-device evidence. Lack of a real site blocks those acceptance cases, not independent source work.

All dependency derivation, code generation, compilation, formatting, lint, automated tests and kernel experiments run only through GitHub-hosted Actions. No local verification command was run for this slice. Source/tests are pending evidence and do not mark W23 complete or authorize a release.
