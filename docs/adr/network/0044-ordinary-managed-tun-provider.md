# ADR 0044: Ordinary owner and exact managed TUN resources

Status: Linux source implemented, pending GitHub-hosted compilation and native experiments. Windows provider adoption remains an explicit implementation gap. W22 is not complete.

Date: 2026-10-31, Asia/Shanghai. Applies to W22 and the future W23/W24 adapters. R01 and R02 apply to every dependency and experiment below.

## Decision and alternatives

Use the installed Linux kernel TUN driver and exact `tun-rs 2.8.16`, with `default-features = false` and only `async_tokio`, for descriptor framing, readiness and whole-packet I/O. NestLink implements the original ordinary process, signed business/host binding, finite online lifetime and exact OS-resource ownership. No TCP/IP stack, encryption, TUN driver or generic netconfig implementation is added.

Compared options:

1. Run the whole daemon as root/administrator. Rejected: it exposes login recovery, transport and application business code to permanent network-administration privilege.
2. Reuse the kernel/provider with a separately selected public plan and minimal privileged owner. Selected for Linux: create a new nonpersistent interface, record its original identity durably, then make that exact interface persistent and accessible only to the original ordinary UID. The ordinary process holds the sole packet descriptor and independently checks every complete IP packet.
3. Write custom TUN ioctls, a Windows ring implementation or an ad hoc TCP/IP stack. Rejected where the reviewed provider already supplies the operation. Windows handle-adoption gaps require a separate minimal design and actual standard-user experiment; they do not justify elevating the whole daemon.

The host-only command deliberately accepts two exact signed local addresses and two exact remote `/32` and `/128` routes. It does not install a subnet, default route, forwarding policy, NAT, DNS or WireGuard portal. W23/W24 remain separate mandatory work; these narrower source boundaries are not a scope waiver.

## Original authority and ordinary packet owner

`network-tun` reuses the existing installation admission, registered installation key, protected `SessionStore` recovery, `HeadlessRuntimeLease`, maintenance/logout observation and operator-pinned network authority. It neither introduces a second login nor reads credentials in a privileged process.

Before a socket, plan or system resource is created, `OnlinePacketAccess::start` consumes the original durable online `NetworkAccessStart` claim. Even the same owner UUID cannot retry a lost start response. A restarted command needs a newly issued grant and a new explicit local digest approval. The original cumulative full-duplex budget and original expiry never reset after reconnect, stop or re-reading a saved JSON response.

The ordinary owner continuously refreshes the exact pinned management graph, current address assignments and epochs. It stops on an observation gap, revoked/changed grant, membership/address replacement, logout, protected-session rotation, maintenance, expired lifetime, changed interface or failed physical path. Packet validation uses current time before every admission. Neither a cached plan nor a recovered journal can manufacture new network authority.

`DirectPacketEndpoint` binds the explicit original underlay before any overlay route is installed. Endpoint-pinned installation mTLS, the dedicated packet ALPN and the exact business/transport-group proof precede packet access. The selected interface/source is revalidated; a virtual host route cannot equal either explicitly selected physical peer endpoint. Complete IP packets are admitted locally before transmission and remotely before OS injection, using the original SDK policy and reply table. Existing bounded authenticated fragmentation preserves the complete IPv6 minimum 1280-byte MTU; this is distinct from accepting IP fragmentation. The TUN read buffer is 65536 bytes so an oversized provider packet cannot be truncated into a valid-looking 1280-byte prefix.

## Minimal privileged resource owner

`network-tun-system` accepts `review`, `init-journal`, `apply`, `inspect` and `recover`. The plan contains only schema/owner/space/deployment identifiers, original process identity and UID, exact hosts/peers, approved public grant digest, original finite deadline, pinned authority and signed public policy. Unknown fields are rejected. No session path, login token, arbitrary executable, route command, default route, DNS server or arbitrary prefix is deserialized from a plan.

The helper checks the original live ordinary PID/start identity, UID, exact executable device/inode, same image and same network namespace. It uses the existing process-identity, trusted OS-command and protected-metadata primitives. `ip` is resolved from fixed root-owned OS directories with writable executables rejected; no caller-controlled shell or loader environment is inherited. The installed root-owned `/dev/net/tun` character device 10:200 must already exist, so the provider's device-node creation fallback is not used.

Creation order is significant:

1. Reject existing same-named links, existing assigned hosts and overlapping nondefault routes, including another VPN's host/subnet route. Existing default routes are observed and preserved.
2. Ask the kernel to allocate a fresh unnamed **nonpersistent** exclusive L3/NO_PI TUN, without offload, multiqueue, addresses or routes. Rename that new descriptor's interface atomically to the planned name, failing if the target was occupied after preflight. Passing a requested name directly to the provider could otherwise attach a raced existing TUN. Give the new interface the ordinary UID and full owner-UUID marker. A crash at this stage drops the creating descriptor and the kernel removes the ephemeral interface.
3. Record the actual original interface index, name, marker and UID in the root-private durable journal before persistence can outlive that descriptor.
4. Persist that exact interface, configure MTU 1280, disable automatic link-local address generation, add only the signed local `/32`/`/128` addresses and exact remote host routes, then read back complete address/route state.
5. Close the privileged descriptor. Only then can the original ordinary UID attach the single queue. The ordinary owner independently compares the exact interface/readback before and after opening it.

The helper never receives or injects a packet. It never loads an installation key or management session. It holds its original recovery lock, watches the original normal process and public plan, and removes only the original journal-owned interface. Deleting the exact ordinary-owned public plan is a one-way stop request. Crash recovery cannot attach the original online budget or restart traffic.

The public plan is opened with Linux `NOFOLLOW | NONBLOCK`. Type, owner, mode and size are checked on that same descriptor before a bounded read; UID, mode, length, modification time and change time are compared again after reading. A replaced symlink or FIFO cannot redirect a root read or block its expiry/process monitor. The signed policy is still validated independently. Observing the configured link as UP is not proof that the helper has closed its queue: the ordinary owner retries only the original `EBUSY`, with exact before/after readback, login/maintenance checks, online refresh and termination handling, under a monotonic deadline bounded by two seconds and the original remaining lifetime.

Ordinary descriptor attachment changes volatile carrier/queue counts. Ownership comparisons therefore retain the complete stable identity, MTU, activation, persistence, framing, exact addresses and normalized route state, excluding only volatile `linkdown` from the route flag list. No gateway, multipath route, different source/metric/table, broad prefix, extra address or foreign route is accepted. A changed/replaced interface or external configuration is preserved with a failed cleanup receipt and retained recovery journal, rather than silently adopted or deleted.

After the packet descriptor is dropped, normal shutdown removes the original public plan and waits at most five seconds for OS absence. The helper confirms that the original link and all routes referring to its name are absent before clearing its root journal. Failure is reported and retained for explicit recovery. The five-second target requires actual native evidence; a timer in source alone is not a passing measurement.

## Exact dependency and full target-lock review

Official exact-version crates.io metadata and dependency endpoints were read on 2026-10-31. The published `tun-rs` archive was downloaded for source reading only; its local SHA256 equals the registry checksum below. No dependency installation, resolution, formatter, compiler, test or project script was executed locally. All lock derivation and execution occur in GitHub-hosted Actions.

The reviewed provider source includes `Cargo.toml`, `build.rs`, `src/builder.rs`, Linux creation/persistence/owner operations, Unix async descriptor adoption/readiness and Windows adapter/session creation/open/drop paths. This is a component/boundary and dependency-edge review, not a claim that every line of every third-party crate received a security audit.

| New lock identity | SHA256 | License | Published MSRV |
| --- | --- | --- | --- |
| tun-rs 2.8.16 | `280a6cc03289f9254d9268eadd5712c476dbd7a47ef51aae86e8b9d0b45dcd43` | Apache-2.0 | Not declared |
| nix 0.31.3 | `cf20d2fde8ff38632c426f1165ed7436270b44f199fc55284c38276f9db47c3d` | MIT | 1.69 |
| getifaddrs 0.6.2 | `a542e1b7ac1f3d62c5777d430d66eca9cb59e813c46b86e29fa9ce94ff9a4810` | MIT OR Apache-2.0 | Not declared |
| libloading 0.9.0 | `754ca22de805bb5744484a5b151a9e1a8e837d5dc232c2d7d8c2e3492edc8b60` | ISC | 1.88.0 |
| widestring 1.2.1 | `72069c3113ab32ab29e5584db3c6ec55d416895e60715417b5b883a357c3e471` | MIT OR Apache-2.0 | 1.58 |
| winreg 0.56.0 | `7d6f32a0ff4a9f6f01231eb2059cc85479330739333e0e58cadf03b6af2cca10` | MIT | 1.60 |
| encoding_rs 0.8.35 | `75030f3c4f45dafd7586dd6780965a8c7e8e285a5ecb86713e63a79c5b2766f3` | (Apache-2.0 OR MIT) AND BSD-3-Clause | 1.36 |
| route_manager 0.2.17 | `694798681cd69a10928204225a680ad9416b081d9e9f8718d7a61e2d134da323` | Apache-2.0 | Not declared |
| netlink-packet-core 0.9.0 | `2d6e2daf9a8c2e21302714706860a0e6be02e03d17294ecc66b354ea7d4059dd` | MIT | Not declared |
| netlink-packet-route 0.33.0 | `59d48ffc8b73a506e1ff0878528c72668f2bfbc3d875b6be890a96be5d0d5576` | MIT | 1.77 |
| netlink-sys 0.9.0 | `c99d38e00b420df49e940fe0826e667c3dad82ac68eb4c2bbf754c1c14a83a10` | MIT | Not declared |
| flume 0.12.0 | `5e139bc46ca777eb5efaf62df0ab8cc5fd400866427e56c68b22e414e53bd3be` | Apache-2.0/MIT | Not declared |
| spin 0.9.9 | `3763264f6b73151db08c50ff20d7d8a0b8796e021cdea7ceedad07b80155fa0e` | MIT | 1.38 |

Each exact metadata record is at `https://crates.io/api/v1/crates/<name>/<version>` and its complete dependency list at the same URL plus `/dependencies`. All selected identities above were observed non-yanked. The earlier tentative `spin 0.9.8` was rejected after exact metadata showed it is yanked; only non-yanked `0.9.9` is approved. `encoding_rs` is deliberately locked at reviewed `0.8.35` instead of importing unrelated newer SIMD dependencies.

Full enabled target-lock edges:

- `tun-rs`: existing bytes/libc/log/Tokio; Linux ahash and nix; Windows getifaddrs/ipnet/encoding_rs/libloading/scopeguard/widestring/windows-sys/winreg/blocking. Only `async_tokio` activates existing Tokio and the Windows/macOS blocking adapter. No address-management, netconfig-rs, async-io, framed futures or bindgen feature is enabled.
- `nix 0.31.3`: existing bitflags 2, cfg-if, cfg_aliases, libc and memoffset 0.9.1 from the enabled network feature. Existing `nix 0.26.4` edges retain that exact version selector.
- `getifaddrs`: existing bitflags 2 and libc, or existing windows-sys 0.61.2. `libloading 0.9.0`: existing cfg-if/windows-link; all previous libloading edges retain 0.8.9. `widestring`: no dependencies. `winreg`: existing cfg-if/windows-sys 0.61.2; optional serde/chrono features are not activated. `encoding_rs 0.8.35`: existing cfg-if; optional serde/any_all_workaround are not activated.
- `route_manager 0.2.17` is the provider's macOS/BSD dependency. Cargo includes its complete target graph in the cross-platform lock even though this Linux product entry does not execute it. Its Linux target graph adds netlink-packet-core 0.9.0, netlink-packet-route 0.33.0 and netlink-sys 0.9.0; its Windows graph adds flume 0.12.0 and existing windows-sys. No optional Tokio/async-io/bindgen feature is activated.
- `netlink-packet-core 0.9.0`: no dependencies. `netlink-packet-route 0.33.0`: existing bitflags/libc/log/zerocopy. `netlink-sys 0.9.0`: existing bytes/libc/log, with its optional async backends disabled.
- `flume 0.12.0`: spin 0.9.9 and existing fastrand/futures-core/futures-sink. Spin's default feature adds existing lock_api, whose existing scopeguard edge is unchanged; portable-atomic is not activated. Flume enables fastrand 2.5.0 `js`; exact metadata shows that feature activates an optional **getrandom ^0.4 with wasm_js**, restricted to wasm32/wasm64 plus target_os=unknown. Its newly active lock edge must name the already existing getrandom 0.4.3. An earlier assumption that the edge used 0.3.4 was incorrect and is superseded by this exact metadata observation. No getrandom version change is permitted.
- Previously selected windows-sys versions, all existing package checksums, and all other existing dependency edges remain unchanged. A Cargo-generated unqualified `libloading` or `nix` selector is rewritten only to its original explicit version when the added second version makes the old selector ambiguous. Any other unexpected lock identity or edge blocks import.

Every new license must enter the existing Actions notices/SBOM pipeline before a release. Registry metadata, a compatible MSRV and a published checksum do not establish driver safety or platform qualification.

## Windows limitation and acceptance still required

The reviewed Windows provider calls `WintunOpenAdapter` automatically when a configured name already exists. It has no public `AsyncDevice`/`SyncDevice` API that adopts a privileged-created adapter/session handle into an ordinary process. Assuming standard-user `WintunOpenAdapter`/`WintunStartSession` permissions would be unsupported. A unique UUID adapter name, actual GUID/LUID/index readback and explicit conflict rejection are required before any future adoption. `delete_driver` must remain false: the driver can be shared by other VPNs, and deleting it is not an owned-interface cleanup operation. No unpinned Wintun DLL is bundled or loaded by this Linux-only entry.

The Windows packet-policy/carrier code can still be compiled/tested independently. A real standard-user Windows provider fixture, signed provider distribution/license review, ordinary-process handle/ring design and exact cleanup/coexistence tests remain mandatory. There is no hardcoded Windows success or elevation fallback.

Linux acceptance must cover the actual ordinary UID, exclusive descriptor, full 1280-byte IPv4/IPv6 traffic, grant/direction/source/port/fragment spoof rejection, original cumulative quota, live revocation/observation gaps, helper/ordinary crashes, partial install, external changes, physical endpoint recursion protection, unrelated VPN/routes and five-second normal cleanup. SDK and native mechanism experiments are evidence for their exact boundaries; protected-login production CLI, target distribution, long-soak and Windows/mobile evidence remain separate. Source and unit assertions alone do not pass W22 or authorize release.

## Hosted native mechanism entry

`network_tun_system::native_tests::ordinary_uid_root_helper_whole_packets_normal_close_and_crash_recovery` is an ignored, explicitly enabled Linux mechanism experiment. It must run as the ordinary user on an isolated `ubuntu-24.04` GitHub-hosted VM with passwordless `/usr/bin/sudo`, iproute2, `/usr/bin/env`, `/bin/kill`, `/usr/bin/mkfifo` and the installed root-owned `/dev/net/tun` character device 10:200. The fixture creates only UUID-named `nlt…` interfaces, the two signed local host addresses and two remote host routes; its root journal is a fresh `/tmp/nestlink-tun-native-<UUID>` directory. It refuses to run without both `GITHUB_ACTIONS=true` and `NESTLINK_TUN_NATIVE_LAB=1`.

The Actions command, after the exact lock has been derived and imported through Actions, is:

```sh
NESTLINK_TUN_NATIVE_LAB=1 cargo test --locked -p nestlink-daemon --bin nestlink-daemon network_tun_system::native_tests::ordinary_uid_root_helper_whole_packets_normal_close_and_crash_recovery -- --ignored --exact --nocapture --test-threads=1
```

The same compiled test image launches an ordinary actor and a separately elevated `hosted_native_role` actor; no Cargo command runs under sudo. The production helper `run`, plan parser, protected journal, exact Linux configuration, ordinary provider attachment and normal `release_plan` functions are reused. Actual kernel UDP packets traverse the ordinary TUN descriptor at complete 1280-byte IPv4 and IPv6 lengths. Mature `etherparse 0.21.0`, already present in the product lock, constructs correct reply packets, and real kernel UDP sockets must receive both replies. A second ordinary descriptor must be rejected. Normal stop measures exact interface absence below five seconds. A second scenario SIGKILLs the original root helper, requires persistence to survive, rejects recovery while the original ordinary owner remains alive, then SIGKILLs that owner and recovers from the original protected journal. Root cleanup removes only its named empty fixture directory after the recovery journal is absent; changed configuration is preserved on failure.

This source is pending hosted execution. It qualifies the driver/privilege/resource mechanism only. It does not instantiate a recovered production login, consume a real online NetworkAccess start through the production CLI, transmit authenticated packets between two devices, or establish target/VPN/soak acceptance. Those boundaries remain open even if this mechanism experiment later passes. The ordinary unit suite also exercises signed plan mutations, exact kernel-state rejection, private journal identity and bounded rejection of symlink/FIFO/oversized public input. All compilation, formatting, lint and test commands belong to GitHub Actions under R02.
