# pin-utils maintenance advisory review · 2026-11-06

The dependency audit for source `20bf80a26217f6427a22487d868cb0f5c9f9e7ba` failed in [Actions run 42164015656](https://github.com/ZHanry/NestLink/actions/runs/42164015656), job `127716370941`, on RUSTSEC-2026-0441. That failed run remains failed. This review records a specific maintenance disposition; it does not assert that later CI has passed.

The [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0441) is marked `informational = "unmaintained"`, dated 2026-10-01, and has no patched version. It records the upstream archive and recommends standard `pin!` or pin-project libraries. It identifies no concrete exploit or vulnerability. There is no compatible patched pin-utils release to select in the existing nix 0.26 graph.

Exact crates.io source archives were downloaded and checked against the committed lockfile checksums:

| Crate | Archive SHA-256 | Relevant source |
| --- | --- | --- |
| pin-utils 0.1.1 | `13bee6c73da26345c729282832b60b0363cf3dd9f4bfd81d8551b7a1c889a113` | `src/projection.rs`, `src/stack_pin.rs` |
| nix 0.26.4 | `598beaf3cc6fdd9a5dfb1630c2800c7acd31df7aaf0f565796fba2b53ca1af1b` | `src/sys/aio.rs`, `Cargo.toml`, `src/sys/mod.rs` |
| webrtc-util 0.17.2 | 1beae0b4f24969741c26ca282a257dc5823bd9cbe608f7e3ca3775102d323ad9 | src/ifaces/ffi/unix/mod.rs, Cargo.toml |
| webrtc-util 0.12.0 | `d1c0c7e0c8f280f2bbfae442701465777ac07adaf46ce0c5863cd58e13fe472a` | `src/ifaces/ffi/unix/mod.rs`, `Cargo.toml` |

The product graph selects nix 0.26.4 through webrtc-util 0.12.0 and 0.17.2. The independent browser-native-host fixture selects both webrtc-util versions and the same nix and pin-utils versions and checksums. webrtc-util declares nix for non-Windows targets with default features; nix's default `aio` feature enables the optional pin-utils dependency. In the exact nix archive, pin-utils call sites occur only in `src/sys/aio.rs`, as pin projections for AIO objects. In both exact webrtc-util archives, nix calls are confined to socket address types and `getifaddrs` in Unix interface enumeration. It does not call nix AIO. Searches of first-party `apps/` and `crates/` find no nix AIO or pin-utils calls. Windows does not select this Unix webrtc-util nix path. This is a call-site review, not a claim that the package is absent from the all-features dependency graph.

`deny.toml` records only RUSTSEC-2026-0441 as an individual maintenance exception, consistent with the repository's existing per-advisory review process. Advisory checks, licenses, source restrictions and bans remain enabled. No version or archive checksum changes are made, and unrelated future security advisories remain blocking. Recheck the consumer graph and call sites on changes to nix, webrtc-util, pin-utils or their callers, and migrate to a maintained dependency path before stable release. This exception does not qualify physical-device, network, signing or UI acceptance.
