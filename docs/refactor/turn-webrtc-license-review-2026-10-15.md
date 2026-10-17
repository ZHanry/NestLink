# TURN/WebRTC dependency license review (2026-10-15)

This review records the exact TURN/WebRTC-related dependencies in the current lockfile, the managed local TURN fork, and the two newly surfaced Boost Software License dependencies. It is a scoped source and notice review, not the final product SBOM/NOTICE or formal release acceptance.

The `clipboard-win 5.4.1` and `error-code 3.4.0` crates declare `BSL-1.0`. Their registry archives match the Cargo.lock checksums, and the archive VCS metadata identifies the upstream source commits below. `error-code` includes the complete BSL text; `clipboard-win` does not ship a license file in its archive. The standard full BSL-1.0 text is retained for each exact dependency under [`packaging/notices`](../../packaging/notices). The existing `deny.toml` exceptions remain restricted to those exact versions; no global BSL allowance was added.

| Package | Locked version | Archive/Cargo.lock SHA-256 | Upstream commit | License and notice |
| --- | --- | --- | --- | --- |
| `clipboard-win` | 5.4.1 | `bde03770d3df201d4fb868f2c9c59e66a3e4e2bd06692a0fe701e7103c7e84d4` | `3b27cf2bfd1adcfa6e0264eb51c1025ddaf0f342` | BSL-1.0; full text `clipboard-win-5.4.1-BSL-1.0.txt`, 1,338 bytes, SHA-256 `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566` |
| `error-code` | 3.4.0 | `0b5343afd4a8365a643ac588dab4cf234a190c7f6c88c9f6dd6ffe00837661b7` | `e4615e514db3ff64f5f1b328b4865b20a3dcdbc3` | BSL-1.0; retained full text matches the archive `LICENSE`, 1,338 bytes, SHA-256 `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566` |
| `webrtc` | 0.14.0 | `08fd686c0920ac08f3a57eacc48e31f0e4ca1ffefba4478784606f78c14e83ad` | `a1f8f1919235d8452835852e018efd654f2f8366` | MIT OR Apache-2.0; complete upstream license texts are retained in the two `webrtc-rs-LICENSE-*` notices |
| `turn` | 0.11.0 | `5ed995882f66ab94238de77c62e5e778389698ab700afa4696f4754da8f457cb` | `a1f8f1919235d8452835852e018efd654f2f8366` | MIT OR Apache-2.0; the verified registry archive contains both license files |
| `waitgroup` | 0.1.2 | `d1f50000a783467e6c0200f9d10642f4bc424e39efc1b770203e88b488f79292` | `7a65c1990015b82584dbf3302b54f6ba29e38a01` | Apache-2.0; retained text matches the archive `LICENSE`, 11,357 bytes, SHA-256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` |
| managed local `turn` fork | 0.17.2 | Path dependency; no registry checksum | `1da3fe8ee84db8d266322cbcfcb357c745959a8e` | MIT/Apache-2.0 in the vendored manifest; both complete upstream texts remain beside the modified source and byte-match the retained WebRTC notices |
| `stun` | 0.17.2 | `2e3b8d5ad1dd4c8cd0595440f26521a71dd593cb5873ee8e06b91510b7d97269` | Managed TURN dependency | MIT/Apache-2.0 per crates.io version metadata checked 2026-10-15 |
| `webrtc-util` | 0.17.2 | `1beae0b4f24969741c26ca282a257dc5823bd9cbe608f7e3ca3775102d323ad9` | Managed TURN dependency | MIT/Apache-2.0 per crates.io version metadata checked 2026-10-15 |

The registry archive SHA-256 values for `clipboard-win`, `error-code`, `webrtc`, `turn`, and `waitgroup` were computed from the local `.crate` archives and match `Cargo.lock`. The `stun` and `webrtc-util` values match both `Cargo.lock` and crates.io version metadata; those two archives were not cached locally during this review. The local TURN fork provenance and license copies are documented in [`crates/traversal/vendor/turn/UPSTREAM.md`](../../crates/traversal/vendor/turn/UPSTREAM.md).

`deny.toml` continues to permit BSL-1.0 only for `clipboard-win =5.4.1` and `error-code =3.4.0`. This review adds no license exception or security-advisory ignore. Do not broaden these allowances; repeat the review when any pinned release or the local fork changes. Preserve all applicable copyright and license notices in the final third-party distribution inventory and generate the complete locked-product SBOM/NOTICE before release.

Machine-readable package identifiers, source evidence, and notice hashes are recorded in [turn-webrtc-license-review-2026-10-15.json](turn-webrtc-license-review-2026-10-15.json).
