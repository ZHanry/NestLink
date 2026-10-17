# TLS and dependency advisory review (2026-10-16)

The complete `cargo-deny --all-features check` run in
`artifacts/core-verification/android-browser-host-dependency-audit-20261016-attempt01.log`
failed. Its advisory failures and original source/log receipt are retained.
License, source and ban checks passed in that run. This document records the
individual dispositions; subsequent verification results are recorded separately.

| Advisory | Locked dependency and disposition |
| --- | --- |
| RUSTSEC-2026-0346 | Upgrade rustls 0.23.45 to 0.23.46. Client session `Debug` output must redact resumption secrets. |
| RUSTSEC-2026-0347 | Same upgrade. Rejected ECH must fail before releasing buffered application data. |
| RUSTSEC-2026-0348 | Same upgrade. Bound the Brotli decompressor's peer-selected window. NestLink does not request this optional feature; the vulnerable package is still replaced. |
| RUSTSEC-2026-0349 | Same upgrade. Record the predicted key-exchange group only after authenticating the server. |
| RUSTSEC-2024-0375 | Replace the local TURN fork's Clap 3 development dependency with the already locked Clap 4.6.7 and migrate both retained UDP examples. This removes `atty`; no advisory ignore is added. |
| RUSTSEC-2025-0134 | Remove the direct `rustls-pemfile 2.2.0` dependency. Use the existing `rustls::pki_types::pem::PemObject` parser, retaining the regular-file, private-file, 1 MiB and 1–8 certificate limits. No advisory ignore is added. |
| RUSTSEC-2025-0141 | Reviewed maintenance-only exception for bincode 1.3.3 through dtls 0.13.0 and webrtc 0.14.0, with the reachability limits below. |

The rustls 0.23.46 registry archive SHA-256 is
`48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf`.
The locally downloaded archive matches the retained crates.io version metadata.
Its VCS metadata identifies upstream commit
`f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`. The complete Apache-2.0, ISC and MIT
texts, their hashes, official metadata, and a 25-file archive difference inventory
are retained in `artifacts/tls-dependency-review-20261016/SUPPLIER.json` and its
adjacent files. The declared license remains `Apache-2.0 OR ISC OR MIT`; no license
allowance is broadened. The project minimum rustls version is also raised, so a
future lockfile regeneration cannot select the affected 0.23.45 release.

The bincode advisory reports that development has stopped, with no patched
upstream release. It identifies no concrete vulnerability and describes 1.3.3
as complete. The selected graph uses bincode only in dtls 0.13.0. In that exact
crate, the only two `bincode::` calls are in the explicitly invoked
`State::marshal_binary` and `State::unmarshal_binary` export/import APIs in
`src/state.rs`. Searches of all DTLS and WebRTC Rust sources find no callers of
these APIs. NestLink does not call them either. DTLS cloning uses its typed
`serialize`/`deserialize` helpers directly; network handshake and record parsing
does not enter bincode. The similarly named methods in the local ICE UDP mux
belong to STUN message parsing, not DTLS State.

`deny.toml` therefore records only RUSTSEC-2025-0141 as an individually reviewed
maintenance exception for this dependency path. This does not approve importing
untrusted serialized DTLS state. Recheck source reachability whenever bincode,
DTLS, WebRTC or their callers change, and before stable release. A future security
advisory has its own ID and remains blocking. Do not replace this finding with a
global maintenance allowance or silently move to an incompatible serializer.

The new PEM regressions exercise a generated certificate/key pair through a real
rustls handshake and encrypted application data, plus empty or malformed PEM,
excessive chains, oversized files and mismatched keys. They generate disposable
keys locally and retain no private key material in reports. These checks and the
affected platform/transport builds must pass before this update is considered
verified. They do not establish installed-product or signing acceptance.

The exact TLS-update source and results are frozen in
`artifacts/tls-dependency-review-20261016/FROZEN.json`: Windows selected tests
passed 233, with three explicitly ignored environment-dependent cases; complete
workspace strict Clippy passed. Linux executed 227 passing tests, six failures
and four ignored cases. The new PEM/TLS cases and TURN/transport groups passed on
both platforms. The failed Linux batch remains failed. The wall/monotonic
observer retained 18 steps across its whole command and separate process-window
associations in `LINUX_FAILURE_REVIEW.json`; this association does not establish
each failure's cause. A service-start socket-release race found in that batch
has been corrected and verified as a separate [follow-up](SERVICE-HOST-SOCKET-RELEASE.md).

`SOURCE_REVIEW.json` records the one rustls upgrade and removal of eleven obsolete
packages, with no other registry version/checksum change.
`ARCHIVE_SOURCE_VERIFICATION.json` also compares 303 Rust files to the exact
locked rustls, bincode, DTLS and WebRTC archives. The first updated full audit
attempt02 and the post-socket-change audit attempt03 both passed; their original
logs and source/log/cleanup receipts remain distinct.

The post-repair Windows eight-package batch passed 236/0/3
(passed/failed/ignored), and strict workspace/all-target checks passed on Windows
and Linux. With the explicitly authorized temporary WSL NTP pause, complete
Linux workspace runtime attempt03 passed 1100/0/12 on unchanged inputs and no
observed clock steps. The wrapper restored the original `tsc` clocksource and
active timesyncd, confirmed again by independent readback. The complete summary
is `artifacts/core-verification/native-workspace-linux-runtime-20261015-attempt03-summary.json`;
original failed batches remain unchanged. Android BuildAttempt15 / MatrixAttempt13
passed 112 actual API30–36 emulator cases and both ABI release/all-target strict
Clippy; this is development verification, with formal product acceptance pending.

All three original rustls 0.23.46 license files are now retained under
`packaging/notices/rustls-0.23.46-LICENSE-{APACHE,ISC,MIT}.txt`; their packaged
bytes are bound to `PACKAGED_NOTICES.json` in the TLS evidence directory. The new
[Cargo notice collector](cargo-notice-review-2026-10-16.md) also binds complete
license/attribution material to checksum-verified locked dependencies. Its three
remaining missing MIT originals are separately blocking; a successful security
audit does not resolve those source-material gaps.
