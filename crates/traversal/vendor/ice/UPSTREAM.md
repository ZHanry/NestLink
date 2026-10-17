# Vendored WebRTC ICE source

This directory preserves `webrtc-ice` **0.14.0**, from the exact previously locked
crates.io archive. Its SHA-256 is
`69cb13fd1a373e68addc4bba0c8ca058627518e54342583d024bdcbb8ae5d97d`.
The upstream repository is [webrtc-rs/webrtc](https://github.com/webrtc-rs/webrtc),
commit `a1f8f1919235d8452835852e018efd654f2f8366`, directory `ice`.

All 63 archive files were verified byte for byte on import. `LICENSE-MIT` and
`LICENSE-APACHE` preserve the already reviewed upstream license texts from
`packaging/notices/webrtc-rs-LICENSE-*`; upstream code remains MIT OR Apache-2.0.
The source import receipt is
`artifacts/core-verification/ice-vendor-source-20261015-attempt01.json`.

The local production repair changes one comparison in
`src/agent/agent_internal.rs::find_remote_candidate`: match the candidate's resolved
IP and its existing port. A browser mDNS candidate retains its `.local` signaling
name after `set_ip`; comparing that name to a received packet's IP could never
find the original candidate. Network-type buckets and the previous handling of
IPv6 scope/flow and IPv4-mapped addresses are preserved. Four regression tests
are appended under `cfg(test)` in that same file.

The isolated regression harness runs the real `AgentInternal` method, with
`CandidateHostConfig` and `set_ip`. Its old-comparison run fails the two mDNS cases
while both numeric-address controls pass; its repaired run passes all four. The
harness disables upstream test-module registrations and development dependencies
only in its private copies, retaining every production Rust source. All 142
resolved registry identities are already present in the workspace lock. The
source transformations, byte audit, original failures, successful log and actual
test executable identities are frozen in
`artifacts/ice-resolved-candidate-followup-20261015/`.

The workspace and browser-native fixture select this directory through their
`[patch.crates-io]` entries. Their lock changes preserve every dependency version
and replace only this package's registry source/checksum with its local source.
No registry cache source was edited. Actual browser/media verification is recorded
separately in `docs/refactor/BROWSER-NATIVE-VERIFICATION.md`.

RC source export: removed the upstream Codecov upload token from codecov.yml. Coverage upload credentials are not required to build or use this fork; runtime and license files are unchanged by this removal.
