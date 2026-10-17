# Local TURN fork provenance

This directory is based on the crates.io `turn` crate version `0.17.2`, whose
upstream source is the `turn` directory in
[`webrtc-rs/webrtc`](https://github.com/webrtc-rs/webrtc/tree/1da3fe8ee84db8d266322cbcfcb357c745959a8e/turn).
The source archive identifies upstream commit
`1da3fe8ee84db8d266322cbcfcb357c745959a8e` in `.cargo_vcs_info.json`.

The fork keeps the upstream MIT and Apache-2.0 license texts beside the source.
NestLink's narrow modifications add allocation-scoped operation/peer hooks,
per-allocation close callbacks, and a larger bounded TURN-over-stream frame
buffer. The managed NestLink service always supplies a policy implementation;
the upstream-compatible default hooks exist only to preserve the library's
existing standalone API.

The original crate documentation, tests, examples, and licenses are retained.
The UDP examples use the already locked Clap 4.6.7 command builder and flag
APIs, replacing the upstream Clap 3 development dependency and its unmaintained
`atty` dependency. `Cargo.toml.orig` remains the unmodified upstream manifest.
Do not upgrade this fork by copying a new upstream source over it: review the
new version and reapply the managed hooks as a separately reviewed change.

RC source export: removed the upstream Codecov upload token from codecov.yml. Coverage upload credentials are not required to build or use this fork; runtime and license files are unchanged by this removal.
