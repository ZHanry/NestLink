# RUSTSEC-2026-0387 dependency remediation review

The previous DTLS 0.13 dependency chain selected p256/p384 0.13 and
crypto-bigint 0.5.5, affected by secret-dependent timing behavior in
RUSTSEC-2026-0387. Updating crypto-bigint alone cannot satisfy those curves'
older version requirements. No advisory ignore or version relabeling is used.

The reviewed DTLS compatibility fork preserves dtls 0.13.0 and its public
method signatures, upgrades p256/p384 to 0.14, and constrains crypto-bigint to
>=0.7.6,<0.8. It retains validated SEC1 peer points, uncompressed wire points,
fallible OS entropy, and unchanged ring certificate signing/verification.
Malformed SEC1 input remains rejected; its error classification changes from
the retained legacy Sec1 variant to the retained P256 variant.

Fork commit: `c4cf95eda3c244eff429c73b0d933ff2f18745b4` in
[ZHanry/NestLink-dependencies](https://github.com/ZHanry/NestLink-dependencies/commit/c4cf95eda3c244eff429c73b0d933ff2f18745b4).
The official dtls 0.13.0 archive is retained with SHA256
`f531dd7c181beaf3cebab3716afa4d0d41ab888be85232583f56bbaf07ca208a`.
The DTLS directory contains 107 tracked files, canonical snapshot SHA256
`b95d2c93d04681f3f24365aab7f355f92b8eea3e5ffca19ececfd7c6aba9cfb6`.
Existing six fork package snapshots are unchanged at the new commit.

[DTLS regression run40060558136](https://github.com/ZHanry/NestLink-dependencies/actions/runs/40060558136),
job120772929672, passed all 65 library tests with zero failures/ignored tests.
Added tests verify P256/P384 shared secrets, malformed points and wrong-key
rejection, a real authenticated P256 handshake and application payload,
untrusted certificate rejection, and valid/tampered transcript/signature and
wrong-certificate behavior. This is DTLS test evidence, not whole-product or
real-hardware acceptance.

Both independent workspaces use exact GitHub-derived manifests and locks:

| Scope | Source revision | GitHub run / attempt / job | Original ZIP SHA256 |
| --- | --- | --- | --- |
| Product | a23989facb56e9e02e16d81aec85de5b1d97ea20 | [40060708918](https://github.com/ZHanry/NestLink/actions/runs/40060708918) /1/120773379834 | f507a5319e425e83eb8a7aa898d74d8fae535328b99f4bac78831b05a9614fc4 |
| Browser native fixture | 0d48deccb6cd4dfef0a9980fc20a36b8a6d5c58c | [40061120677](https://github.com/ZHanry/NestLink/actions/runs/40061120677) /1/120774642928 | 770a333215193b950a8d4a8d8f8d05261565494784f9ff3b2c3305f5372c1e5f |

Both runs succeeded; API source/run/attempt/job binding, official artifact
digest, every receipt file length/hash, and before files against source Git
blobs were verified. They resolve dependencies without compiling the product.
Each lock contains crypto-bigint only at 0.7.6 and all Git forks at the reviewed
commit. Both introduce the same 31 reviewed registry tuples and remove the same 10
old crypto tuples. Product has 47 changed entries; fixture 40, including version
disambiguation, old crypto feature edges and compatible Windows resolver edges.

All newly introduced fixture registry identity/version/source/checksum tuples
match the reviewed product lock. Full fixture subset equality is not claimed:
three pre-existing tuples remain unchanged, including checksums:

| Fixture baseline package | SHA256 |
| --- | --- |
| zbus_names 4.3.5 | 812a12be4ead7a59e18ea8f047d08add0066b73bc62fc1467066a2472ae088dd |
| zvariant 5.15.1 | 80bf6d6cd6a4b601acb64cfb8284cdc643fcfa75ef26ae3c46ec8aa4e8a1fbb7 |
| zvariant_derive 5.15.1 | ef2672456ba1cb54b5eaec136e63135b3c7495fb938e53b28a62e633496d486d |

These are comparison-baseline exceptions, not vulnerability exclusions. Current
advisory checks still apply to every package. No local Cargo resolution, build
or test was performed during this remediation. Whole-product cargo-deny,
Linux/Windows/Web/ARM checks, runtime and hardware acceptance remain pending
for the integrated source revision.

The independent fixture is scanned with the same root deny.toml using
`cargo deny --manifest-path scripts/fixtures/browser-native-host/Cargo.toml --locked --all-features --config deny.toml check`.
For cargo-deny 0.20.2 these graph/config options precede the `check` subcommand.
The existing RUSTSEC-2026-0370/0371/0372 maintenance notices also cover the three
fixture baseline versions: each currently reports `informational = "unmaintained"`,
no patched standalone version and no version restriction. The same existing
maintenance-ID exceptions may describe both exact locks. Fixture reachability
is through nestlink-platform-clipboard/files/session to zbus 5.19.0; its lock
does not include the product desktop AccessKit/AT-SPI chain. No new advisory ID
is ignored, and these baseline or maintenance exceptions cannot exempt future
vulnerability advisories. The independent scan still requires an actual CI pass.
