# RC2 SQLite and rustix security update, 2026-11-12

The initial RC2 audit for source `9707bb7cc1d4010c48f9de974892506632088449` failed on RUSTSEC-2026-0459 (bundled SQLite) and RUSTSEC-2026-0486 (rustix). Neither advisory was ignored. The original failing run and logs remain in Actions history.

Hosted lock derivation [43145679825](https://github.com/ZHanry/NestLink/actions/runs/43145679825), source `3bf595353147ffe703d94dfeef02b2e9969277f8`, succeeded for the product, browser-native fixture and fuzz scopes. Each original lock was compared with its committed Git blob before importing the derived bytes. This avoids Windows checkout line-ending ambiguity.

The product and fixture update rusqlite 0.37.0 to 0.41.0, libsqlite3-sys 0.35.0 to 0.39.1, hashlink 0.10.0 to 0.12.2 and rustix 1.1.5 to 1.1.6. Hashbrown/foldhash feature dependencies and compatible windows-sys selections were reviewed; no other package version changed. The fuzz lock was already fixed and is unchanged. Rusqlite retains cache, bundled, backup and serialize; the unused default WASM backend is disabled.

Exact registry archive SHA-256 values:

| Crate | SHA-256 |
| --- | --- |
| rusqlite 0.41.0 | 9c026b4444579e8d754556c6c75d040d69c4a44283cdb648ab8a8d5965c2cfa8 |
| libsqlite3-sys 0.39.1 | 14a5f01b87b92705d07b433c06f96cbc764637d81a0bffb5734ce17cf0f9a2b3 |
| hashlink 0.12.2 | a596f1b20ed2cc5ecac41a164aaebc7258057060f06c0cf7a2ba3991ee7990fb |
| rustix 1.1.6 | e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa |

The downloaded archives match those locked checksums. Their complete root MIT/Apache notices were reviewed. Rusqlite and its SQLite wrapper retain MIT, hashlink offers MIT or Apache-2.0, and rustix offers MIT/Apache alternatives including its LLVM exception. Existing notice collection retains original archive texts.

SQLite 3.54.1 `sqlite3.c` and `sqlite3.h` match the [official amalgamation](https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip) byte for byte. Its ZIP SHA-256 is `0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9`. Source ID is `2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76`. The original public-domain blessing is preserved in `packaging/notices/cargo-upstream/sqlite-3.54.1-PUBLIC-DOMAIN.txt` (SHA-256 `ad89cf5f9a0ca133418eae187ae954f2805fd3261aa00716642ed93fc7f3892d`), as an attribution excerpt rather than a synthesized license. The fixed notice collector and exact-version supplement now bind this archive. The old historical provenance document remains unchanged.

These are source, archive and lock reviews. Final exact-source audit, compilation, storage migration/backup/authorization tests and browser/native integrations remain required before qualification. Product compilation and packaging run only on hosted Actions.
