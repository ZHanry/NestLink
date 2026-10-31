# fast-socks5 1.0.0 source and local security patch

This directory is third-party software by Jonathan Dizdarevic, published under
the original MIT license in LICENSE. It is not NestLink-original protocol code.

UPSTREAM.crate preserves the exact official crates.io archive. Its SHA-256 is
9545787d8304a71e1bf1b711705070a4c400cce9b332c4a11800627b7c9a2067.
The embedded upstream revision is bae2fc05f993d3a247b5435ba7da221f3fd80a3c.
UPSTREAM.json records every original file and the exact locally modified hash.

The source patch deletes the two debug statements that logged RFC1929 username
and password bytes in src/server.rs, and rejects an authentication subnegotiation
version other than RFC1929's version 1 before reading credential bytes.
Authentication parsing, replies, command handling and all other protocol
behavior remain upstream code.
NestLink uses the typestate server API, performs its own product authorization,
and does not use the library's general DNS resolver or unrestricted dialer.

The original archive, examples, tests, metadata, author attribution and license
are retained. This is a reviewed local dependency, excluded from the first-party
workspace. Build, lock generation and validation take place in hosted Actions.
